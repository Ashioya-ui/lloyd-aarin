use anyhow::Context;
use aya::{maps::{perf::AsyncPerfEventArray, HashMap}, programs::{Xdp, XdpFlags, UProbe, URetProbe}, Bpf};
use bytes::BytesMut;
use clap::Parser;
use common::{BlockRule, IotEvent};
use rdkafka::{config::ClientConfig, consumer::{Consumer, StreamConsumer}, message::Message, producer::{FutureProducer, FutureRecord}};
use serde::Deserialize;
use std::{net::Ipv4Addr, str::FromStr, sync::Arc, time::Duration};
use tokio::{signal, task};
use tracing::{error, info, warn};

#[derive(Parser, Debug)] struct Args { #[clap(short, long, default_value = "eth0")] iface: String, #[clap(long, default_value = "/opt/xdp-prog")] bpf_path: String, #[clap(long, default_value = "localhost:9092")] kafka: String }
#[derive(Deserialize, Debug)] struct KillCommand { ip: String, action: String, reason: String }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let iface = std::env::var("IFACE").unwrap_or(args.iface);
    let kafka_broker = std::env::var("KAFKA_BOOTSTRAP").unwrap_or(args.kafka);
    
    info!(interface = %iface, broker = %kafka_broker, "LLOYD System Init");
    let mut bpf = Bpf::load_file(&args.bpf_path).context("Failed to load eBPF")?;
    let program: &mut Xdp = bpf.program_mut("lloyd_parser").unwrap().try_into()?;
    program.load()?; program.attach(&iface, XdpFlags::default())?;
    
    let libssl_path = "/usr/lib/x86_64-linux-gnu/libssl.so.3"; 
    if let Ok(prog) = bpf.program_mut("probe_ssl_write") { let prog: &mut UProbe = prog.try_into()?; prog.load()?; prog.attach(Some("SSL_write"), 0, libssl_path, None).ok(); }
    if let Ok(prog) = bpf.program_mut("probe_ssl_read_enter") { let prog: &mut UProbe = prog.try_into()?; prog.load()?; prog.attach(Some("SSL_read"), 0, libssl_path, None).ok(); }
    if let Ok(prog) = bpf.program_mut("probe_ssl_read_exit") { let prog: &mut URetProbe = prog.try_into()?; prog.load()?; if prog.attach(Some("SSL_read"), 0, libssl_path, None).is_ok() { info!("TLS Introspection Active"); } }

    let blocklist_map: HashMap<_, u32, BlockRule> = HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;
    let mut events_map = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    let producer: FutureProducer = ClientConfig::new().set("bootstrap.servers", &kafka_broker).create()?;
    let consumer: StreamConsumer = ClientConfig::new().set("group.id", "lloyd-enforcer").set("bootstrap.servers", &kafka_broker).create()?;
    consumer.subscribe(&["kill-commands"])?;

    let enforcer_map = Arc::new(tokio::sync::Mutex::new(blocklist_map));
    let map_ref = enforcer_map.clone();
    task::spawn(async move {
        loop {
            match consumer.recv().await {
                Ok(m) => if let Some(Ok(payload)) = m.payload_view::<str>() {
                    if let Ok(cmd) = serde_json::from_str::<KillCommand>(payload) {
                        if let Ok(ip) = Ipv4Addr::from_str(&cmd.ip) {
                            if map_ref.lock().await.insert(u32::from(ip), BlockRule { reason_code: 1, expiration: 0 }, 0).is_ok() {
                                info!(ip = %cmd.ip, reason = %cmd.reason, "⛔ LLOYD INTERDICTION EXECUTED");
                            }
                        }
                    }
                },
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    });

    for cpu_id in events_map.online_cpus() {
        let mut buf = events_map.open(cpu_id, None)?;
        let p_clone = producer.clone();
        task::spawn(async move {
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();
            loop {
                if let Ok(events) = buf.read_events(&mut buffers).await {
                    for i in 0..events.read {
                        let event = unsafe { &*(buffers[i].as_ptr() as *const IotEvent) };
                        let payload = String::from_utf8_lossy(&event.payload_snippet).trim_matches(char::from(0)).to_string();
                        let json = serde_json::json!({ "ts": 0, "src_ip": Ipv4Addr::from(event.src_ip).to_string(), "dst_port": event.dst_port, "proto": if event.protocol == 255 { "TLS" } else { "TCP" }, "len": event.packet_len, "payload": payload });
                        let _ = p_clone.send(FutureRecord::to("iot-events").payload(&json.to_string()).key("lloyd"), Duration::from_secs(0)).await;
                    }
                }
            }
        });
    }
    signal::ctrl_c().await?;
    Ok(())
}