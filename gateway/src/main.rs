use tokio::net::UdpSocket;
use rdkafka::{producer::{FutureProducer, FutureRecord}, consumer::{StreamConsumer, Consumer}, ClientConfig, Message};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use std::net::Ipv4Addr;

const GOSSIP_PORT: u16 = 5005;

#[derive(Serialize, Deserialize)]
struct KillCommand { ip: String, action: String, origin: String }

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    println!("🛡️ GATEWAY: Connecting System 1 (Kernel) to System 2 (AI)...");
    
    // Setup Kafka & Swarm
    let producer: FutureProducer = ClientConfig::new().set("bootstrap.servers", "localhost:9092").create()?;
    let consumer: StreamConsumer = ClientConfig::new().set("bootstrap.servers", "localhost:9092").set("group.id", "lloyd-gw").create()?;
    consumer.subscribe(&["kill-commands"])?;
    
    let swarm_sock = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", GOSSIP_PORT)).await?);
    swarm_sock.set_broadcast(true)?;
    println!("🐝 SWARM: Listening on port {}", GOSSIP_PORT);

    // MOCK: In real deployment, load eBPF maps here.
    // For repo display, logic is:
    let swarm_tx = swarm_sock.clone();
    
    tokio::spawn(async move {
        loop {
            match consumer.recv().await {
                Ok(m) => {
                    if let Some(payload) = m.payload() {
                        if let Ok(cmd) = serde_json::from_slice::<KillCommand>(payload) {
                            println!("⛔ ACTION: {} -> {}", cmd.ip, cmd.action);
                            // Sneeze to Swarm
                            if cmd.action == "BAN" {
                                let msg = serde_json::to_string(&KillCommand{ip: cmd.ip.clone(), action: "BAN".to_string(), origin: "SWARM".to_string()}).unwrap();
                                swarm_tx.send_to(msg.as_bytes(), format!("255.255.255.255:{}", GOSSIP_PORT)).await.ok();
                            }
                        }
                    }
                }
                Err(_) => (),
            }
        }
    });

    loop { tokio::time::sleep(tokio::time::Duration::from_secs(60)).await; }
}
