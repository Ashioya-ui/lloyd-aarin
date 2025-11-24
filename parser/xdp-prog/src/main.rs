#![no_std]
#![no_main]
use aya_bpf::{bindings::xdp_action, macros::{map, xdp, uprobe, uretprobe}, maps::{HashMap, PerfEventArray}, programs::{XdpContext, ProbeContext}, helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user}};
use aya_bpf::cty::c_void;
use core::mem;
use network_types::{eth::{EthHdr, EtherType}, ip::{Ipv4Hdr, IpProto}, tcp::TcpHdr, udp::UdpHdr};
use common::{IotEvent, BlockRule};

#[map] static mut EVENTS: PerfEventArray<IotEvent> = PerfEventArray::new(0);
#[map] static mut BLOCKLIST: HashMap<u32, BlockRule> = HashMap::with_max_entries(10240, 0);
#[map] static mut SSL_CONTEXT: HashMap<u64, UserBuffer> = HashMap::with_max_entries(1024, 0);
#[derive(Clone, Copy)] struct UserBuffer { ptr: u64, len: u64 }

#[xdp] pub fn lloyd_parser(ctx: XdpContext) -> u32 { match try_lloyd_parser(ctx) { Ok(ret) => ret, Err(_) => xdp_action::XDP_ABORTED } }
#[inline(always)] fn try_lloyd_parser(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*eth_hdr).ether_type } { EtherType::Ipv4 => {}, _ => return Ok(xdp_action::XDP_PASS) }
    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_addr = unsafe { u32::from_be((*ipv4_hdr).src_addr) };
    if unsafe { BLOCKLIST.get(&src_addr).is_some() } { return Ok(xdp_action::XDP_DROP); }
    let proto = unsafe { (*ipv4_hdr).proto };
    let mut dst_port = 0; let mut src_port = 0;
    if proto == IpProto::Tcp { let tcp_hdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? }; dst_port = unsafe { u16::from_be((*tcp_hdr).dest) }; src_port = unsafe { u16::from_be((*tcp_hdr).source) }; }
    else if proto == IpProto::Udp { let udp_hdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? }; dst_port = unsafe { u16::from_be((*udp_hdr).dest) }; src_port = unsafe { u16::from_be((*udp_hdr).source) }; }
    if dst_port == 1883 || dst_port == 5683 || dst_port == 80 || dst_port == 443 {
        let event = IotEvent { src_ip: src_addr, src_port, dst_port, protocol: proto as u8, packet_len: ctx.data_end() as u32 - ctx.data() as u32, _padding: [0; 3], payload_snippet: [0; 64] };
        unsafe { EVENTS.output(&ctx, &event, 0) };
    }
    Ok(xdp_action::XDP_PASS)
}
#[uprobe] pub fn probe_ssl_write(ctx: ProbeContext) -> u32 { let buf_ptr: u64 = ctx.arg(1).unwrap_or(0); let buf_len: u64 = ctx.arg(2).unwrap_or(0); if buf_ptr != 0 && buf_len > 0 { send_ssl_event(&ctx, buf_ptr, buf_len); } 0 }
#[uprobe] pub fn probe_ssl_read_enter(ctx: ProbeContext) -> u32 { let tid = bpf_get_current_pid_tgid(); let buf_ptr: u64 = ctx.arg(1).unwrap_or(0); let buf_len: u64 = ctx.arg(2).unwrap_or(0); unsafe { SSL_CONTEXT.insert(&tid, &UserBuffer { ptr: buf_ptr, len: buf_len }, 0) }; 0 }
#[uretprobe] pub fn probe_ssl_read_exit(ctx: ProbeContext) -> u32 { let tid = bpf_get_current_pid_tgid(); if let Some(ctx_data) = unsafe { SSL_CONTEXT.get(&tid) } { if ctx_data.ptr != 0 && ctx_data.len > 0 { send_ssl_event(&ctx, ctx_data.ptr, ctx_data.len); } unsafe { SSL_CONTEXT.remove(&tid) }; } 0 }
fn send_ssl_event(ctx: &ProbeContext, ptr: u64, len: u64) {
    let mut event = IotEvent { src_ip: 0, src_port: 0, dst_port: 0, protocol: 255, packet_len: len as u32, _padding: [0; 3], payload_snippet: [0; 64] };
    let read_len = if len > 64 { 64 } else { len };
    unsafe { let _ = bpf_probe_read_user(event.payload_snippet.as_mut_ptr() as *mut c_void, read_len as u32, ptr as *const c_void); EVENTS.output(ctx, &event, 0); }
}
#[inline(always)] unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> { let start = ctx.data(); let end = ctx.data_end(); let len = mem::size_of::<T>(); if start + offset + len > end { return Err(()); } Ok((start + offset) as *const T) }