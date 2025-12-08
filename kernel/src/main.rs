#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};

const ACTION_PASS: u32 = 0;
const ACTION_DROP: u32 = 1;
const ACTION_TARPIT: u32 = 2;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IotEvent {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u16,
    pub len: u16,
    pub _padding: [u8; 2],
}

#[map]
static mut EVENTS: PerfEventArray<IotEvent> = PerfEventArray::new(0);

#[map]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(10240, 0);

static mut PACKET_COUNTER: u64 = 0;

#[xdp]
pub fn lloyd_parser(ctx: XdpContext) -> u32 {
    match try_lloyd_parser(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_lloyd_parser(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_ip = unsafe { u32::from_be((*ipv4_hdr).src_addr) };

    // KINETIC INTERDICTION
    if let Some(action) = unsafe { BLOCKLIST.get(&src_ip) } {
        if *action == ACTION_DROP { return Ok(xdp_action::XDP_DROP); }
        else if *action == ACTION_TARPIT { return tarpit_packet(&ctx, EthHdr::LEN + Ipv4Hdr::LEN); }
    }

    // SAMPLING (1%)
    unsafe {
        PACKET_COUNTER += 1;
        if PACKET_COUNTER % 100 != 0 { return Ok(xdp_action::XDP_PASS); }
    }

    // TELEMETRY
    let protocol = unsafe { (*ipv4_hdr).proto };
    let mut src_port = 0;
    let mut dst_port = 0;

    match protocol {
        IpProto::Tcp => {
            let tcp_hdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            src_port = unsafe { u16::from_be((*tcp_hdr).source) };
            dst_port = unsafe { u16::from_be((*tcp_hdr).dest) };
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let event = IotEvent {
        src_ip, src_port, dst_port,
        protocol: protocol as u16,
        len: (ctx.data_end() - ctx.data()) as u16,
        _padding: [0; 2],
    };
    unsafe { EVENTS.output(&ctx, &event, 0) };
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn tarpit_packet(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let tcp_hdr: *mut TcpHdr = unsafe { ptr_at_mut(ctx, offset)? };
    unsafe { (*tcp_hdr).window = 0; } // Choke
    Ok(xdp_action::XDP_PASS)
}

unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    if start + offset + mem::size_of::<T>() > ctx.data_end() { return Err(()); }
    Ok((start + offset) as *const T)
}
unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    if start + offset + mem::size_of::<T>() > ctx.data_end() { return Err(()); }
    Ok((start + offset) as *mut T)
}
