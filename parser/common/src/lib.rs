#![no_std]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IotEvent {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _padding: [u8; 3],
    pub packet_len: u32,
    pub payload_snippet: [u8; 64],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BlockRule {
    pub reason_code: u32,
    pub expiration: u64,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for IotEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockRule {}