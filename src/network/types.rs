extern crate core;

use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use c2rust_bitfields::BitfieldStruct;
use cascade::cascade;
use mctp_emu_derive::*;
use num_enum::FromPrimitive;
use serde::Deserializer;
use std::fmt::Debug;
use std::io;
use std::ops::Index;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;

use crate::{MctpEmuEmptyResult, MctpEmuError, MctpEmuResult, OneshotResponder};
use mctp_base_lib::control::enums::CompletionCode::Error;
use mctp_base_lib::{
    base::*,
    control::{
        enums::{CommandCode, CompletionCode, MessageType},
        get_eid::{EidType, EndpointType},
        ControlMsgReponseStatus, *,
    },
};

#[derive(Debug)]
pub enum NetworkBindingCallbackMsg {
    Receive { id: u64, buf: Bytes },
}

pub trait NetworkBinding: Debug + Send + Sync {
    fn transmit(&self, buf: Bytes, phy_addr: u64) -> MctpEmuEmptyResult;
    fn bind(
        &mut self,
        id: u64,
        rx_callback: Sender<NetworkBindingCallbackMsg>,
    ) -> MctpEmuResult<JoinHandle<MctpEmuEmptyResult>>;
}

pub const MCTP_NET_ANY: u8 = 0x08;
pub const MCTP_ADDR_ANY: u8 = 0x08;
pub const MCTP_ADDR_BCAST: u8 = 0xff;
pub const MCTP_TAG_OWNER: u8 = 0x08;

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct MctpAddr {
    pub s_addr: uint8_t,
}

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct SockAddrMctp {
    pub smctp_family: uint16_t,
    smctp_pad0: uint16_t,
    pub smctp_network: uint32_t,
    pub smctp_addr: MctpAddr,
    pub smctp_type: uint8_t,
    pub smctp_tag: uint8_t,
    smctp_pad1: uint8_t,
}

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct SockAddrMctpExt {
    smctp_base: SockAddrMctp,
    smctp_ifindex: int32_t,
    smctp_halen: uint8_t,
    smctp_pad0: [uint8_t; 3],
    smctp_haddr: [uint8_t; 32],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Client {
    local_addr: Option<SockAddrMctp>,
    remote_addr: Option<SockAddrMctp>,
}

impl Client {
    pub fn new() -> Arc<RwLock<Client>> {
        Arc::new(RwLock::new(Client::default()))
    }

    pub fn set_local_addr(&mut self, new: SockAddrMctp) {
        self.local_addr.replace(new);
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NeighbourSource {
    Static = 0,
    Discover = 1,
}

#[derive(Debug)]
pub struct Neighbour {
    eid: uint8_t,
    source: NeighbourSource,
    ha: [uint8_t; 32],
}

#[derive(Debug)]
pub struct Route {
    min_eid: uint8_t,
    max_eid: uint8_t,
    net: uint32_t,
    mtu: uint32_t,
    route_type: uint8_t,
}

impl Route {
    pub(crate) fn matches(&self, dnet: uint32_t, daddr: uint8_t) -> bool {
        dnet == self.net && self.min_eid <= daddr && self.max_eid >= daddr
    }
}

pub trait NetDevice {
    fn dev_address(&self) -> Option<uint8_t>;
    fn queue_xmit(&self, cmd: MctpSenderCommand) -> MctpEmuEmptyResult;
}

#[async_trait::async_trait]
pub trait MctpNetwork {
    fn socket(&self) -> int32_t;
    fn bind(&self, sd: int32_t, addr: SockAddrMctp) -> MctpEmuResult<()>;
    fn sendto(
        &self,
        sd: int32_t,
        payload: Bytes,
        addr: SockAddrMctp,
    ) -> MctpEmuResult<(SockAddrMctpExt, Bytes)>;

    async fn add_physical_binding(&self, binding: NetworkBindingHandle) -> MctpEmuEmptyResult;

    fn join_handles(&self) -> Vec<JoinHandle<MctpEmuEmptyResult>>;
}

#[derive(Debug)]
pub enum MctpSenderCommand {
    OneShot {
        msg_type: MessageType,
        buf: Bytes,
        resp: OneshotResponder<(SockAddrMctpExt, Bytes)>,
    },
    Broadcast {
        msg_type: MessageType,
        buf: Bytes,
        resp: Receiver<(SockAddrMctpExt, Bytes)>,
    },
}

pub type SocketDescriptor = i32;
pub type BindingDescriptor = u64;
pub type NetworkBindingHandle = Arc<tokio::sync::Mutex<dyn NetworkBinding>>;
pub type ClientHandle = Arc<RwLock<Client>>;
pub type RouteHandle = Arc<Route>;
pub type MctpNetworkHandle = Arc<dyn MctpNetwork>;
