#![allow(dead_code, unused)]

extern crate core;

use anyhow::{anyhow, Context, Error, Result};
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
use tokio::sync::{mpsc, oneshot};

use crate::Responder;
use mctp_base_lib::{
    base::*,
    control::{
        enums::{CommandCode, CompletionCode, MessageType},
        get_eid::{EidType, EndpointType},
        ControlMsgReponseStatus, *,
    },
};

pub const MCTP_NET_ANY: uint8_t = 0x08;
pub const MCTP_ADDR_ANY: uint8_t = 0x08;
pub const MCTP_ADDR_BCAST: uint8_t = 0xff;
pub const MCTP_TAG_OWNER: uint8_t = 0x08;

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
struct Client {
    local_addr: Option<SockAddrMctp>,
    remote_addr: Option<SockAddrMctp>,
}

impl Client {
    fn new() -> Arc<RwLock<Client>> {
        Arc::new(RwLock::new(Client::default()))
    }

    fn set_local_addr(&mut self, new: SockAddrMctp) {
        self.local_addr.replace(new);
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
enum NeighbourSource {
    Static = 0,
    Discover = 1,
}

#[derive(Debug)]
struct Neighbour {
    eid: uint8_t,
    source: NeighbourSource,
    ha: [uint8_t; 32],
}

#[derive(Debug)]
struct Route {
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
    fn queue_xmit(&self, cmd: MctpSenderCommand) -> Result<()>;
}

pub struct SmbusNetDev {
    address_7b: uint8_t,
    msg_tx: Sender<MctpSenderCommand>,
}

impl SmbusNetDev {
    pub fn new(address_7b: uint8_t) -> SmbusNetDev {
        let (msg_tx, msg_rx) = mpsc::channel(32);

        let netdev = SmbusNetDev { address_7b, msg_tx };
        netdev.start_msg_xmit_thread(msg_rx);

        netdev
    }

    fn start_msg_xmit_thread(&self, mut msg_rx: Receiver<MctpSenderCommand>) {
        tokio::spawn(async move {
            while let Some(cmd) = msg_rx.recv().await {
                println!("Received cmd: {:?}", cmd);
            }
        });
    }
}

impl NetDevice for SmbusNetDev {
    fn dev_address(&self) -> Option<uint8_t> {
        Some(self.address_7b << 1)
    }

    fn queue_xmit(&self, cmd: MctpSenderCommand) -> Result<()> {
        self.msg_tx.try_send(cmd).context("Failed to xmit MCTP msg")
    }
}

#[derive(Debug, Default)]
pub struct VirtualNetwork<T>
where
    T: NetDevice + Debug,
{
    clients: Arc<RwLock<Vec<Arc<RwLock<Client>>>>>,
    num_clients: AtomicU16,
    routes: Arc<RwLock<Vec<Arc<Route>>>>,
    net_devs: Arc<RwLock<Vec<Arc<T>>>>,
}

pub trait MctpNetwork<T>
where
    T: NetDevice + Debug + Default,
{
    fn socket(&self) -> int32_t;
    fn bind(&self, sd: int32_t, addr: SockAddrMctp) -> Result<()>;
    fn sendto(
        &self,
        sd: int32_t,
        payload: Bytes,
        addr: SockAddrMctp,
    ) -> Result<(SockAddrMctpExt, Bytes)>;
    fn add_netdev(&self, netdev: T) -> Result<uint32_t>;
}

impl<T> VirtualNetwork<T>
where
    T: NetDevice + Debug + Default,
{
    pub fn new() -> Arc<VirtualNetwork<T>> {
        Arc::new(VirtualNetwork::default())
    }

    fn get_client(&self, sd: int32_t) -> Result<Arc<RwLock<Client>>> {
        if sd < (self.num_clients.load(Ordering::SeqCst) as int32_t - 1) {
            return Err(anyhow!("Unknown socket descriptor: {:?}", sd));
        }
        match self.clients.read().unwrap().get(sd as usize) {
            Some(client) => Ok(client.clone()),
            None => Err(anyhow!("Failed to find client")),
        }
    }

    fn route_lookup(&self, dnet: uint32_t, daddr: uint8_t) -> Option<Arc<Route>> {
        for route in self.routes.read().unwrap().iter() {
            if route.matches(dnet, daddr) {
                return Some(route.clone());
            }
        }
        None
    }

    async fn mctp_tx_thread() {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5));
            }
        });
    }
}

impl<T> MctpNetwork<T> for VirtualNetwork<T>
where
    T: NetDevice + Debug + Default,
{
    fn socket(&self) -> int32_t {
        let sd = self.num_clients.fetch_add(1, Ordering::SeqCst);
        {
            self.clients.write().unwrap().push(Client::new());
        }
        sd as int32_t
    }

    fn bind(&self, sd: int32_t, addr: SockAddrMctp) -> Result<()> {
        let client = self.get_client(sd)?;
        {
            client.write().unwrap().set_local_addr(addr);
        }
        Ok(())
    }

    fn sendto(
        &self,
        _sd: int32_t,
        payload: Bytes,
        addr: SockAddrMctp,
    ) -> Result<(SockAddrMctpExt, Bytes)> {
        let net = addr.smctp_network;
        let s_addr = addr.smctp_addr.s_addr;
        let route_rt = self
            .route_lookup(net, s_addr)
            .context(format!("Route not found for {:?},{:?}", net, s_addr))?;

        todo!()
    }

    fn add_netdev(&self, netdev: T) -> Result<uint32_t> {
        let mut net_devs = self.net_devs.write().unwrap();
        net_devs.push(Arc::new(netdev));
        Ok(net_devs.len() as uint32_t - 1)
    }
}

#[derive(Debug)]
pub enum MctpSenderCommand {
    OneShot {
        msg_type: MessageType,
        buf: Bytes,
        resp: Responder<(SockAddrMctpExt, Bytes)>,
    },
    Broadcast {
        msg_type: MessageType,
        buf: Bytes,
        resp: Receiver<(SockAddrMctpExt, Bytes)>,
    },
}
