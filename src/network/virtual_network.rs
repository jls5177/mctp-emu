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
use tokio::sync::{mpsc, oneshot};

use crate::network::{types::*, Error, NetDevice, Result};
use crate::MctpEmuResult;
use mctp_base_lib::{
    base::*,
    control::{
        enums::{CommandCode, CompletionCode, MessageType},
        get_eid::{EidType, EndpointType},
        ControlMsgReponseStatus, *,
    },
};

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

impl<T> VirtualNetwork<T>
where
    T: NetDevice + Debug + Default,
{
    pub fn new() -> Arc<VirtualNetwork<T>> {
        Arc::new(VirtualNetwork::default())
    }

    fn get_client(&self, sd: int32_t) -> MctpEmuResult<Arc<RwLock<Client>>> {
        if sd < (self.num_clients.load(Ordering::SeqCst) as int32_t - 1) {
            return Err(Error::InvalidSocketError { sd }.into());
        }
        match self.clients.read().unwrap().get(sd as usize) {
            Some(client) => Ok(client.clone()),
            None => Err(Error::InvalidSocketError { sd }.into()),
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

    fn bind(&self, sd: int32_t, addr: SockAddrMctp) -> MctpEmuResult<()> {
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
    ) -> MctpEmuResult<(SockAddrMctpExt, Bytes)> {
        let net = addr.smctp_network;
        let s_addr = addr.smctp_addr.s_addr;
        let route_rt = self
            .route_lookup(net, s_addr)
            .context(format!("Route not found for {:?},{:?}", net, s_addr))?;
        todo!()
    }

    fn add_netdev(&self, netdev: T) -> MctpEmuResult<uint32_t> {
        let mut net_devs = self.net_devs.write().unwrap();
        net_devs.push(Arc::new(netdev));
        Ok(net_devs.len() as uint32_t - 1)
    }

    fn add_physical_binding(&self, binding: Box<dyn NetworkBinding>) -> crate::MctpEmuEmptyResult {
        todo!()
    }
}
