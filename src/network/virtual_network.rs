extern crate core;

use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use c2rust_bitfields::BitfieldStruct;
use cascade::cascade;
use mctp_emu_derive::*;
use num_enum::FromPrimitive;
use serde::Deserializer;
use std::borrow::{Borrow, BorrowMut};
use std::fmt::Debug;
use std::io;
use std::ops::Index;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, oneshot, MutexGuard};
use tokio::task::JoinHandle;

use mctp_base_lib::{
    base::*,
    control::{
        enums::{CommandCode, CompletionCode, MessageType},
        get_eid::{EidType, EndpointType},
        ControlMsgReponseStatus, *,
    },
};

use crate::{
    network::{types::*, Error, NetDevice, Result},
    MctpEmuEmptyResult, MctpEmuResult,
};

#[derive(Debug, derive_builder::Builder)]
#[builder(private, pattern = "owned")]
pub struct VirtualNetwork {
    clients: Arc<RwLock<Vec<ClientHandle>>>,
    num_clients: AtomicU16,
    routes: Arc<RwLock<Vec<Arc<Route>>>>,
    net_devs: Arc<RwLock<Vec<NetworkBindingHandle>>>,
    num_bindings: AtomicU64,
    callback_handles: Arc<RwLock<Vec<JoinHandle<MctpEmuEmptyResult>>>>,
    rx_callback: Sender<NetworkBindingCallbackMsg>,
}

impl VirtualNetwork {
    pub fn new_mctp_network() -> MctpEmuResult<MctpNetworkHandle> {
        let network = VirtualNetwork::new()?;
        Ok(network)
    }

    fn new() -> MctpEmuResult<Arc<Self>> {
        let (sender, mut receiver) = mpsc::channel::<NetworkBindingCallbackMsg>(32);

        let builder = VirtualNetworkBuilder::default().rx_callback(sender);
        let mut network: VirtualNetwork = match builder.build() {
            Ok(n) => n,
            Err(err) => {
                return Err(
                    Error::Other(anyhow!("failed building VirtualNetwork: {:?}", err)).into(),
                )
            }
        };
        let network = Arc::new(network);

        let network2 = network.clone();
        let callback_handle =
            tokio::spawn(async move { network2.callback_handler(receiver).await });

        // store callback handle
        {
            network
                .callback_handles
                .write()
                .unwrap()
                .push(callback_handle);
        }

        Ok(network)
    }

    async fn callback_handler(
        &self,
        mut receiver: Receiver<NetworkBindingCallbackMsg>,
    ) -> MctpEmuEmptyResult {
        loop {
            while let Some(cmd) = receiver.recv().await {
                println!("Received cmd: {:?}", cmd);
                match cmd {
                    NetworkBindingCallbackMsg::Receive { id, buf } => {}
                }
            }
        }
    }

    fn get_binding(&self, binding_id: u64) -> Result<NetworkBindingHandle> {
        if binding_id < (self.num_bindings.load(Ordering::SeqCst) as u64 - 1) {
            return Err(Error::InvalidBindingError { binding_id });
        }
        match self.net_devs.read().unwrap().get(binding_id as usize) {
            Some(binding) => Ok(binding.clone()),
            None => Err(Error::InvalidBindingError { binding_id }),
        }
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

#[async_trait::async_trait]
impl MctpNetwork for VirtualNetwork {
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

    async fn add_physical_binding(&self, binding: NetworkBindingHandle) -> MctpEmuEmptyResult {
        let bind_id = self.num_bindings.fetch_add(1, Ordering::SeqCst);
        {
            self.net_devs.write().unwrap().push(binding.clone());
        }

        let handle = match binding.lock().await.bind(bind_id, self.rx_callback.clone()) {
            Ok(handle) => handle,
            Err(err) => {
                return Err(Error::Other(anyhow!("failed calling binding: {:?}", err)).into())
            }
        };

        {
            self.callback_handles.write().unwrap().push(handle);
        }

        Ok(())
    }

    fn join_handles(&self) -> Vec<JoinHandle<MctpEmuEmptyResult>> {
        let mut handles = Vec::new();
        for hdl in self.callback_handles.write().unwrap().drain(..) {
            handles.push(hdl);
        }
        handles
    }
}
