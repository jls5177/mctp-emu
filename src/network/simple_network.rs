extern crate core;

use anyhow::{anyhow, Context};
use bytes::{BufMut, Bytes, BytesMut};
use c2rust_bitfields::BitfieldStruct;
use cascade::cascade;
use mctp_emu_derive::*;
use num_enum::FromPrimitive;
use serde::Deserializer;
use std::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Debug;
use std::io;
use std::ops::{Deref, Index};
use std::sync::atomic::{AtomicI32, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, oneshot, MutexGuard};
use tokio::task::JoinHandle;
use tracing::{event, Level};

use mctp_base_lib::{
    base::*,
    control::{
        enums::{CommandCode, CompletionCode, MessageType},
        get_eid::{EidType, EndpointType},
        ControlMsgReponseStatus, *,
    },
};

use crate::endpoint::{MctpFlowList, MsgFlowTag};
use crate::phys::smbus_types::SmbusPhysTransportHeader;
use crate::{
    network::{types::*, Error, NetDevice, Result},
    MctpEmuEmptyResult, MctpEmuError, MctpEmuResult,
};

#[derive(Debug, derive_builder::Builder)]
#[builder(private, pattern = "owned")]
pub struct SimpleNetwork {
    clients: Arc<RwLock<HashMap<i32, ClientHandle>>>,
    num_clients: AtomicI32,
    phys_bindings: NetworkBindingHandle,
    callback_handles: Arc<RwLock<Vec<JoinHandle<MctpEmuEmptyResult>>>>,
    rx_callback: Sender<NetworkBindingCallbackMsg>,
    flows: Arc<Mutex<MctpFlowList>>,
}

fn create_tag(bytes: Bytes) -> Option<MsgFlowTag> {
    if bytes.len() < 4 {
        return Some(MsgFlowTag::default());
    }
    match TransportHeader::try_from(bytes) {
        Ok(hdr) => Some(MsgFlowTag {
            dest_eid: hdr.destination_eid,
            src_eid: hdr.source_eid,
            msg_tag: hdr.msg_tag(),
            tag_owner: hdr.tag_owner() != 0,
        }),
        Err(err) => {
            println!("Failed parsing header from received msg: {:?}", err);
            None
        }
    }
}

impl SimpleNetwork {
    pub fn new_mctp_network(binding: NetworkBindingHandle) -> MctpEmuResult<MctpNetworkHandle> {
        let network = SimpleNetwork::new(binding)?;
        Ok(network)
    }

    fn new(binding: NetworkBindingHandle) -> MctpEmuResult<Arc<Self>> {
        let (sender, mut receiver) = mpsc::channel::<NetworkBindingCallbackMsg>(32);

        let builder = SimpleNetworkBuilder::default()
            .phys_bindings(binding)
            .clients(Default::default())
            .num_clients(Default::default())
            .callback_handles(Default::default())
            .rx_callback(sender)
            .flows(Default::default());
        let mut network: SimpleNetwork = match builder.build() {
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

    #[tracing::instrument(level = "info", skip(receiver))]
    async fn callback_handler(
        &self,
        mut receiver: Receiver<NetworkBindingCallbackMsg>,
    ) -> MctpEmuEmptyResult {
        loop {
            while let Some(cmd) = receiver.recv().await {
                event!(Level::INFO, "received a command: {:?}", cmd);
                match cmd {
                    NetworkBindingCallbackMsg::Receive { id, buf } => {
                        let binding = self.get_binding(id);

                        let transport_hdr = match SmbusPhysTransportHeader::try_from(buf.clone()) {
                            Ok(hdr) => hdr,
                            Err(_) => {
                                tracing::warn!("failed parsing transport header from received msg");
                                continue;
                            }
                        };

                        let buf = buf.slice(4..);

                        let recv_tag = match create_tag(buf.clone()) {
                            None => {
                                tracing::warn!("failed creating tag from received msg");
                                continue;
                            }
                            Some(tag) => tag,
                        };

                        let response = ClientCallbackMsg::Receive {
                            addr: SocketAddress::Extended {
                                address: 0,
                                network: 1,
                                binding_id: id,
                                phy_addr: 0,
                            },
                            buf,
                        };

                        // TODO: check if for a pending flow
                        let mut index = 0usize;
                        {
                            let mut flows_inflight = self.flows.lock().unwrap();
                            while index < flows_inflight.len() {
                                let (tag, _) = &flows_inflight[index];
                                if tag.msg_tag == recv_tag.msg_tag
                                    && tag.tag_owner != recv_tag.tag_owner
                                    && tag.dest_eid == recv_tag.src_eid
                                {
                                    break;
                                }
                                index += 1;
                            }

                            // TODO: build response
                            if index != flows_inflight.len() {
                                let (_, resp) = flows_inflight.remove(index);
                                resp.send(response).unwrap();
                                continue;
                            }
                        }

                        // TODO: send to client channel
                        tracing::warn!("sending to client is not yet supported");
                    }
                }
            }
        }
    }

    fn get_binding(&self, binding_id: u64) -> Result<NetworkBindingHandle> {
        if binding_id != 1 {
            return Err(Error::InvalidBindingError { binding_id });
        }
        Ok(self.phys_bindings.clone())
    }

    fn get_client(&self, sd: i32) -> MctpEmuResult<ClientHandle> {
        match self.clients.read().unwrap().get(&sd) {
            Some(client) => Ok(client.clone()),
            None => Err(Error::InvalidSocketError { sd }.into()),
        }
    }
}

#[async_trait::async_trait]
impl MctpNetwork for SimpleNetwork {
    fn socket(&self) -> i32 {
        self.num_clients.fetch_add(1, Ordering::SeqCst)
    }

    fn bind(&self, sd: int32_t, address: u8, msg_type: u8, tag: u8) -> MctpEmuResult<()> {
        if sd < (self.num_clients.load(Ordering::SeqCst) as int32_t - 1) {
            return Err(Error::InvalidSocketError { sd }.into());
        }
        let client_handle = Client::new(address, msg_type, tag);
        {
            self.clients.write().unwrap().insert(sd, client_handle);
        }
        Ok(())
    }

    async fn sendto(
        &self,
        sd: int32_t,
        payload: Bytes,
        addr: SocketAddress,
    ) -> MctpEmuResult<(SocketAddress, Bytes)> {
        let (network, address, binding_id, phy_addr) = if let SocketAddress::Extended {
            address,
            network,
            binding_id,
            phy_addr,
        } = addr
        {
            (network, address, binding_id, phy_addr)
        } else {
            todo!("Support looking up routes to get the physical address");
        };

        let binding_handle = self.get_binding(binding_id)?;

        let mut buf = BytesMut::new();

        // scoping to allow grabbing mutex around client and then releasing it when finished
        {
            let client_handle = self.get_client(sd)?;
            let client = client_handle.read().unwrap();
            let Client {
                address: client_address,
                msg_type: client_msg_type,
                tag: client_tag,
                ..
            } = client.deref();

            // TODO: support multiple packet messages (payload > MTU)
            let hdr = TransportHeader::builder()
                .src_eid(*client_address)
                .dst_eid(address)
                .msg_tag(*client_tag)
                .tag_owner(true)
                .start_of_msg(true)
                .end_of_msg(true)
                .build();
            drop(client);

            buf.put(Bytes::from(hdr));
        }
        buf.put(payload);

        // TODO: create channel
        let (resp_tx, resp_rx) = oneshot::channel::<ClientCallbackMsg>();

        // TODO: allocate tag and track flow
        let buf = buf.freeze();
        match create_tag(buf.clone()) {
            None => return Err(Error::Other(anyhow!("failed to allocate tag")).into()),
            Some(tag) => {
                self.flows.lock().unwrap().push((tag, resp_tx));
            }
        }

        // TODO: transmit message
        let binding = binding_handle.lock().await;
        binding.deref().transmit(buf.clone(), phy_addr).unwrap();

        // TODO: wait for response
        let res_bytes = resp_rx.await.map_err(|e| {
            MctpEmuError::Network(Error::Other(anyhow!("response failed: {:?}", e)))
        })?;

        event!(Level::INFO, "received a response: {:?}", res_bytes);

        // TODO: return response bytes
        match res_bytes {
            ClientCallbackMsg::Receive { buf, addr } => Ok((addr, buf)),
        }
    }

    async fn add_physical_binding(&self, binding: NetworkBindingHandle) -> MctpEmuEmptyResult {
        let handle = match binding.lock().await.bind(1, self.rx_callback.clone()) {
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
