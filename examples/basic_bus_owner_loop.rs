use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use smbus_pec::pec;
use std::fmt::Debug;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, oneshot};

use mctp_base_lib::{
    base::*,
    control::{
        allocate_eids::AllocationStatus,
        enums::{CommandCode, CompletionCode, MessageType},
        get_eid::{EidType, EndpointType},
        models::ControlMsgHeader,
        set_eid::EidAllocationStatus,
        ControlMsgReponseStatus, *,
    },
};
use mctp_emu::{
    endpoint::{MctpFlowList, MsgFlowTag},
    hex_dump::print_buf,
    OneshotResponder,
};

#[derive(Debug)]
enum PhysicalTransportCommands {
    ReceiveMsg {
        buf: Bytes,
    },
    SendMsg {
        msg_type: MessageType,
        buf: Bytes,
        resp: Option<OneshotResponder<Bytes>>,
    },
}

#[derive(Debug, Default)]
#[allow(non_camel_case_types, unused)]
struct MctpEndpointContext {
    smbus_addr: u8,
    msg_types: Vec<u8>,
    topmost_bus_owner: bool,
    assigned_eid: AtomicU8,
    perform_discovery: Arc<AtomicBool>,
    min_eid_in_pool: u8,
    eid_pool_size: u8,
    next_msg_tag: AtomicU8,
    next_instance_id: AtomicU8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[allow(non_camel_case_types, unused)]
struct EndpointContext {
    eid: u8,
    endpoint_type: EndpointType,
    eid_type: EidType,
    eid_allocation_status: EidAllocationStatus,
    min_dynamic_eid: u8,
    max_dynamic_eid: u8,
    dynamic_eid_pool_size: u8,
}

impl MctpEndpointContext {
    pub async fn run_bus_owner_loop(
        &self,
        tx_cn: Sender<PhysicalTransportCommands>,
        ping_eid: u8,
    ) -> Result<()> {
        let mut next_eid = self.min_eid_in_pool;

        let mut endpoint: EndpointContext;

        loop {
            if self.perform_discovery.swap(false, Ordering::SeqCst) {
                println!("Starting endpoint discovery");

                // Step 1: Send GetEid to endpoint
                let resp = self
                    .send_get_eid_request(0, tx_cn.clone())
                    .await
                    .context("GetEid request failed")?;
                resp.is_success()
                    .context("GetEID Response is non-successful")?;
                endpoint = EndpointContext {
                    eid: resp.eid,
                    endpoint_type: EndpointType::from(resp.endpoint_type()),
                    eid_type: EidType::from(resp.eid_type()),
                    eid_allocation_status: EidAllocationStatus::NoPoolSupport,
                    min_dynamic_eid: 0,
                    max_dynamic_eid: 0,
                    dynamic_eid_pool_size: 0,
                };

                println!("Discovered endpoint: {:#?}", resp);
                if endpoint.eid_type == EidType::Dynamic {
                    use set_eid::*;

                    let eid = next_eid;
                    next_eid += 1;
                    println!("Endpoint is dynamic, assigning EID: {:?}", eid);

                    // TODO: Step 2: Send SetEID to assign EID to endpoint
                    let resp = self
                        .send_set_eid_request(eid, tx_cn.clone())
                        .await
                        .context("SetEid request failed")?;
                    resp.is_success()?;

                    endpoint.eid_allocation_status = resp.eid_allocation_status();
                    // endpoint.eid_assignment_status
                    if resp.eid_assignment_status() != 0 {
                        return Err(anyhow!("EID assignment was rejected: {:#?}", resp));
                    }
                    if endpoint.endpoint_type == EndpointType::BusOwnerOrBridge
                        && endpoint.eid_allocation_status
                            == EidAllocationStatus::RequiresPoolAllocation
                        && resp.eid_pool_size > 0
                    {
                        endpoint.min_dynamic_eid = next_eid;
                        endpoint.max_dynamic_eid = next_eid + resp.eid_pool_size - 1;
                        endpoint.dynamic_eid_pool_size = resp.eid_pool_size;
                        next_eid += resp.eid_pool_size;
                    }
                }

                // TODO: Step 3: Assign an EID Pool (if needed)
                if endpoint.min_dynamic_eid != endpoint.max_dynamic_eid {
                    println!(
                        "Allocating a pool of eids: {:?} to {:?}",
                        endpoint.min_dynamic_eid, endpoint.max_dynamic_eid
                    );
                    let resp = self
                        .send_allocate_eids_request(
                            endpoint.min_dynamic_eid,
                            endpoint.dynamic_eid_pool_size,
                            tx_cn.clone(),
                        )
                        .await
                        .context("AllocateEid request failed")?;
                    resp.is_success()?;
                    if resp.allocation_status() != AllocationStatus::AllocationAccepted {
                        return Err(anyhow!("EID pool allocation was rejected: {:#?}", resp));
                    }
                }

                // TODO: Step 4: Get Msg Types Supported

                // TODO: Step 5: get Vendor Defined Msg Types Supported

                // TODO: Step 6: Get UUID
            } else {
                tokio::time::sleep(Duration::from_secs(5)).await;

                if ping_eid != 0 {
                    println!("Sending GetEid");
                    let resp = self
                        .send_get_eid_request(ping_eid, tx_cn.clone())
                        .await
                        .context("GetEid request failed")
                        .unwrap();
                    resp.is_success()
                        .context("GetEID Response is non-successful")
                        .unwrap();
                    println!("Received GetEid: {:#?}", resp);
                }
            }
        }
    }

    async fn send_set_eid_request(
        &self,
        eid: u8,
        tx_cn: Sender<PhysicalTransportCommands>,
    ) -> Result<set_eid::Response> {
        use set_eid::*;

        let transport_hdr = self.new_transport_hdr(0);
        let ctrl_hdr = ControlMsgHeader::new(
            CommandCode::SetEndpointID,
            self.next_instance_id.fetch_add(1, Ordering::SeqCst),
            false,
            true,
            false,
        );
        let req = Request::new(ctrl_hdr, Operation::SetEid, eid);
        let req_payload = ControlPayload::new(transport_hdr, ctrl_hdr, req);
        let bytes = Bytes::from(req_payload);

        let (_, response) = self
            .send_and_decode::<Response>(bytes.clone(), MessageType::Control, tx_cn)
            .await
            .context("Failed sending SetEid request")?;
        Ok(response)
    }

    async fn send_get_eid_request(
        &self,
        dest_eid: u8,
        tx_cn: Sender<PhysicalTransportCommands>,
    ) -> Result<get_eid::Response> {
        let transport_hdr = self.new_transport_hdr(dest_eid);
        let ctrl_hdr = ControlMsgHeader::new(
            CommandCode::GetEndpointID,
            self.next_instance_id.fetch_add(1, Ordering::SeqCst),
            false,
            true,
            false,
        );
        let req = get_eid::Request { hdr: ctrl_hdr };
        let req_payload = ControlPayload::new(transport_hdr, ctrl_hdr, req);
        let bytes = Bytes::from(req_payload);

        let (_, response) = self
            .send_and_decode::<get_eid::Response>(bytes.clone(), MessageType::Control, tx_cn)
            .await
            .context("Failed sending GetEid request")?;
        Ok(response)
    }

    async fn send_allocate_eids_request(
        &self,
        starting_eid: u8,
        number_of_eids: u8,
        tx_cn: Sender<PhysicalTransportCommands>,
    ) -> Result<allocate_eids::Response> {
        use allocate_eids::*;

        let transport_hdr = self.new_transport_hdr(0);
        let ctrl_hdr = ControlMsgHeader::new(
            CommandCode::AllocateEndpointIDs,
            self.next_instance_id.fetch_add(1, Ordering::SeqCst),
            false,
            true,
            false,
        );
        let req = Request::new(
            ctrl_hdr,
            Operation::AllocateEids,
            number_of_eids,
            starting_eid,
        );
        let req_payload = ControlPayload::new(transport_hdr, ctrl_hdr, req);
        let bytes = Bytes::from(req_payload);

        let (_, response) = self
            .send_and_decode::<Response>(bytes.clone(), MessageType::Control, tx_cn)
            .await
            .context("Failed sending GetEid request")?;
        Ok(response)
    }

    fn new_transport_hdr(&self, dst_eid: u8) -> TransportHeader {
        TransportHeader::builder()
            .src_eid(self.assigned_eid.load(Ordering::SeqCst))
            .dst_eid(dst_eid)
            .msg_tag(self.next_msg_tag.fetch_add(1, Ordering::SeqCst))
            .tag_owner(true)
            .start_of_msg(true)
            .end_of_msg(true)
            .build()
    }

    async fn send_and_decode<T: TryFrom<Bytes>>(
        &self,
        bytes: Bytes,
        msg_type: MessageType,
        tx_cn: Sender<PhysicalTransportCommands>,
    ) -> Result<(ControlPayload, T)> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let tx_cmd = PhysicalTransportCommands::SendMsg {
            buf: bytes,
            msg_type,
            resp: Some(resp_tx),
        };

        tx_cn
            .send(tx_cmd)
            .await
            .context("Failed sending GetEid cmd")?;

        let res_bytes = resp_rx.await.context("Failed waiting for result")?.unwrap();
        println!("GOT = {:?}", res_bytes);

        ControlPayload::try_to_response::<T>(res_bytes)
    }

    pub fn handle_request(&self, bytes: Bytes) -> Result<Bytes> {
        let payload = ControlPayload::try_from(bytes).context("Failed parsing payload")?;
        match payload.command_code() {
            Ok(CommandCode::SetEndpointID) => {
                use set_eid::*;
                let req = Request::try_from(payload.clone())
                    .context("Failed parsing SetEndpointID msg")?;
                self.assigned_eid.store(req.eid, Ordering::SeqCst);
                let resp = Response::from(
                    req,
                    CompletionCode::Success,
                    EidAllocationStatus::NoPoolSupport,
                    EidAssignmentStatus::Accepted,
                    self.assigned_eid.load(Ordering::SeqCst),
                    0,
                );
                let resp_payload = payload.create_response_payload(resp.hdr, resp.into());
                let resp_bytes = Bytes::from(resp_payload);
                println!("DEBUG: GetEid response: {:#?}", resp);
                println!("DEBUG: GetEid response bytes: {:#?}", resp_bytes);
                print_buf(resp_bytes.clone());
                Ok(resp_bytes)
            }
            Ok(CommandCode::GetEndpointID) => {
                use get_eid::*;

                let req =
                    Request::try_from(payload.clone()).context("Failed parsing GetEid msg")?;
                println!("DEBUG: GetEid request: {:#?}", req);

                let resp = Response::from(
                    req,
                    CompletionCode::Success,
                    0x00,
                    EidType::Dynamic,
                    EndpointType::Simple,
                    0,
                );
                let resp_payload = payload.create_response_payload(resp.hdr, resp.into());
                let resp_bytes = Bytes::from(resp_payload);
                println!("DEBUG: GetEid response: {:#?}", resp);
                println!("DEBUG: GetEid response bytes: {:#?}", resp_bytes);
                print_buf(resp_bytes.clone());
                Ok(resp_bytes)
            }
            Ok(CommandCode::DiscoveryNotify) => {
                let _req =
                    EmptyRequest::try_from(payload.clone()).context("Failed parsing GetEid msg")?;
                let resp = EmptyResponse::from(_req, CompletionCode::Success);
                let resp_payload = payload.create_response_payload(resp.hdr, resp.into());
                let resp_bytes = Bytes::from(resp_payload);
                println!("DEBUG: DiscoveryNotify response: {:#?}", resp);
                println!("DEBUG: DiscoveryNotify response bytes: {:#?}", resp_bytes);
                print_buf(resp_bytes.clone());

                println!("DEBUG: DiscoveryNotify request: {:#?}", _req);
                self.perform_discovery.store(true, Ordering::SeqCst);
                Ok(resp_bytes)
            }
            Ok(CommandCode::GetRoutingTableEntries) => {
                use get_routing_table::*;
                let req = Request::try_from(payload.clone())
                    .context("Failed parsing GetRoutingTable msg")?;
                let resp = Response::from(req, CompletionCode::Success, 0xff, 0);
                let resp_payload = payload.create_response_payload(resp.hdr, resp.into());
                let resp_bytes = Bytes::from(resp_payload);
                println!("DEBUG: GetEid response: {:#?}", resp);
                println!("DEBUG: GetEid response bytes: {:#?}", resp_bytes);
                print_buf(resp_bytes.clone());
                Ok(resp_bytes)
            }
            Ok(_) => {
                let _req =
                    EmptyRequest::try_from(payload.clone()).context("Failed parsing GetEid msg")?;
                let resp = EmptyResponse::from(_req, CompletionCode::ErrorUnsupportedCmd);
                let resp_payload = payload.create_response_payload(resp.hdr, resp.into());
                let resp_bytes = Bytes::from(resp_payload);

                println!("Unsupported command: {:?}", _req);
                Ok(resp_bytes)
            }
            Err(_) => todo!(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let recv_addr = "localhost:5559";
    let send_addr = "localhost:5558";
    let sock = UdpSocket::bind(&recv_addr).await?;
    sock.connect(send_addr).await?;
    let sock_rd = Arc::new(sock);

    let perform_discovery = Arc::new(AtomicBool::new(false));
    const SMBUS_ADDR_7BIT: u8 = 0x10;
    const DEST_SMBUS_ADDR_7BIT: u8 = 0x60 >> 1;
    let ctx = Arc::new(MctpEndpointContext {
        smbus_addr: SMBUS_ADDR_7BIT,
        msg_types: vec![0x7E],
        topmost_bus_owner: false,
        assigned_eid: AtomicU8::new(0x00),
        perform_discovery: perform_discovery.clone(),
        eid_pool_size: 32,
        min_eid_in_pool: 0x80,
        next_instance_id: AtomicU8::new(1),
        next_msg_tag: AtomicU8::new(1),
    });

    let (mctp_cn_tx, mut mctp_cn_rx) = mpsc::channel::<PhysicalTransportCommands>(32);
    let mctp_cn_tx_2 = mctp_cn_tx.clone();
    let sock2 = sock_rd.clone();
    tokio::spawn(async move {
        loop {
            // let mut buf_request = BytesMut::with_capacity(4096);
            let mut buf_request: [u8; 4 * 1024] = [0; 4 * 1024];
            let (len, _) = sock2.recv_from(&mut buf_request).await.unwrap();
            let buf_request = Bytes::copy_from_slice(&buf_request[..len]);
            // DEBUGGING: dump buffer
            {
                let recv_buf_ref = buf_request.clone();
                let recv_addr = recv_addr;
                tokio::spawn(async move {
                    println!(
                        "{:?} ({:?}) bytes received from {:?}",
                        recv_buf_ref.len(),
                        len,
                        recv_addr
                    );
                    print_buf(recv_buf_ref);
                });
            }

            if len != 0 {
                let cmd = PhysicalTransportCommands::ReceiveMsg { buf: buf_request };
                mctp_cn_tx_2.try_send(cmd).unwrap();
            }
        }
    });

    let create_tag = |bytes: Bytes| -> Option<MsgFlowTag> {
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
    };

    let ctx2 = ctx.clone();
    tokio::spawn(async move {
        let pending_cmd: Arc<Mutex<MctpFlowList>> = Default::default();

        let send_cmd_closure =
            |msg_type: MessageType, buf: Bytes, resp: Option<OneshotResponder<Bytes>>| {
                let pending_cmd = pending_cmd.clone();
                let sock2 = sock_rd.clone();
                async move {
                    println!(
                        "DBG[SendMsg] Sending msg: {:?}, len={:?}",
                        msg_type,
                        buf.len()
                    );
                    if let Some(resp) = resp {
                        match create_tag(buf.clone()) {
                            None => return,
                            Some(tag) => pending_cmd.lock().unwrap().push((tag, resp)),
                        }
                    }

                    let mut resp_buf = BytesMut::new();
                    resp_buf.put_slice(&[
                        DEST_SMBUS_ADDR_7BIT << 1,
                        0x0f,
                        buf.len() as u8 + 1,
                        SMBUS_ADDR_7BIT << 1 | 1,
                    ]);
                    resp_buf.put(buf.clone());
                    resp_buf.put_slice(&[pec(resp_buf.as_ref())]);
                    let buf = resp_buf.freeze();
                    {
                        let recv_buf_ref = Bytes::copy_from_slice(&buf[..]);
                        tokio::spawn(async move {
                            println!("DBG[SendMsg] Sending {:?} bytes", recv_buf_ref.len());
                            print_buf(recv_buf_ref);
                        });
                    }
                    let resp_buf: &[u8] = buf.as_ref();
                    let sent_bytes = sock2
                        .send(&resp_buf[..buf.len()])
                        .await
                        .expect("Failed sending message to socket");
                    if sent_bytes != buf.len() {
                        println!(
                            "Failed to send entire buffer: {:?} != {:?}",
                            sent_bytes,
                            buf.len()
                        );
                    }
                }
            };

        while let Some(cmd) = mctp_cn_rx.recv().await {
            println!("Received cmd: {:?}", cmd);
            match cmd {
                PhysicalTransportCommands::ReceiveMsg { buf } => {
                    // DEBUGGING: dump buffer
                    {
                        let recv_buf_ref = Bytes::copy_from_slice(&buf[..]);
                        tokio::spawn(async move {
                            println!("DBG[ReceiveMsg] Received {:?} bytes", recv_buf_ref.len(),);
                            print_buf(recv_buf_ref);
                        });
                    }
                    if buf.len() < 4 || buf[1] != 0x0f {
                        continue;
                    }
                    let resp_buf = buf.slice(4..);

                    {
                        let recv_tag = match create_tag(resp_buf.clone()) {
                            None => continue,
                            Some(tag) => tag,
                        };
                        let mut pending_cmds = pending_cmd.lock().unwrap();
                        let mut index = 0usize;
                        while index < pending_cmds.len() {
                            let (tag, _) = &pending_cmds[index];
                            if tag.msg_tag == recv_tag.msg_tag
                                && tag.tag_owner != recv_tag.tag_owner
                                && tag.dest_eid == recv_tag.src_eid
                            {
                                break;
                            }
                            index += 1;
                        }
                        if index != pending_cmds.len() {
                            let (_, resp) = pending_cmds.remove(index);
                            resp.send(Ok(resp_buf)).unwrap();
                            continue;
                        }
                    }

                    let send_cmd_closure = send_cmd_closure;
                    match ctx2.handle_request(buf.slice(4..)) {
                        Ok(resp) => {
                            send_cmd_closure(MessageType::Control, resp, None).await;
                        }
                        Err(err) => {
                            println!("Failed handling request: {:?}", err);
                        }
                    }
                }
                PhysicalTransportCommands::SendMsg {
                    msg_type,
                    buf,
                    resp,
                } => {
                    send_cmd_closure(msg_type, buf, resp).await;
                }
            }
            println!("Done, going back to sleep");
        }
    });

    ctx.run_bus_owner_loop(mctp_cn_tx, 0).await?;

    Ok(())
}
