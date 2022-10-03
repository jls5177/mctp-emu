use anyhow::Result;
use bytes::Bytes;
use mctp_base_lib::base::TransportHeader;
use mctp_base_lib::control::enums::CommandCode;
use mctp_base_lib::control::models::ControlMsgHeader;
use mctp_base_lib::control::{get_eid, ControlPayload};
use mctp_emu::network::simple_network::SimpleNetwork;
use mctp_emu::network::SocketAddress;
use mctp_emu::phys::smbus_netdev::SmbusNetDevBinding;
use std::sync::atomic::{AtomicU8, Ordering};
use tracing::{event, Level};

#[tokio::main]
async fn main() -> Result<()> {
    // setup tracing globally across app
    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let smbus_binding = SmbusNetDevBinding::new(
        String::from("localhost:5559"),
        String::from("localhost:5558"),
        0x10,
    )
    .await?;

    let simpl_net1 = SimpleNetwork::new_mctp_network(smbus_binding.clone())?;
    simpl_net1
        .add_physical_binding(smbus_binding.clone())
        .await?;

    tracing::warn!("Engines are running...");

    // Set local endpoint address and listen for data
    let sd = simpl_net1.socket();
    simpl_net1.bind(sd, 0, 0, 0)?;

    let next_instance_id = AtomicU8::new(0);

    let transport_hdr = TransportHeader::builder()
        .src_eid(0)
        .dst_eid(0)
        .msg_tag(0)
        .tag_owner(true)
        .start_of_msg(true)
        .end_of_msg(true)
        .build();
    let ctrl_hdr = ControlMsgHeader::new(
        CommandCode::GetEndpointID,
        next_instance_id.fetch_add(1, Ordering::SeqCst),
        false,
        true,
        false,
    );
    let req = get_eid::Request { hdr: ctrl_hdr };
    let req_payload = ControlPayload::new(transport_hdr, ctrl_hdr, req);
    let bytes = Bytes::from(req_payload);

    let dest_add = SocketAddress::Extended {
        address: 0,
        network: 1,
        binding_id: 1,
        phy_addr: 0x25,
    };
    let (_, result) = simpl_net1.sendto(sd, bytes.slice(4..), dest_add).await?;
    event!(Level::INFO, "response from endpoint: {:?}", result.len());

    // TODO: do something with the results. E.g. did any fail?
    tracing::warn!("Exiting main thread...");
    Ok(())
}
