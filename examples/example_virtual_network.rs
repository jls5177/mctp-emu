use anyhow::Result;
use bytes::Bytes;
use mctp_emu::network::virtual_network::VirtualNetwork;
use mctp_emu::network::SockAddrMctp;

use mctp_emu::phys::smbus_netdev::SmbusNetDevBinding;

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

    let network1 = VirtualNetwork::new_mctp_network()?;
    network1.add_physical_binding(smbus_binding).await?;

    tracing::warn!("Engines are running...");

    // Set local endpoint address and listen for data
    let addr = SockAddrMctp::default();
    let sd = network1.socket();
    network1.bind(sd, addr)?;

    network1
        .sendto(sd, Bytes::from(vec![0, 1, 2, 3]), addr)
        .await?;

    // join all started threads to ensure main stays running
    // let mut results = Vec::new();
    // for handle in network1.join_handles() {
    //     results.push(handle.await);
    // }

    // TODO: do something with the results. E.g. did any fail?
    tracing::warn!("Exiting main thread...");
    Ok(())
}
