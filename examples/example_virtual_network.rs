use anyhow::Result;
use mctp_emu::network::virtual_network::VirtualNetwork;
use mctp_emu::network::SockAddrMctp;

use mctp_emu::phys::smbus_netdev::SmbusNetDevBinding;

#[tokio::main]
async fn main() -> Result<()> {
    let smbus_binding = SmbusNetDevBinding::new(
        String::from("localhost:5559"),
        String::from("localhost:5558"),
        0x10,
    )
    .await?;

    let network1 = VirtualNetwork::new_mctp_network()?;
    network1.add_physical_binding(smbus_binding).await?;

    // Set local endpoint address and listen for data
    let addr = SockAddrMctp::default();
    let sd = network1.socket();
    network1.bind(sd, addr)?;

    // join all started threads to ensure main stays running
    let mut results = Vec::new();
    for handle in network1.join_handles() {
        results.push(handle.await);
    }

    // TODO: do something with the results. E.g. did any fail?
    Ok(())
}
