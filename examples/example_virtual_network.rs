use anyhow::{anyhow, Context, Result};
use cascade::cascade;
use mctp_emu::network::virtual_network::VirtualNetwork;
use mctp_emu::network::{MctpNetwork, NetworkBinding};

use mctp_emu::phys::smbus_netdev::Binding;

#[tokio::main]
async fn main() -> Result<()> {
    let smbus_binding = Binding::new(
        String::from("localhost:5559"),
        String::from("localhost:5558"),
        0x10,
    )
    .await?;

    let network = VirtualNetwork::new();
    network.add_physical_binding(Box::new(smbus_binding));

    let _network1 = cascade! {
        VirtualNetwork::new();
        ..add_physical_binding(Box::new(smbus_binding)).context("failed adding smbus binding")?;
    };

    Ok(())
}
