mod error;
mod types;
pub mod virtual_network;

pub use error::*;
pub use types::*;

// pub struct SmbusNetDev {
//     address_7b: uint8_t,
//     msg_tx: Sender<MctpSenderCommand>,
// }
//
// impl SmbusNetDev {
//     pub fn new(address_7b: uint8_t) -> SmbusNetDev {
//         let (msg_tx, msg_rx) = mpsc::channel(32);
//
//         let netdev = SmbusNetDev { address_7b, msg_tx };
//         netdev.start_msg_xmit_thread(msg_rx);
//
//         netdev
//     }
//
//     fn start_msg_xmit_thread(&self, mut msg_rx: Receiver<MctpSenderCommand>) {
//         tokio::spawn(async move {
//             while let Some(cmd) = msg_rx.recv().await {
//                 println!("Received cmd: {:?}", cmd);
//             }
//         });
//     }
// }
//
// impl NetDevice for SmbusNetDev {
//     fn dev_address(&self) -> Option<uint8_t> {
//         Some(self.address_7b << 1)
//     }
//
//     fn queue_xmit(&self, cmd: MctpSenderCommand) -> Result<()> {
//         self.msg_tx
//             .try_send(cmd)
//             .context("Failed to xmit MCTP msg")
//             .map_err(|e| Err(Error::Other(e)))
//     }
// }
