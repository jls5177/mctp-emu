use anyhow::anyhow;
use bytes::{BufMut, BytesMut};
use cascade::cascade;
use smbus_pec::pec;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{event, Level};

use mctp_base_lib::base::*;

use crate::{
    hex_dump::print_buf,
    network::{NetworkBinding, NetworkBindingCallbackMsg},
    phys::{smbus_types::*, Error, Result},
    MctpEmuEmptyResult, MctpEmuResult,
};

#[tracing::instrument(level = "info", skip(socket, rx_callback))]
async fn poll_socket(
    socket: Arc<UdpSocket>,
    network_id: u64,
    rx_callback: Sender<NetworkBindingCallbackMsg>,
) -> MctpEmuEmptyResult {
    event!(Level::INFO, "start polling network socket");
    loop {
        let mut buf_request: [u8; 4 * 1024] = [0; 4 * 1024];
        let (len, _) = socket.recv_from(&mut buf_request).await.unwrap();
        let buf_request = Bytes::copy_from_slice(&buf_request[..len]);

        event!(Level::INFO, msg_len = len, "received a message");
        {
            let recv_buf_ref = buf_request.clone();
            tokio::spawn(async move {
                println!(
                    "poll_socket(): {:?} ({:?}) bytes received",
                    recv_buf_ref.len(),
                    len
                );
                print_buf(recv_buf_ref);
            });
        }

        if len != 0 {
            let cmd = NetworkBindingCallbackMsg::Receive {
                id: network_id,
                buf: buf_request,
            };
            rx_callback.send(cmd).await;
        }
    }
    event!(Level::INFO, "stopped polling network socket");
}

fn validate_smbus_address(addr: u64) -> MctpEmuEmptyResult {
    // Filter out reserved, invalid and unsupported addresses
    if addr < 8 || (addr >> 3) == 0b1111 || addr > 0x7F {
        return Err(Error::InvalidAddress { addr: addr as u64 }.into());
    }
    Ok(())
}

pub type SmbusBindingHandle = Arc<tokio::sync::Mutex<SmbusNetDevBinding>>;

#[derive(Debug, Default)]
pub struct SmbusNetDevBinding {
    address: u8,
    network_id: AtomicU64,
    socket: Option<Arc<UdpSocket>>,
}

impl SmbusNetDevBinding {
    pub async fn new(
        recv_sock_addr: String,
        send_sock_addr: String,
        address: u8,
    ) -> MctpEmuResult<SmbusBindingHandle> {
        let mut binding = cascade! {
            let binding = Self::default();
            ..set_address(address);
        };

        /// connect to socket
        let socket = UdpSocket::bind(recv_sock_addr)
            .await
            .map_err(Error::SocketError)?;
        socket
            .connect(send_sock_addr)
            .await
            .map_err(Error::SocketError)?;
        binding.socket = Some(Arc::new(socket));

        Ok(Arc::new(Mutex::new(binding)))
    }

    fn set_address(&mut self, address: u8) -> MctpEmuEmptyResult {
        validate_smbus_address(address as u64)?;
        self.address = address;
        Ok(())
    }
}

impl NetworkBinding for SmbusNetDevBinding {
    #[tracing::instrument(level = "info", skip(msg))]
    fn transmit(&self, msg: Bytes, phy_addr: u64) -> MctpEmuEmptyResult {
        tracing::info!("sending command to {phy_addr:?}");
        validate_smbus_address(phy_addr)?;
        if msg.len() >= 256 {
            todo!("Support fragmenting messages");
        }

        let dest_addr: u8 = (phy_addr & 0x7f) as u8;
        let msg_length: u8 = (msg.len() & 0xff) as u8;

        let mut tx_buf = BytesMut::new();
        let hdr = SmbusPhysTransportHeader::new(dest_addr, self.address, msg_length);
        let hdr_bytes = Bytes::from(hdr);
        tx_buf.put(hdr_bytes);
        tx_buf.put(msg.clone());
        tx_buf.put_slice(&[pec(msg.as_ref())]);

        let socket = self.socket.as_ref().unwrap().clone();
        let sent_bytes = socket.try_send(&tx_buf[..]);

        match socket.try_send(&tx_buf[..]) {
            Ok(sent_bytes) => {
                if sent_bytes == tx_buf.len() {
                    Ok(())
                } else {
                    Err(Error::TransmitError(format!(
                        "incomplete transfer: {:?} != {:?}",
                        sent_bytes,
                        tx_buf.len()
                    ))
                    .into())
                }
            }
            Err(err) => Err(Error::SocketError(err).into()),
        }
    }

    fn bind(
        &mut self,
        id: u64,
        rx_callback: Sender<NetworkBindingCallbackMsg>,
    ) -> MctpEmuResult<JoinHandle<MctpEmuEmptyResult>> {
        self.network_id.store(id, Ordering::SeqCst);

        let socket = match self.socket.as_ref() {
            Some(socket) => socket.clone(),
            None => return Err(Error::Other(anyhow!("failed grabbing socket vector")).into()),
        };
        let handle = tokio::spawn(async move { poll_socket(socket, id, rx_callback).await });

        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MctpEmuError;
    use anyhow::{anyhow, Result};

    #[test]
    fn test_invalid_address() -> Result<()> {
        match validate_smbus_address(0x86) {
            Ok(_) => Err(anyhow!("Expected an invalid error")),
            Err(MctpEmuError::Phys(err)) => Ok(()),
            Err(err) => Err(anyhow!("Unexpected error: {err:?}")),
        }
    }
}
