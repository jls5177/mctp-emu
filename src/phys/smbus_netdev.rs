use bytes::{BufMut, BytesMut};
use cascade::cascade;
use mctp_base_lib::base::*;
use smbus_pec::pec;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

use crate::{
    hex_dump::print_buf,
    network::{NetworkBinding, NetworkBindingCallbackMsg},
    phys::{Error, Result},
    MctpEmuEmptyResult, MctpEmuResult,
};

const SMBUS_COMMAND_CODE_MCTP: u8 = 0x0f;

async fn poll_socket(
    socket: Arc<UdpSocket>,
    network_id: u64,
    rx_callback: Sender<NetworkBindingCallbackMsg>,
) -> Result<()> {
    loop {
        let mut buf_request: [u8; 4 * 1024] = [0; 4 * 1024];
        let (len, _) = socket.recv_from(&mut buf_request).await.unwrap();
        let buf_request = Bytes::copy_from_slice(&buf_request[..len]);

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
}

fn validate_smbus_address(addr: u64) -> MctpEmuEmptyResult {
    // Filter out reserved, invalid and unsupported addresses
    if addr < 8 || (addr >> 3) == 0b1111 || addr > 0x7F {
        return Err(Error::InvalidAddress { addr: addr as u64 }.into());
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct Binding {
    address: u8,
    network_id: AtomicU64,
    socket: Option<Arc<UdpSocket>>,
}

impl Binding {
    pub async fn new(
        recv_sock_addr: String,
        send_sock_addr: String,
        address: u8,
    ) -> MctpEmuResult<Self> {
        let mut binding = cascade! {
            let binding = Binding::default();
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

        Ok(binding)
    }

    fn set_address(&mut self, address: u8) -> MctpEmuEmptyResult {
        validate_smbus_address(address as u64)?;
        self.address = address;
        Ok(())
    }
}

impl NetworkBinding for Binding {
    fn transmit(&self, msg: Bytes, phy_addr: u64) -> MctpEmuEmptyResult {
        validate_smbus_address(phy_addr)?;
        if msg.len() >= 256 {
            todo!("Support fragmenting messages");
        }

        let dest_addr: u8 = (phy_addr & 0x7f) as u8;
        let msg_length: u8 = (msg.len() & 0xff) as u8;

        let mut tx_buf = BytesMut::new();
        let hdr = SmbusPhysTransportHeader::new(dest_addr, self.address, msg_length);
        let hdr_bytes = Bytes::from(hdr);
        tx_buf.put(hdr_bytes.clone());
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
    ) -> MctpEmuResult<()> {
        self.network_id.store(id, Ordering::SeqCst);

        let socket = self.socket.as_ref().unwrap().clone();
        tokio::spawn(async move {
            poll_socket(socket, id, rx_callback).await;
        });

        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, c2rust_bitfields::BitfieldStruct)]
#[mctp_emu_derive::add_binary_derives]
#[repr(C, packed)]
pub struct SmbusPhysTransportHeader {
    dest_addr: u8,
    command_code: u8,
    byte_count: u8,
    src_addr: u8,
}

impl SmbusPhysTransportHeader {
    pub fn new(dest_addr_7bit: u8, src_addr_7bit: u8, byte_count: u8) -> Self {
        SmbusPhysTransportHeader {
            dest_addr: dest_addr_7bit << 1,
            command_code: SMBUS_COMMAND_CODE_MCTP,
            byte_count,
            src_addr: src_addr_7bit << 1 | 0x01,
        }
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
