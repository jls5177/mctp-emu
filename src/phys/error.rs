use bytes::Bytes;
use std::{io, result};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("socket error: {0}")]
    SocketError(#[from] io::Error),

    #[error("transmit failed: {0}")]
    TransmitError(String),

    /// Invalid slave address.
    ///
    /// I2C supports 7-bit and 10-bit addresses. Several 7-bit addresses
    /// are reserved, and can't be used as slave addresses. A list of
    /// those reserved addresses can be found [here].
    ///
    /// [here]: https://en.wikipedia.org/wiki/I%C2%B2C#Reserved_addresses_in_7-bit_address_space
    #[error("invalid address: {addr:?}")]
    InvalidAddress { addr: u64 },

    #[error(transparent)]
    Other(#[from] anyhow::Error),

    #[non_exhaustive]
    #[error("unknown error")]
    Unknown,
}

pub type Result<T> = result::Result<T, Error>;
