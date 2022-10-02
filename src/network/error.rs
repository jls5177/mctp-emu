use crate::network::{BindingDescriptor, SocketDescriptor};
use std::{io, result};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid socket descriptor")]
    InvalidSocketError { sd: SocketDescriptor },

    #[error("invalid physical binding descriptor")]
    InvalidBindingError { binding_id: BindingDescriptor },

    #[error(transparent)]
    Other(#[from] anyhow::Error),

    #[non_exhaustive]
    #[error("unknown error")]
    Unknown,
}

pub type Result<T> = result::Result<T, Error>;
