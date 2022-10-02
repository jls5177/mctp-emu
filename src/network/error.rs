use std::{io, result};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid socket descriptor")]
    InvalidSocketError { sd: i32 },

    #[error(transparent)]
    Other(#[from] anyhow::Error),

    #[non_exhaustive]
    #[error("unknown error")]
    Unknown,
}

pub type Result<T> = result::Result<T, Error>;
