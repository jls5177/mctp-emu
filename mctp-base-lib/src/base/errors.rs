use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("invalid payload size (found {found:?}, expected {expected:?})")]
    InvalidPayloadSize { expected: String, found: String },

    #[error("unknown value ({value:?})")]
    UnknownValue { value: String },

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Result type used when return value is needed from methods in library.
pub type MctpEmuResult<T> = std::result::Result<T, ParseError>;

/// Result type used when return value is _NOT_ needed from methods in library.
pub type EmptyResult = std::result::Result<(), ParseError>;
