//! Defines MCTP Control Protocol layer
pub mod allocate_eids;
pub mod enums;
pub mod get_eid;
pub mod get_routing_table;
pub mod models;
pub mod set_eid;

use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::mem;

use crate::{
    base::{MctpBaseLibError, TransportHeader},
    control::{enums::*, models::*},
};

// expose the common empty requests and responses
pub use self::models::EmptyRequest;
pub use self::models::EmptyResponse;

trait ControlMsgBody {}

struct NullControlMsg {}

impl ControlMsgBody for NullControlMsg {}

pub trait ControlMsgReponseStatus {
    fn completion_code(&self) -> CompletionCode;
    fn is_success(&self) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ControlPayload {
    pub hdr: TransportHeader,
    pub control_hdr: ControlMsgHeader,
    pub(self) payload: Bytes,
}

#[buildstructor::buildstructor]
impl ControlPayload {
    #[builder]
    pub fn new<T: Into<Bytes>>(
        hdr: TransportHeader,
        control_hdr: ControlMsgHeader,
        payload: T,
    ) -> Self {
        ControlPayload {
            hdr,
            control_hdr,
            payload: payload.into(),
        }
    }

    pub fn try_to_response<T: TryFrom<Bytes>>(bytes: Bytes) -> Result<(ControlPayload, T)> {
        let payload = Self::try_from(bytes).context("Failed parsing payload")?;
        match T::try_from(payload.payload.clone()) {
            Ok(resp) => Ok((payload, resp)),
            // TODO: find a way to pull out the error instead of just propogating a new generic message
            Err(_) => Err(anyhow::Error::msg("Failed parsing response")),
        }
        // TODO: expose "completion_code" to commonize success check here
    }

    pub fn command_code(&self) -> Result<CommandCode, MctpBaseLibError> {
        match self.control_hdr.command_code {
            CommandCode::Unknown => Err(MctpBaseLibError::UnknownValue {
                value: format!("{:?}", self.control_hdr.command_code),
            }),
            code => Ok(code),
        }
    }

    pub fn create_response_payload(
        &self,
        control_hdr: ControlMsgHeader,
        response_body: Bytes,
    ) -> ControlPayload {
        let rsp_hdr = self.hdr.create_response();
        ControlPayload::new(rsp_hdr, control_hdr, response_body)
    }
}

impl From<ControlPayload> for Vec<u8> {
    fn from(t: ControlPayload) -> Self {
        let bytes = Bytes::from(t);
        bytes.to_vec()
    }
}

impl From<ControlPayload> for Bytes {
    fn from(payload: ControlPayload) -> Self {
        let mut buf = BytesMut::new();
        buf.put(Bytes::from(payload.hdr));
        buf.put(payload.payload);
        buf.freeze()
    }
}

impl TryFrom<Bytes> for ControlPayload {
    type Error = MctpBaseLibError;
    fn try_from(bytes: Bytes) -> core::result::Result<Self, Self::Error> {
        let hdr_size = mem::size_of::<TransportHeader>();
        let control_hdr_size = mem::size_of::<ControlMsgHeader>();
        let total_hdr_size = hdr_size + control_hdr_size;

        let msg_size = bytes.len() as isize - total_hdr_size as isize;
        if msg_size < 0 {
            return Err(MctpBaseLibError::InvalidPayloadSize {
                expected: total_hdr_size.to_string(),
                found: bytes.len().to_string(),
            });
        }

        // payload contains the control header and body (if any)
        let payload = bytes.slice(hdr_size..);

        // let msg_bytes = if msg_size > 0 {
        //     Some(bytes.slice(total_hdr_size..))
        // } else {
        //     None
        // };

        let hdr = TransportHeader::try_from(bytes.slice(..hdr_size))?;
        let control_hdr = ControlMsgHeader::try_from(bytes.slice(hdr_size..total_hdr_size))?;

        Ok(ControlPayload::builder()
            .hdr(hdr)
            .control_hdr(control_hdr)
            .payload(payload)
            // .and_msg_bytes(msg_bytes)
            .build())
    }
}

// 01 02 0a c0 00 00 02 00 0a 10 00 9c
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_completion_code_serialize() -> Result<()> {
        let bytes: Vec<u8> = vec![
            0x01, 0x02, 0x0a, 0xc0, 0x00, 0x00, 0x02, 0x00, 0x0a, 0x10, 0x00, 0x9c,
        ];

        let ctrl_payload = ControlPayload::try_from(bytes).unwrap()?;

        assert_eq!(bincode::serialize(&completion_code)?, bytes);

        Ok(())
    }

    #[test]
    fn test_completion_code_known_u8_deserialize() -> Result<()> {
        let bytes = vec![2];

        let mut completion_code: CompletionCode;

        assert_eq!(
            CompletionCode::ErrorInvalidData,
            bincode::deserialize(&bytes)?
        );

        Ok(())
    }
}
