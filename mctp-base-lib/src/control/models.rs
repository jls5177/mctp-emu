use bytes::Bytes;
use c2rust_bitfields::BitfieldStruct;
use cascade::cascade;
use mctp_emu_derive::*;
use serde::{Deserialize, Serialize};
use std::convert::From;

use crate::{
    base::*,
    control::{CommandCode, CompletionCode, ControlPayload},
};

pub(crate) const SIZEOF_CONTROL_HDR: uint8_t = 3;

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default)]
#[add_binary_derives]
#[repr(C, packed)]
pub struct ControlMsgHeader {
    #[bitfield(name = "msg_type", ty = "uint8_t", bits = "0..=6")]
    #[bitfield(name = "integrity_check", ty = "uint8_t", bits = "7..=7")]
    #[bitfield(name = "instance_id", ty = "uint8_t", bits = "8..=12")]
    #[bitfield(name = "rsvd", ty = "uint8_t", bits = "13..=13")]
    #[bitfield(name = "d_bit", ty = "uint8_t", bits = "14..=14")]
    #[bitfield(name = "rq", ty = "uint8_t", bits = "15..=15")]
    msg_type_integrity_check_instance_id_rsvd_d_bit_rq: [u8; 2],
    pub command_code: CommandCode,
}

impl ControlMsgHeader {
    pub fn new(
        cmd_code: CommandCode,
        instance_id: uint8_t,
        integ_check: bool,
        request: bool,
        datagram: bool,
    ) -> Self {
        cascade! {
            Self::default();
            ..set_rq(request.into());
            ..set_instance_id(instance_id);
            ..set_integrity_check(integ_check.into());
            ..set_d_bit(datagram.into());
            ..command_code = cmd_code;
        }
    }
}

impl From<TransportHeader> for ControlMsgHeader {
    fn from(transport_hdr: TransportHeader) -> Self {
        let is_req = transport_hdr.tag_owner() != 0;
        let is_datagram = transport_hdr.destination_eid == 0xff;
        Self::new(CommandCode::default(), 0, true, is_req, is_datagram)
    }
}

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default)]
#[add_from_control_payload_derives]
#[repr(C, packed)]
pub struct EmptyRequest {
    pub hdr: ControlMsgHeader,
}

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default)]
#[add_from_control_payload_derives]
#[repr(C, packed)]
pub struct EmptyResponse {
    pub hdr: ControlMsgHeader,
    pub completion_code: uint8_t,
}

impl EmptyResponse {
    pub fn new(hdr: ControlMsgHeader, completion_code: uint8_t) -> Self {
        Self {
            hdr,
            completion_code,
        }
    }

    pub fn from(req: EmptyRequest, completion_code: CompletionCode) -> Self {
        let mut hdr = req.hdr;
        hdr.set_rq(0);
        Self::new(hdr, completion_code as uint8_t)
    }
}

// pub mod discovery_notify {
//     use crate::control::models::{EmptyRequest, EmptyResponse};
//
//     // Has no additional
//     pub type Request = EmptyRequest;
//     pub type Response = EmptyResponse;
// }
//
// pub mod endpoint_discovery {
//     use crate::control::models::{EmptyRequest, EmptyResponse};
//
//     // Has no additional
//     pub type Request = EmptyRequest;
//     pub type Response = EmptyResponse;
// }

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_EmptyResponse_to_Bytes() -> Result<()> {
        let ctrl_hdr = ControlMsgHeader::new(CommandCode::DiscoveryNotify, 0, false, false, false);
        let ctrl_hdr_bytes = Bytes::from(ctrl_hdr);
        assert_eq!(ctrl_hdr_bytes.len(), 3);

        let resp = EmptyResponse::new(ctrl_hdr, CompletionCode::Success as u8);
        let bytes: Bytes = Bytes::from(resp);
        assert_eq!(bytes.len(), 4);

        Ok(())
    }


    #[test]
    fn test_EmptyResponse_try_from_Bytes() -> Result<()> {
        let ctrl_hdr = ControlMsgHeader::new(CommandCode::DiscoveryNotify, 0, false, false, false);
        let ctrl_hdr_bytes = Bytes::from(ctrl_hdr);

        let resp = EmptyResponse::new(ctrl_hdr, CompletionCode::Success as u8);
        let bytes: Bytes = Bytes::try_from(resp).context("Failed to unmarshal buffer")?;

        assert_eq!(ctrl_hdr_bytes.len(), 3);
        assert_eq!(bytes.len(), 4);

        Ok(())
    }
}