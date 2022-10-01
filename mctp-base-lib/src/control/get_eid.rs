use anyhow::Error;
use c2rust_bitfields::BitfieldStruct;
use cascade::cascade;
use mctp_emu_derive::*;
use num_enum::FromPrimitive;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    base::*,
    control::{models::ControlMsgHeader, CompletionCode, ControlPayload},
    control::ControlMsgReponseStatus,
};

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default)]
#[add_from_control_payload_derives]
#[repr(C, packed)]
pub struct Request {
    pub hdr: ControlMsgHeader,
}

#[derive(
    Debug, PartialEq, Eq, Copy, Clone, DeserializeU8Enum, SerializeU8Enum, FromPrimitive, Default,
)]
#[repr(u8)]
pub enum EidType {
    #[default]
    Dynamic = 0,
    StaticSupportedWithPresentEidReturned = 1,
    StaticMatch = 2,
    StaticMismatch = 3,
}

#[derive(
    Debug, PartialEq, Eq, Copy, Clone, DeserializeU8Enum, SerializeU8Enum, FromPrimitive, Default,
)]
#[repr(u8)]
pub enum EndpointType {
    #[default]
    Simple = 0,
    BusOwnerOrBridge = 1,
}

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default, AddControlMsgResponse)]
#[add_from_control_payload_derives]
#[repr(C, packed)]
pub struct Response {
    pub hdr: ControlMsgHeader,
    pub completion_code: uint8_t,
    pub eid: uint8_t,
    #[bitfield(name = "eid_type", ty = "uint8_t", bits = "0..=1")]
    #[bitfield(name = "reserved1", ty = "uint8_t", bits = "2..=3")]
    #[bitfield(name = "endpoint_type", ty = "uint8_t", bits = "4..=5")]
    #[bitfield(name = "reserved2", ty = "uint8_t", bits = "6..=7")]
    eid_endpoint_type: [u8; 1],
    pub medium_specific: uint8_t,
}

#[buildstructor::buildstructor]
impl Response {
    pub fn new(
        hdr: ControlMsgHeader,
        completion_code: uint8_t,
        eid: uint8_t,
        eid_type: EidType,
        endpoint_type: EndpointType,
        medium_specific: uint8_t,
    ) -> Self {
        cascade! {
            Self {
                hdr,
                completion_code,
                eid,
                eid_endpoint_type: [0; 1],
                medium_specific,
            };
            ..set_eid_type(eid_type as u8);
            ..set_endpoint_type(endpoint_type as u8);
        }
    }

    pub fn from(
        req: Request,
        completion_code: CompletionCode,
        eid: uint8_t,
        eid_type: EidType,
        endpoint_type: EndpointType,
        medium_specific: uint8_t,
    ) -> Self {
        let mut hdr = req.hdr.clone();
        hdr.set_rq(0);
        Self::new(
            hdr,
            completion_code as uint8_t,
            eid,
            eid_type,
            endpoint_type,
            medium_specific,
        )
    }
}
