use anyhow::Error;
use c2rust_bitfields::BitfieldStruct;
use cascade::cascade;
use mctp_emu_derive::*;
use num_enum::FromPrimitive;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    base::*,
    control::{enums::*, models::*, *},
};

#[derive(
    Debug, PartialEq, Eq, Copy, Clone, DeserializeU8Enum, SerializeU8Enum, FromPrimitive,
)]
#[repr(u8)]
pub enum Operation {
    #[default]
    SetEid = 0,
    ForceEid = 1,
    ResetEid = 2,
    SetDiscoveredFlag = 3,
}

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default)]
#[add_from_control_payload_derives]
#[repr(C, packed)]
pub struct Request {
    pub hdr: ControlMsgHeader,
    #[bitfield(name = "operation", ty = "uint8_t", bits = "0..=1")]
    #[bitfield(name = "reserved", ty = "uint8_t", bits = "2..=7")]
    operation_reserved: [u8; 1],
    pub eid: uint8_t,
}

impl Request {
    pub fn new(hdr: ControlMsgHeader, operation: Operation, eid: uint8_t) -> Self {
        cascade! {
            Self {
                hdr,
                operation_reserved: [0; 1],
                eid,
            };
            ..set_operation(operation as uint8_t);
        }
    }
}

#[derive(
Debug, PartialEq, Eq, Copy, Clone, DeserializeU8Enum, Serialize, FromPrimitive,
)]
#[repr(u8)]
pub enum EidAssignmentStatus {
    Accepted = 0,
    #[default]
    Rejected = 1,
}

#[derive(
Debug, PartialEq, Eq, Copy, Clone, DeserializeU8Enum, Serialize, FromPrimitive, Default,
)]
#[repr(u8)]
pub enum EidAllocationStatus {
    #[default]
    NoPoolSupport = 0,
    RequiresPoolAllocation = 1,
    PoolAlreadyAllocated = 2,
}

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default, AddControlMsgResponse)]
#[add_from_control_payload_derives]
#[repr(C, packed)]
pub struct Response {
    pub hdr: ControlMsgHeader,
    pub completion_code: uint8_t,
    #[bitfield(name = "raw_eid_allocation_status", field = "eid_allocation_status", ty = "uint8_t", bits = "0..=1")]
    #[bitfield(name = "reserved1", ty = "uint8_t", bits = "2..=3")]
    #[bitfield(name = "eid_assignment_status", ty = "uint8_t", bits = "4..=5")]
    #[bitfield(name = "reserved2", ty = "uint8_t", bits = "6..=7")]
    eid_allocation_status_reserved1_eid_assignment_status_reserved2: [u8; 1],
    pub eid_setting: uint8_t,
    pub eid_pool_size: uint8_t,
}

impl Response {
    pub fn new(
        hdr: ControlMsgHeader,
        completion_code: uint8_t,
        eid_allocation_status: EidAllocationStatus,
        eid_assignment_status: EidAssignmentStatus,
        eid_setting: uint8_t,
        eid_pool_size: uint8_t,
    ) -> Self {
        cascade! {
            Self {
                hdr,
                completion_code,
                eid_allocation_status_reserved1_eid_assignment_status_reserved2: [0; 1],
                eid_setting,
                eid_pool_size,
            };
            ..set_raw_eid_allocation_status(eid_allocation_status as u8);
            ..set_eid_assignment_status(eid_assignment_status as u8);
        }
    }

    pub fn from(
        req: Request,
        completion_code: CompletionCode,
        eid_allocation_status: EidAllocationStatus,
        eid_assignment_status: EidAssignmentStatus,
        eid_setting: uint8_t,
        eid_pool_size: uint8_t,
    ) -> Self {
        let mut hdr = req.hdr;
        hdr.set_rq(0);
        Self::new(
            hdr,
            completion_code as uint8_t,
            eid_allocation_status,
            eid_assignment_status,
            eid_setting,
            eid_pool_size,
        )
    }

    pub fn eid_allocation_status(&self) -> EidAllocationStatus {
        EidAllocationStatus::from(self.raw_eid_allocation_status())
    }
}
