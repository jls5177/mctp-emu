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
    AllocateEids = 0,
    ForceAllocation = 1,
    GetAllocationInfo = 2,
}

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default)]
#[add_from_control_payload_derives]
#[repr(C, packed)]
pub struct Request {
    pub hdr: ControlMsgHeader,
    #[bitfield(name = "operation", ty = "uint8_t", bits = "0..=1")]
    #[bitfield(name = "reserved", ty = "uint8_t", bits = "2..=7")]
    operation_reserved: [u8; 1],
    pub number_of_eids: uint8_t,
    pub starting_eid: uint8_t,
}

impl Request {
    pub fn new(hdr: ControlMsgHeader, operation: Operation, number_of_eids: uint8_t, starting_eid: uint8_t) -> Self {
        cascade! {
            Self {
                hdr,
                operation_reserved: [0; 1],
                number_of_eids,
                starting_eid,
            };
            ..set_operation(operation as uint8_t);
        }
    }
}

#[derive(
    Debug, PartialEq, Eq, Copy, Clone, DeserializeU8Enum, SerializeU8Enum, FromPrimitive,
)]
#[repr(u8)]
pub enum AllocationStatus {
    AllocationAccepted = 0,
    #[default]
    AllocationRejected = 1,
}

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default, AddControlMsgResponse)]
#[add_from_control_payload_derives]
#[repr(C, packed)]
pub struct Response {
    pub hdr: ControlMsgHeader,
    pub completion_code: uint8_t,
    #[bitfield(name = "raw_allocation_status", ty = "uint8_t", bits = "0..=1")]
    #[bitfield(name = "reserved", ty = "uint8_t", bits = "2..=7")]
    allocation_status_reserved: [u8; 1],
    pub eid_pool_size: uint8_t,
    pub first_eid: uint8_t,
}

impl Response {
    pub fn new(
        hdr: ControlMsgHeader,
        completion_code: uint8_t,
        allocation_status: AllocationStatus,
        eid_pool_size: uint8_t,
        first_eid: uint8_t,
    ) -> Self {
        cascade! {
            Self {
                hdr,
                completion_code,
                allocation_status_reserved: [0; 1],
                first_eid,
                eid_pool_size,
            };
            ..set_raw_allocation_status(allocation_status as u8);
        }
    }

    pub fn from(
        req: Request,
        completion_code: uint8_t,
        allocation_status: AllocationStatus,
        eid_pool_size: uint8_t,
        first_eid: uint8_t,
    ) -> Self {
        let mut hdr = req.hdr;
        hdr.set_rq(0);
        Self::new(
            hdr,
            completion_code,
            allocation_status,
            eid_pool_size,
            first_eid,
        )
    }

    pub fn allocation_status(&self) -> AllocationStatus {
        AllocationStatus::from(self.raw_allocation_status())
    }
}
