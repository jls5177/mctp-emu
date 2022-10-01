use anyhow::Error;
use cascade::cascade;

use crate::{
    base::*,
    control::{enums::*, models::*, *},
};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, c2rust_bitfields::BitfieldStruct)]
#[mctp_emu_derive::add_from_control_payload_derives]
#[repr(C, packed)]
pub struct Request {
    pub hdr: ControlMsgHeader,
    entry_handle: uint8_t,
}

impl Request {
    pub fn new(hdr: ControlMsgHeader, entry_handle: uint8_t) -> Self {
        Self { hdr, entry_handle }
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Default,
    c2rust_bitfields::BitfieldStruct,
    mctp_emu_derive::AddControlMsgResponse,
)]
#[mctp_emu_derive::add_from_control_payload_derives]
#[repr(C, packed)]
pub struct Response {
    pub hdr: ControlMsgHeader,
    pub completion_code: uint8_t,
    pub next_entry_handle: uint8_t,
    pub entries_in_response: uint8_t,
}

// TODO: support a single entry to start with instead of trying to do dynamic sizing
// Can use a Byte array to support any number of entries with methods to add entries to the list
// Or can just take a static size within "from|new".

impl Response {
    pub fn new(
        hdr: ControlMsgHeader,
        completion_code: uint8_t,
        next_entry_handle: uint8_t,
        entries_in_response: uint8_t,
    ) -> Self {
        Self {
            hdr,
            completion_code,
            next_entry_handle,
            entries_in_response,
        }
    }

    pub fn from(
        req: Request,
        completion_code: CompletionCode,
        next_entry_handle: uint8_t,
        entries_in_response: uint8_t,
    ) -> Self {
        let mut hdr = req.hdr;
        hdr.set_rq(0);
        Self::new(
            hdr,
            completion_code as uint8_t,
            next_entry_handle,
            entries_in_response,
        )
    }
}
