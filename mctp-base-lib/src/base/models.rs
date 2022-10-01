use c2rust_bitfields::BitfieldStruct;
use cascade::cascade;
use mctp_emu_derive::{add_binary_derives, FromBinary};

use crate::base::*;

pub const MCTP_BASE_PROTOCOL_SUPPORTED_HDR_VERSION: uint8_t = 0x1;

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default)]
#[add_binary_derives]
#[repr(C, packed)]
pub struct TransportHeader {
    #[bitfield(name = "header_version", ty = "uint8_t", bits = "0..=3")]
    #[bitfield(name = "rsvd", ty = "uint8_t", bits = "4..=7")]
    header_version_rsvd: [u8; 1],
    pub destination_eid: uint8_t,
    pub source_eid: uint8_t,
    #[bitfield(name = "msg_tag", ty = "uint8_t", bits = "0..=2")]
    #[bitfield(name = "tag_owner", ty = "uint8_t", bits = "3..=3")]
    #[bitfield(name = "packet_seq", ty = "uint8_t", bits = "4..=5")]
    #[bitfield(name = "eom", ty = "uint8_t", bits = "6..=6")]
    #[bitfield(name = "som", ty = "uint8_t", bits = "7..=7")]
    msg_tag_tag_owner_packet_seq_eom_som: [u8; 1],
}

#[buildstructor::buildstructor]
impl TransportHeader {
    #[builder]
    pub fn new(
        src_eid: uint8_t,
        dst_eid: uint8_t,
        msg_tag: uint8_t,
        tag_owner: Option<bool>,
        start_of_msg: Option<bool>,
        end_of_msg: Option<bool>,
    ) -> Self {
        cascade! {
            Self {
                header_version_rsvd: [0; 1],
                destination_eid: dst_eid,
                source_eid: src_eid,
                msg_tag_tag_owner_packet_seq_eom_som: [0; 1],
            };
            ..set_header_version(MCTP_BASE_PROTOCOL_SUPPORTED_HDR_VERSION);
            ..set_msg_tag(msg_tag);
            ..set_tag_owner(tag_owner.unwrap_or_default().into());
            ..set_som(start_of_msg.unwrap_or_default().into());
            ..set_eom(end_of_msg.unwrap_or_default().into());
        }
    }

    pub fn create_response(&self) -> TransportHeader {
        TransportHeader::builder()
            .src_eid(self.destination_eid)
            .dst_eid(self.source_eid)
            .msg_tag(self.msg_tag())
            .tag_owner(self.tag_owner() == 0)
            .start_of_msg(true)
            .end_of_msg(true)
            .build()
    }
}
