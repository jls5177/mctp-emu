use c2rust_bitfields::BitfieldStruct;
use cascade::cascade;
use mctp_emu_derive::{add_binary_derives, FromBinary};

#[derive(Copy, Clone, BitfieldStruct, Debug, PartialEq, Eq, Default)]
#[add_binary_derives]
#[repr(C, packed)]
pub struct SmbusPhysTransportHeader {
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
