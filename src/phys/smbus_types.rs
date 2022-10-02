use mctp_base_lib::base::*;

const SMBUS_COMMAND_CODE_MCTP: u8 = 0x0f;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, c2rust_bitfields::BitfieldStruct)]
#[mctp_emu_derive::add_binary_derives]
#[repr(C, packed)]
pub struct SmbusPhysTransportHeader {
    dest_addr: u8,
    command_code: u8,
    byte_count: u8,
    src_addr: u8,
}

impl SmbusPhysTransportHeader {
    pub fn new(dest_addr_7bit: u8, src_addr_7bit: u8, byte_count: u8) -> Self {
        SmbusPhysTransportHeader {
            dest_addr: dest_addr_7bit << 1,
            command_code: SMBUS_COMMAND_CODE_MCTP,
            byte_count,
            src_addr: src_addr_7bit << 1 | 0x01,
        }
    }
}
