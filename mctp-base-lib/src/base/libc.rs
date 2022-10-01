#![allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]

pub mod types_h {
    pub type __uint8_t = libc::c_uchar;
    pub type __int8_t = libc::c_char;
    pub type __uint16_t = libc::c_ushort;
    pub type __int16_t = libc::c_short;
    pub type __uint32_t = libc::c_uint;
    pub type __int32_t = libc::c_int;
}

pub mod stdint_uintn_h {
    pub type uint8_t = __uint8_t;
    pub type uint16_t = __uint16_t;
    pub type uint32_t = __uint32_t;
    use super::types_h::{__uint16_t, __uint32_t, __uint8_t};
}

pub mod stdint_intn_h {
    pub type int8_t = __int8_t;
    pub type int16_t = __int16_t;
    pub type int32_t = __int32_t;
    use super::types_h::{__int16_t, __int32_t, __int8_t};
}

pub mod stddef_h {
    pub type size_t = libc::c_ulong;
    pub const NULL: libc::c_int = 0 as libc::c_int;
}
