use crate::Responder;
use bytes::Bytes;

#[derive(Debug, Default, PartialEq, Ord, PartialOrd, Eq)]
#[allow(non_camel_case_types, unused)]
pub struct MsgFlowTag {
    pub dest_eid: u8,
    pub src_eid: u8,
    pub msg_tag: u8,
    pub tag_owner: bool,
}

pub type MctpFlow = (MsgFlowTag, Responder<Bytes>);
pub type MctpFlowList = Vec<MctpFlow>;
