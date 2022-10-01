use mctp_emu_derive::{DeserializeU8Enum, SerializeU8Enum};
use num_enum::{FromPrimitive};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A list of supported Command Codes
#[derive(
    Debug, PartialEq, Copy, Clone, DeserializeU8Enum, SerializeU8Enum, Default, Ord, PartialOrd, Eq, FromPrimitive,
)]
#[repr(u8)]
pub enum CommandCode {
    /// Reserved
    Reserved = 0x00,
    /// Assigns an EID to the endpoint at the given physical address.
    SetEndpointID = 0x01,
    /// Returns the EID presently assigned to an endpoint.
    GetEndpointID = 0x02,
    /// Retrieves a per-device unique UUID associated with the endpoint.
    GetEndpointUUID = 0x03,
    /// Lists which versions of the MCTP control protocol are supported on an
    /// endpoint.
    GetMCTPVersionSupport = 0x04,
    /// Lists the message types that an endpoint supports.
    GetMessageTypeSupport = 0x05,
    /// Used to discover an MCTP endpoint’s vendor-specific MCTP extensions
    /// and capabilities.
    GetVendorDefinedMessageSupport = 0x06,
    /// Used to get the physical address associated with a given EID.
    ResolveEndpointID = 0x07,
    /// Used by the bus owner to allocate a pool of EIDs to an MCTP bridge
    AllocateEndpointIDs = 0x08,
    /// Used by the bus owner to extend or update the routing information that
    /// is maintained by an MCTP bridge
    RoutingInformationUpdate = 0x09,
    /// Used to request an MCTP bridge to return data corresponding to its
    /// present routing table entries
    GetRoutingTableEntries = 0x0A,
    /// Used to direct endpoints to clear their “discovered”flags to enable
    /// them to respond to the Endpoint Discovery command
    PrepareForEndpointDiscovery = 0x0B,
    /// Used to discover MCTP-capable devices on a bus, provided that another
    /// discovery mechanism is not defined for the particular physical medium
    EndpointDiscovery = 0x0C,
    /// Used to notify the bus owner that an MCTP device has become available
    /// on the bus
    DiscoveryNotify = 0x0D,
    /// Used to get the MCTP networkID
    GetNetworkID = 0x0E,
    /// Used to discover what bridges, if any, are in the path to a given
    /// target endpoint and what transmission unit sizes the bridges will pass
    /// for a given message type when routing to the target endpoint
    QueryHop = 0x0F,
    /// Used by endpoints to find another endpoint matching an endpoint that
    /// uses a specific UUID
    ResolveUUID = 0x10,
    /// Used to discover the data rate limit settings of the given target
    /// for incoming messages
    QueryRateLimit = 0x11,
    /// Used to request the allowed transmit data rate limit for the given
    /// endpoint for outgoing messages
    RequestTXRateLimit = 0x12,
    /// Used to update the receiving side on change to the transmit data
    /// rate which was not requested by the receiver
    UpdateRateLimit = 0x13,
    /// Used to discover the existing device MCTP interfaces
    QuerySupportedInterfaces = 0x14,
    /// Not supported
    #[default]
    Unknown = 0xFF,
}

/// This field is only present in Response messages. This field contains a
/// value that indicates whether the response completed normally. If the
/// command did not complete normally, the value can provide additional
/// information regarding the error condition. The values for completion
/// codes are specified in Table 13.
#[derive(
    Debug, PartialEq, Eq, Copy, Clone, DeserializeU8Enum, SerializeU8Enum, FromPrimitive, Default,
)]
#[repr(u8)]
pub enum CompletionCode {
    /// The Request was accepted and completed normally
    Success = 0x00,
    /// This is a generic failure message. (It should not be used when a
    /// more specific result code applies.)
    Error = 0x01,
    /// The packet payload contained invalid data or an illegal parameter
    /// value.
    ErrorInvalidData = 0x02,
    /// The message length was invalid. (The Message body was larger or
    /// smaller than expected for the particular request.)
    ErrorInvalidLength = 0x03,
    /// The Receiver is in a transient state where it is not ready to
    /// receive the corresponding message
    ErrorNotReady = 0x04,
    /// The command field in the control type of the received message
    /// is unspecified or not supported on this endpoint. This completion
    /// code shall be returned for any unsupported command values received
    /// in MCTP control Request messages.
    #[default]
    ErrorUnsupportedCmd = 0x05,
}

/// The Message Type of the MCTP packet
#[derive(
    Debug, PartialEq, Eq, Copy, Clone, DeserializeU8Enum, SerializeU8Enum, FromPrimitive, Default,
)]
#[repr(u8)]
pub enum MessageType {
    /// Messages used to support initialization and configuration of MCTP communication within an MCTP network, as
    /// specified in DSP0236
    Control = 0x00,
    /// Messages used to convey Platform Level Data Model (PLDM) traffic over MCTP , as specified in DSP0241.
    Pldm = 0x01,
    /// Messages used to convey NC-SI Control traffic over MCTP, as specified in DSP0261.
    NCSIOverMCTP = 0x02,
    /// Messages used to convey Ethernet traffic over MCTP. See DSP0261. This message type can also be used separately
    /// by other specifications.
    EthernetOverMCTP = 0x03,
    /// Messages used to convey NVM Express (NVMe) Management Messages over MCTP, as specified in DSP0235.
    NvmExpressOverMCTP = 0x04,
    /// Messages used to convey Security Protocol and Data Model Specification (SPDM) traffic over MCTP, as specified
    /// in DSP0275.
    SpdmOverMCTP = 0x05,
    /// Messages used to convey Secured Messages using SPDM over MCTP Binding Specification traffic, as specified in
    /// DSP0276.
    SecuredMessages = 0x06,
    /// Messages used to convey CXLTM Fabric Manager API over MCTP Binding Specification traffic as specified in
    /// DSP0234.
    CxlFmApiOverMCTP = 0x07,
    /// Messages used to convey CXLTM Type 3 Device Component Command Interface over MCTP Binding Specification traffic
    /// as specified in DSP0281.
    CxlCciOverMCTP = 0x08,
    /// Message type used to support VDMs where the vendor is identified using a PCI-based vendor ID.
    VendorDefinedPCI = 0x7E,
    /// Message type used to support VDMs where the vendor is identified using an IANA-based vendor ID.
    VendorDefinedIANA = 0x7F,
    /// Internal use
    #[default]
    Invalid = 0xFF,
}

#[derive(
    Debug, PartialEq, Eq, Copy, Clone, DeserializeU8Enum, SerializeU8Enum, FromPrimitive, Default,
)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum PhysicalMediumIdentifier {
    #[default]
    Unspecified = 0x0,
    SMBUS_2_0_100khz = 0x1,
    SMBUS_2_0_I2C_100khz = 0x2,
    I2C_100khz = 0x3,
    SMBUS_3_0_I2C_400khz = 0x4,
    SMBUS_3_0_I2C_1mhz = 0x5,
    I2C_3_4mhz = 0x6,
    PCIeRev_1_1 = 0x8,
    PCIeRev_2_0 = 0x9,
    PCIeRev_2_1 = 0xA,
    PCIeRev_3 = 0xB,
    PCIeRev_4 = 0xC,
    PCIeRev_5 = 0xD,
    PCICompatible = 0xF,
    USB_1_1 = 0x10,
    USB_2 = 0x11,
    USB_3 = 0x12,
    NCSIOverRBT = 0x18,
    KCSLegacy = 0x20,
    KCSPCI = 0x21,
    SerialHostLegacy = 0x22,
    SerialHostPCI = 0x23,
    AsyncSerial = 0x24,
    I3CBasic = 0x30,
}

#[derive(
    Debug, PartialEq, Eq, Copy, Clone, DeserializeU8Enum, SerializeU8Enum, FromPrimitive, Default,
)]
#[repr(u8)]
pub enum PhysicalTransportBinding {
    Reserved = 0x0,
    MCTPoverSMBus = 0x01,
    MCTPoverPcieVdm = 0x02,
    MCTPoverKCS   = 0x04,
    MCTPoverSerial = 0x05,
    MCTPoverI3C = 0x06,
    #[default]
    VendorDefined = 0xff,
}

/// Add a few tests to ensure conversion to/from various types: Bytes, Vec, u8/uint8_t
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_completion_code_serialize() -> Result<()> {
        let bytes = vec![0x03 as u8];

        let completion_code = CompletionCode::ErrorInvalidLength;

        assert_eq!(bincode::serialize(&completion_code)?, bytes);

        Ok(())
    }

    #[test]
    fn test_completion_code_known_u8_deserialize() -> Result<()> {
        let bytes = vec![2];

        let mut completion_code: CompletionCode;

        assert_eq!(CompletionCode::ErrorInvalidData, bincode::deserialize(&bytes)?);

        Ok(())
    }

    #[test]
    fn test_completion_code_unknown_u8_deserialize() -> Result<()> {
        let bytes = vec![0x55];

        let mut completion_code: CompletionCode;

        assert_eq!(CompletionCode::ErrorUnsupportedCmd, bincode::deserialize(&bytes)?);

        Ok(())
    }

    #[test]
    fn test_completion_code_from_u8() {
        assert_eq!(CompletionCode::Success, 0.into());
        assert_eq!(CompletionCode::Success, CompletionCode::from(0));
        assert_eq!(CompletionCode::Error, CompletionCode::from(1));
        assert_eq!(CompletionCode::Error, 1.into());
        assert_eq!(CompletionCode::ErrorUnsupportedCmd, CompletionCode::from(5));
        assert_eq!(CompletionCode::ErrorUnsupportedCmd, CompletionCode::from(0x55));
    }
}
