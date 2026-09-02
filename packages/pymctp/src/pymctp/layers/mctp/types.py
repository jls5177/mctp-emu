# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import base64
import dataclasses
import json
import uuid
from collections import defaultdict
from dataclasses import field
from enum import IntEnum
from pathlib import Path
from typing import Any, Protocol, TypeVar, runtime_checkable

from mashumaro import DataClassDictMixin, field_options
from mashumaro.config import BaseConfig

from ..interfaces import AnyPacketType


class MsgTypes(IntEnum):
    """
    Messages used to support initialization and configuration of MCTP communication within an MCTP network, as
    specified in DSP0236
    """

    CTRL = 0x00
    PLDM = 0x01
    NCSI = 0x02
    Ethernet = 0x03
    NVMeMgmtMsg = 0x04
    SPDM = 0x05
    SECUREDMSG = 0x06
    CXL_FM_API = 0x07
    CXL_CCI = 0x08
    VDPCI = 0x7E
    VDIANA = 0x7F


class VendorIdFormat(IntEnum):
    PCI_VENDOR_ID = 0x0
    """16-bit Unsigned Integer that identifies the manufacturer
    of the device. Valid vendor identifiers are allocated by the
    PCI SIG to ensure uniqueness."""

    IANA_ENT_NUMBER = 0x1
    """The IANA enterprise number for the organization or vendor
    expressed as a 32-bit unsigned binary number."""


@dataclasses.dataclass(frozen=True)
class VendorCapabilitySet(DataClassDictMixin):
    vendor_id: int
    id_format: VendorIdFormat = VendorIdFormat.PCI_VENDOR_ID
    command_set_type: int = 0


class PhysicalTransportBindingId(IntEnum):
    Reserved = 0x0
    MCTPoverSMBus = 0x01
    MCTPoverPcieVdm = 0x02
    MCTPoverKCS = 0x04
    MCTPoverSerial = 0x05
    MCTPoverI3C = 0x06
    VendorDefined = 0xFF


class PhysicalMediumIdentifiers(IntEnum):
    Unspecified = 0x0
    SMBUS_2_0_100khz = 0x1
    SMBUS_2_0_I2C_100khz = 0x2
    I2C_100khz = 0x3
    SMBUS_3_0_I2C_400khz = 0x4
    SMBUS_3_0_I2C_1mhz = 0x5
    I2C_3_4mhz = 0x6
    PCIeRev_1_1 = 0x8
    PCIeRev_2_0 = 0x9
    PCIeRev_2_1 = 0xA
    PCIeRev_3 = 0xB
    PCIeRev_4 = 0xC
    PCIeRev_5 = 0xD
    PCICompatible = 0xF
    USB_1_1 = 0x10
    USB_2 = 0x11
    USB_3 = 0x12
    NCSIOverRBT = 0x18
    KCSLegacy = 0x20
    KCSPCI = 0x21
    SerialHostLegacy = 0x22
    SerialHostPCI = 0x23
    AsyncSerial = 0x24
    I3CBasic = 0x30


class EntryType(IntEnum):
    SINGLE_ENDPOINT = 0
    BRIDGE_AND_DOWNSTREAM_ENDPOINT = 1
    SINGLE_BRIDGE_ENDPOINT = 2
    ADDITIONAL_BRIDGE_EID_RANGE = 3


@dataclasses.dataclass(frozen=True)
class RoutingTableEntry(DataClassDictMixin):
    starting_eid: int
    port_number: int
    phy_address: list[int]
    phys_transport_binding_id: PhysicalTransportBindingId = PhysicalTransportBindingId.MCTPoverSMBus
    phy_media_type_id: PhysicalMediumIdentifiers = PhysicalMediumIdentifiers.I2C_100khz
    entry_type: EntryType = EntryType.SINGLE_ENDPOINT
    eid_range: int = 1
    static_eid: bool = False


@dataclasses.dataclass(frozen=True)
class Smbus7bitAddress(DataClassDictMixin):
    address: int

    def __post_init__(self):
        if self.address > 0x7F:
            msg = f"SMBUS address {hex(self.address)} is more than 7 bits."
            raise ValueError(msg)

    def read(self) -> int:
        return self.address << 1 | 0x01

    def write(self) -> int:
        return self.address << 1 | 0x00


@dataclasses.dataclass(frozen=True)
class Smbus10bitAddress(DataClassDictMixin):
    address: int

    def __post_init__(self):
        if self.address > 0x3FF:
            msg = f"SMBUS address {hex(self.address)} is more than 10 bits."
            raise ValueError(msg)


AnyPhysicalAddress = TypeVar("AnyPhysicalAddress", Smbus7bitAddress, Smbus10bitAddress, None)


@dataclasses.dataclass(frozen=True)
class MctpResponse(DataClassDictMixin):
    request: list[int]
    response: list[int]
    processing_delay: int = field(metadata=field_options(alias="processing-delay"))
    key: bytes = field(init=False)
    data: bytes = field(init=False)
    response_index: int = 0
    description: str = "<missing>"

    def __post_init__(self):
        req = bytes(self.request)
        key = base64.b64encode(req)
        object.__setattr__(self, "key", key)

        packet = bytes(self.response)
        object.__setattr__(self, "data", packet)


# @dataclasses.dataclass(frozen=True)
# class VdPciResponeList(DataClassDictMixin):
#     vendors: Dict[str, Dict[str, List[MctpResponse]]]


@dataclasses.dataclass(frozen=True)
class MctpResponseList(DataClassDictMixin):
    responses: dict[MsgTypes, list[MctpResponse] | dict[str, dict[str, list[MctpResponse]]]]


def deserialize_msg_types(values: list[MsgTypes] | list[str]) -> list[MsgTypes]:
    if not isinstance(values, list):
        msg = f"Unknown msg type: {type(values)}"
        raise TypeError(msg)
    if all(isinstance(y, MsgTypes) for y in values):
        return values
    msg_types = []
    for mt in values:
        if isinstance(mt, str) and hasattr(MsgTypes, mt):
            msg_types += [MsgTypes[mt]]
            continue
        msg = f"Unknown msg type: {mt}"
        raise TypeError(msg)
    return msg_types


@dataclasses.dataclass
class EndpointContext(DataClassDictMixin):
    physical_address: Smbus7bitAddress | None = None
    static_eid: int | None = None
    assigned_eid: int = 0
    discovered: bool = False
    is_bus_owner: bool = False
    is_bridge: bool = False
    pool_size: int = 0
    mtu_size: int = 240 - (4 + 5)  # make room for transport and protocol headers
    allocated_pool: list[int] | None = None
    endpoint_uuid: uuid.UUID = dataclasses.field(default_factory=lambda: uuid.uuid4())
    supported_msg_types: list[MsgTypes] = dataclasses.field(default_factory=lambda: [MsgTypes.CTRL])
    supported_vdm_msg_types: list[VendorCapabilitySet] = dataclasses.field(default_factory=list)
    mctp_responses: MctpResponseList | None = None
    routing_table_ready: bool = False
    routing_table: list[RoutingTableEntry] = dataclasses.field(default_factory=list)
    max_reassembly_contexts: int = 1
    reassembly_timeout_s: float = 5.0
    # Deprecated compatibility view. EndpointSession now owns validated
    # reassembly state through MctpReassemblyManager.
    reassembly_list: dict[str, bytes] = dataclasses.field(default_factory=dict)
    msg_type_context: dict[str, Any] = dataclasses.field(default_factory=lambda: defaultdict(dict))

    class Config(BaseConfig):
        serialization_strategy = {list[MsgTypes]: {"deserialize": deserialize_msg_types}}

    @property
    def supports_bridging(self) -> bool:
        """True when this endpoint answers bridge/routing control commands.

        A bus owner is always a bridge, but a bridge is not necessarily the bus
        owner.  ``is_bus_owner`` is still honoured so contexts written before
        ``is_bridge`` existed keep behaving the same way.
        """
        return self.is_bridge or self.is_bus_owner

    @property
    def eid(self) -> int:
        if self.assigned_eid:
            return self.assigned_eid
        if self.static_eid:
            return self.static_eid
        # no EID assigned, just return the null EID
        return 0

    def import_json_responses(self, resp_file: Path):
        with resp_file.open("r") as f:
            data: dict[str, Any] = json.load(f)
            data = {MsgTypes[k]: v for k, v in data.items() if MsgTypes[k] in self.supported_msg_types}
            self.mctp_responses = MctpResponseList.from_dict({"responses": data})

    def get_response(
        self, msg_type: MsgTypes, req_bytes: bytes, vendor_id: str = "", vdm_cmd_code: str = ""
    ) -> MctpResponse | None:
        if msg_type not in MsgTypes:
            return None
        if msg_type not in self.mctp_responses.responses:
            return None
        key = base64.b64encode(req_bytes)
        if msg_type != MsgTypes.VDPCI:
            for resp in self.mctp_responses.responses[msg_type]:
                if resp.key == key:
                    return resp
        else:
            responses = self.mctp_responses.responses[msg_type]
            if vendor_id not in responses:
                return None
            responses = responses[vendor_id]
            if vdm_cmd_code not in responses:
                return None
            for resp in responses[vdm_cmd_code]:
                if resp.key == key:
                    return resp
        return None


@runtime_checkable
class ICanReply(Protocol):
    def is_request(self, check_payload: bool = True) -> bool:
        pass

    def make_reply(self, ctx: EndpointContext) -> AnyPacketType:
        pass
