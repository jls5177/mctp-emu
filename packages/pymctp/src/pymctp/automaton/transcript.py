# SPDX-FileCopyrightText: 2026 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Thread-safe packet and logical-message transcripts for machine tests."""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from scapy.packet import Packet

from pymctp.layers.mctp.transport import TransportHdrPacket


class TraceDirection(str, Enum):
    RX = "rx"
    TX = "tx"


class TraceEventKind(str, Enum):
    PACKET = "packet"
    MESSAGE = "message"
    REASSEMBLY_STARTED = "reassembly_started"
    REASSEMBLY_CONTINUED = "reassembly_continued"
    REASSEMBLY_REJECTED = "reassembly_rejected"
    REASSEMBLY_EXPIRED = "reassembly_expired"


@dataclass(frozen=True)
class PacketTraceEvent:
    """One immutable transport observation."""

    timestamp: float
    endpoint: str
    direction: TraceDirection
    kind: TraceEventKind
    raw: bytes
    transport_raw: bytes = b""
    src: int | None = None
    dst: int | None = None
    tag: int | None = None
    to: int | None = None
    som: bool | None = None
    eom: bool | None = None
    pkt_seq: int | None = None
    msg_type: int | None = None
    protocol: str | None = None
    protocol_type: int | None = None
    command_code: int | None = None
    is_request: bool | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["direction"] = self.direction.value
        data["kind"] = self.kind.value
        data["raw"] = self.raw.hex()
        data["transport_raw"] = self.transport_raw.hex()
        return data


def packet_trace_event(
    packet: Packet | None,
    *,
    endpoint: str,
    direction: TraceDirection,
    kind: TraceEventKind,
    detail: str | None = None,
    timestamp: float | None = None,
) -> PacketTraceEvent:
    """Describe the transport and protocol identity carried by ``packet``."""
    raw_packet = bytes(packet) if packet is not None else b""
    transport = packet.getlayer(TransportHdrPacket) if packet is not None else None
    protocol, protocol_type, command_code, is_request = _protocol_identity(packet, transport)
    return PacketTraceEvent(
        timestamp=time.monotonic() if timestamp is None else timestamp,
        endpoint=endpoint,
        direction=direction,
        kind=kind,
        raw=raw_packet,
        transport_raw=bytes(transport) if transport is not None else b"",
        src=int(transport.src) if transport is not None else None,
        dst=int(transport.dst) if transport is not None else None,
        tag=int(transport.tag) if transport is not None else None,
        to=int(transport.to) if transport is not None else None,
        som=bool(transport.som) if transport is not None else None,
        eom=bool(transport.eom) if transport is not None else None,
        pkt_seq=int(transport.pkt_seq) if transport is not None else None,
        msg_type=int(transport.msg_type) if transport is not None and transport.som else None,
        protocol=protocol,
        protocol_type=protocol_type,
        command_code=command_code,
        is_request=is_request,
        detail=detail,
    )


def _protocol_identity(
    packet: Packet | None,
    transport: TransportHdrPacket | None,
) -> tuple[str | None, int | None, int | None, bool | None]:
    if packet is None:
        return None, None, None, None
    for layer_name, protocol, command_attr, request_attr in (
        ("ControlHdrPacket", "mctp-control", "cmd_code", "rq"),
        ("PldmHdrPacket", "pldm", "cmd_code", "rq"),
        ("SpdmHdrPacket", "spdm", "request_response_code", None),
        ("VdPciHdrPacket", "vdpci", "vdm_cmd_code", None),
    ):
        layer = packet.getlayer(layer_name)
        if layer is None:
            continue
        request: bool | None
        if request_attr is not None:
            request = bool(getattr(layer, request_attr))
        else:
            is_request = getattr(layer, "is_request", None)
            request = bool(is_request()) if callable(is_request) else (bool(transport.to) if transport is not None else None)
        protocol_type = int(getattr(layer, "pldm_type")) if protocol == "pldm" else None
        return protocol, protocol_type, int(getattr(layer, command_attr)), request
    return None, None, None, bool(transport.to) if transport is not None else None


class EndpointTranscript:
    """Callable observer that stores events safely across endpoint threads."""

    def __init__(self) -> None:
        self._events: list[PacketTraceEvent] = []
        self._lock = threading.Lock()

    def __call__(self, event: PacketTraceEvent) -> None:
        with self._lock:
            self._events.append(event)

    def snapshot(self) -> list[PacketTraceEvent]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def to_dict(self) -> list[dict[str, Any]]:
        return [event.to_dict() for event in self.snapshot()]


def logical_transport_packet(packets: list[Packet]) -> TransportHdrPacket | None:
    """Rebuild one logical MCTP message from its outbound transport packets."""
    transports = [packet.getlayer(TransportHdrPacket) for packet in packets]
    transports = [packet for packet in transports if packet is not None]
    if not transports:
        return None
    if len(transports) == 1:
        return TransportHdrPacket(bytes(transports[0]))

    first = bytes(transports[0])
    header = bytearray(first[:4])
    header[3] |= 0x40
    payload = bytearray(first[4:])
    for packet in transports[1:]:
        payload.extend(bytes(packet)[4:])
    return TransportHdrPacket(bytes(header) + bytes(payload))
