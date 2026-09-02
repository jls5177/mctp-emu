# SPDX-FileCopyrightText: 2026 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""MCTP reassembly and transcript behavior."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from scapy.packet import Packet, Raw

from pymctp.automaton.reassembly import MctpReassemblyManager, ReassemblyUpdateKind
from pymctp.automaton.sessions import EndpointSession
from pymctp.automaton.transcript import EndpointTranscript, TraceDirection, TraceEventKind, packet_trace_event
from pymctp.layers.mctp.control import ControlHdr, GetEndpointID
from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import EndpointContext, MsgTypes


def _fragment(
    *,
    src: int = 0x20,
    dst: int = 0x10,
    tag: int = 0,
    seq: int,
    som: bool,
    eom: bool,
    payload: bytes,
) -> TransportHdrPacket:
    return TransportHdr(
        src=src,
        dst=dst,
        tag=tag,
        to=1,
        pkt_seq=seq,
        som=som,
        eom=eom,
        msg_type=MsgTypes.CTRL,
    ) / Raw(payload)


def test_one_context_endpoint_rejects_a_second_in_flight_message() -> None:
    manager = MctpReassemblyManager(max_contexts=1)

    first = manager.feed(_fragment(tag=0, seq=0, som=True, eom=False, payload=b"A"))
    second = manager.feed(_fragment(tag=1, seq=0, som=True, eom=False, payload=b"B"))

    assert first[-1].kind == ReassemblyUpdateKind.STARTED
    assert second[-1].kind == ReassemblyUpdateKind.REJECTED
    assert second[-1].detail == "reassembly context limit 1 reached"
    assert manager.active_count == 1


def test_eight_context_endpoint_reassembles_interleaved_messages() -> None:
    manager = MctpReassemblyManager(max_contexts=8)
    for tag in range(8):
        update = manager.feed(_fragment(tag=tag, seq=0, som=True, eom=False, payload=bytes([tag])))
        assert update[-1].kind == ReassemblyUpdateKind.STARTED

    completed = {}
    for tag in reversed(range(8)):
        update = manager.feed(_fragment(tag=tag, seq=1, som=False, eom=True, payload=bytes([tag + 8])))
        assert update[-1].kind == ReassemblyUpdateKind.COMPLETED
        completed[tag] = bytes(update[-1].packet)[4:]

    assert completed == {tag: b"\x00" + bytes([tag, tag + 8]) for tag in range(8)}
    assert manager.active_count == 0


def test_ninth_context_is_rejected() -> None:
    manager = MctpReassemblyManager(max_contexts=8)
    for src in range(8):
        manager.feed(_fragment(src=src, tag=0, seq=0, som=True, eom=False, payload=b"A"))

    update = manager.feed(_fragment(src=8, tag=0, seq=0, som=True, eom=False, payload=b"B"))

    assert update[-1].kind == ReassemblyUpdateKind.REJECTED
    assert "limit 8" in str(update[-1].detail)


def test_out_of_order_fragment_abandons_the_context() -> None:
    manager = MctpReassemblyManager(max_contexts=1)
    manager.feed(_fragment(seq=0, som=True, eom=False, payload=b"A"))

    update = manager.feed(_fragment(seq=2, som=False, eom=True, payload=b"B"))

    assert update[-1].kind == ReassemblyUpdateKind.REJECTED
    assert "expected 1, got 2" in str(update[-1].detail)
    assert manager.active_count == 0


def test_incomplete_context_expires() -> None:
    now = [10.0]
    manager = MctpReassemblyManager(max_contexts=1, timeout_s=2.0, time_source=lambda: now[0])
    manager.feed(_fragment(seq=0, som=True, eom=False, payload=b"A"))
    now[0] = 12.1

    updates = manager.expire()

    assert updates[0].kind == ReassemblyUpdateKind.EXPIRED
    assert manager.active_count == 0


@dataclass
class _FakeAM:
    replies: list[list[Packet]] = field(default_factory=list)

    def is_request(self, packet: Packet) -> bool:
        return True

    def make_reply(self, packet: Packet):
        return None

    def send_reply(self, packets) -> None:
        self.replies.append(list(packets))


def test_session_does_not_reply_before_request_eom() -> None:
    transcript = EndpointTranscript()
    session = EndpointSession(
        context=EndpointContext(max_reassembly_contexts=1),
        socket=object(),
        endpoint_name="rot",
        observer=transcript,
    )
    am = _FakeAM()
    session.am = am

    session.on_packet_received(
        TransportHdr(src=0x20, dst=0x10, tag=0, to=1, pkt_seq=0, som=1, eom=0, msg_type=0x7F) / Raw(b"A")
    )
    assert am.replies == []

    session.on_packet_received(
        TransportHdr(src=0x20, dst=0x10, tag=0, to=1, pkt_seq=1, som=0, eom=1, msg_type=0x7F) / Raw(b"B")
    )

    assert len(am.replies) == 1
    kinds = [event.kind for event in transcript.snapshot()]
    assert kinds == [
        TraceEventKind.PACKET,
        TraceEventKind.REASSEMBLY_STARTED,
        TraceEventKind.PACKET,
        TraceEventKind.MESSAGE,
    ]


def test_missing_som_is_observed_and_not_dispatched() -> None:
    transcript = EndpointTranscript()
    session = EndpointSession(
        context=EndpointContext(),
        socket=object(),
        endpoint_name="rot",
        observer=transcript,
    )
    am = _FakeAM()
    session.am = am

    session.on_packet_received(_fragment(seq=1, som=False, eom=True, payload=b"B"))

    assert am.replies == []
    assert transcript.snapshot()[-1].kind == TraceEventKind.REASSEMBLY_REJECTED


def test_transcript_extracts_control_command_identity() -> None:
    packet = (
        TransportHdr(src=0x20, dst=0x10, tag=3, to=1, pkt_seq=0, som=1, eom=1, msg_type=MsgTypes.CTRL)
        / ControlHdr(rq=True, cmd_code=GetEndpointID().cmd_code)
        / GetEndpointID()
    )

    event = packet_trace_event(
        packet,
        endpoint="rot",
        direction=TraceDirection.RX,
        kind=TraceEventKind.MESSAGE,
    )

    assert event.endpoint == "rot"
    assert event.protocol == "mctp-control"
    assert event.command_code == GetEndpointID().cmd_code
    assert event.is_request is True
    assert event.to_dict()["raw"] == bytes(packet).hex()


@pytest.mark.parametrize("limit", [0, 9])
def test_reassembly_context_limit_must_fit_the_mctp_tag_space(limit: int) -> None:
    with pytest.raises(ValueError, match="between 1 and 8"):
        MctpReassemblyManager(max_contexts=limit)
