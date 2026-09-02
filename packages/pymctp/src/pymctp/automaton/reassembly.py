# SPDX-FileCopyrightText: 2026 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Validated MCTP message reassembly for endpoint sessions."""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum

from pymctp.layers.mctp.transport import TransportHdrPacket


@dataclass(frozen=True)
class ReassemblyKey:
    """Fields that identify one in-flight MCTP message."""

    src: int
    dst: int
    tag: int
    to: int

    @classmethod
    def from_packet(cls, packet: TransportHdrPacket) -> ReassemblyKey:
        return cls(src=int(packet.src), dst=int(packet.dst), tag=int(packet.tag), to=int(packet.to))

    def __str__(self) -> str:
        return f"{self.src:02x}->{self.dst:02x}/tag={self.tag}/to={self.to}"


class ReassemblyUpdateKind(str, Enum):
    """Outcome of feeding one transport packet into a reassembler."""

    SINGLE = "single"
    STARTED = "started"
    CONTINUED = "continued"
    COMPLETED = "completed"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(frozen=True)
class ReassemblyUpdate:
    """One observable reassembly transition."""

    kind: ReassemblyUpdateKind
    key: ReassemblyKey
    packet: TransportHdrPacket | None = None
    detail: str | None = None


@dataclass
class _InFlightMessage:
    header: bytes
    payload: bytearray
    last_seq: int
    started_at: float
    updated_at: float


class MctpReassemblyManager:
    """Reassemble up to an endpoint-configured number of MCTP messages."""

    def __init__(
        self,
        *,
        max_contexts: int = 1,
        timeout_s: float = 5.0,
        time_source=time.monotonic,
    ) -> None:
        if not 1 <= int(max_contexts) <= 8:
            msg = f"max_contexts must be between 1 and 8, got {max_contexts}"
            raise ValueError(msg)
        if float(timeout_s) <= 0:
            msg = f"timeout_s must be positive, got {timeout_s}"
            raise ValueError(msg)
        self.max_contexts = int(max_contexts)
        self.timeout_s = float(timeout_s)
        self._time_source = time_source
        self._contexts: dict[ReassemblyKey, _InFlightMessage] = {}

    @property
    def active_count(self) -> int:
        return len(self._contexts)

    @property
    def active_keys(self) -> tuple[ReassemblyKey, ...]:
        return tuple(self._contexts)

    def expire(self, now: float | None = None) -> list[ReassemblyUpdate]:
        """Drop contexts idle longer than ``timeout_s``."""
        current = self._time_source() if now is None else float(now)
        expired: list[ReassemblyUpdate] = []
        for key, context in list(self._contexts.items()):
            if current - context.updated_at < self.timeout_s:
                continue
            del self._contexts[key]
            expired.append(
                ReassemblyUpdate(
                    ReassemblyUpdateKind.EXPIRED,
                    key,
                    detail=f"incomplete message expired after {current - context.updated_at:.3f}s idle",
                )
            )
        return expired

    def feed(self, packet: TransportHdrPacket, now: float | None = None) -> list[ReassemblyUpdate]:
        """Consume one MCTP transport packet and return observable transitions."""
        current = self._time_source() if now is None else float(now)
        updates = self.expire(current)
        key = ReassemblyKey.from_packet(packet)
        som = bool(packet.som)
        eom = bool(packet.eom)

        if som and eom:
            updates.append(
                ReassemblyUpdate(
                    ReassemblyUpdateKind.SINGLE,
                    key,
                    packet=TransportHdrPacket(bytes(packet)),
                )
            )
            return updates

        if som:
            replaced = self._contexts.pop(key, None)
            if replaced is None and len(self._contexts) >= self.max_contexts:
                updates.append(
                    ReassemblyUpdate(
                        ReassemblyUpdateKind.REJECTED,
                        key,
                        detail=f"reassembly context limit {self.max_contexts} reached",
                    )
                )
                return updates

            raw_packet = bytes(packet)
            self._contexts[key] = _InFlightMessage(
                header=raw_packet[:4],
                payload=bytearray(raw_packet[4:]),
                last_seq=int(packet.pkt_seq),
                started_at=current,
                updated_at=current,
            )
            detail = "new SOM replaced an incomplete message with the same key" if replaced is not None else None
            updates.append(ReassemblyUpdate(ReassemblyUpdateKind.STARTED, key, detail=detail))
            return updates

        context = self._contexts.get(key)
        if context is None:
            updates.append(
                ReassemblyUpdate(
                    ReassemblyUpdateKind.REJECTED,
                    key,
                    detail="fragment arrived without a matching SOM",
                )
            )
            return updates

        expected_seq = (context.last_seq + 1) % 4
        actual_seq = int(packet.pkt_seq)
        if actual_seq != expected_seq:
            del self._contexts[key]
            updates.append(
                ReassemblyUpdate(
                    ReassemblyUpdateKind.REJECTED,
                    key,
                    detail=f"packet sequence out of order: expected {expected_seq}, got {actual_seq}",
                )
            )
            return updates

        context.payload.extend(bytes(packet)[4:])
        context.last_seq = actual_seq
        context.updated_at = current
        if not eom:
            updates.append(ReassemblyUpdate(ReassemblyUpdateKind.CONTINUED, key))
            return updates

        del self._contexts[key]
        header = bytearray(context.header)
        header[3] |= 0x40  # Present the completed logical message with EOM set.
        logical = TransportHdrPacket(bytes(header) + bytes(context.payload))
        updates.append(ReassemblyUpdate(ReassemblyUpdateKind.COMPLETED, key, packet=logical))
        return updates
