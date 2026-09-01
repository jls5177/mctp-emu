# SPDX-FileCopyrightText: 2025 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""QEMU I2C "remote target" transport over a single bidirectional TCP stream.

QEMU is the I2C/SMBUS target device in this topology and acts as the TCP
*server*; this transport connects as the TCP *client*. A single connection
carries both directions, framed exactly like the I3C stream transport (see
:mod:`qemu_i3c_stream` and :mod:`stream_framing`)::

    [u32 length BE][u8 type][body...]

Message types (minimal, new protocol — not shared with the UDP
``i2c-netdev`` transport)::

    0x00 WRITE     — bytes written by the QEMU-side I2C/SMBUS master to us
                     (the slave/target). Delivered to callers as a parsed
                     :class:`~pymctp.layers.mctp.SmbusTransportPacket`.
    0x01 READ_REQ  — body ``[u16 len BE]``. The QEMU-side master wants to
                     read ``len`` bytes from us; we must answer with a
                     READ_RSP frame. Handled internally by :meth:`recv`.
    0x02 READ_RSP  — body is the bytes returned for a pending read. Sent by
                     us in response to READ_REQ; never expected inbound.
    0x03 ALERT     — async notify from slave (us) to master, optional body.
                     Sent via :meth:`send_alert`.
    0x07 HELLO     — body ``[u32 proto_version BE]``, sent once on connect.

Outbound data queued via :meth:`send` (already-wrapped SMBus/MCTP bytes) is
buffered until the master issues a READ_REQ, matching real I2C/SMBus turn-
around semantics where the slave cannot push data onto the bus unsolicited.

Master mode
------------

When constructed with ``master=True``, the socket instead models QEMU's
``i2c-target-remote`` *master* mode (peer-as-master / multi-master, mirroring
the old UDP ``i2c-netdev`` transport's semantics — see
:mod:`qemu_i2c_netdev`). QEMU masters the (virtual) I2C bus on our behalf, so
there is no READ_REQ/READ_RSP turn-around: every WRITE frame is address-
prefixed instead::

    WRITE (0x00) body := [addr_byte][data...]
    addr_byte        := (i2c_7bit_address << 1) | 0   # write, no R/W bit set

* :meth:`send` (peer -> QEMU): prefixes the already-wrapped SMBus/MCTP bytes
  with ``target_address`` (the BMC's own SMBus address, supplied at
  construction time) and transmits a WRITE frame immediately — QEMU masters
  the bus and writes ``data`` to ``target_address``.
* :meth:`recv` (QEMU -> peer): the BMC has mastered the bus and written to
  this endpoint's own address. The leading ``addr_byte`` (this endpoint's own
  address) is stripped and the remainder is parsed as a
  :class:`~pymctp.layers.mctp.SmbusTransportPacket`, exactly as the old
  ``qemu_i2c_netdev`` transport parses its (unframed) UDP datagrams.
"""

from __future__ import annotations

import collections
import contextlib
import logging
import select
import socket
import struct
import time
from enum import IntEnum

from scapy.compat import raw
from scapy.data import MTU
from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from scapy.utils import linehexdump

from pymctp.layers.mctp import SmbusTransport

from .stream_framing import FrameDecoder, encode_frame

logger = logging.getLogger(__name__)

# Wire protocol version sent/checked in HELLO frames: major=1, minor=0.
PROTO_VERSION = 0x00010000

# Minimum length of a WRITE payload for it to plausibly hold an SMBUS/MCTP
# transport header (dst_addr, command_code, byte_count, src_addr, ... PEC).
_MIN_SMBUS_PAYLOAD_LEN = 4

# Minimum length of a master-mode WRITE payload: the leading address byte
# plus the same minimal SMBUS/MCTP transport header as slave mode.
_MIN_MASTER_WRITE_PAYLOAD_LEN = 1 + _MIN_SMBUS_PAYLOAD_LEN


class I2CStreamMsgType(IntEnum):
    """Frame type tags for the I2C TCP stream transport."""

    WRITE = 0x00
    READ_REQ = 0x01
    READ_RSP = 0x02
    ALERT = 0x03
    HELLO = 0x07


class QemuI2CStreamSocket(SuperSocket):
    """SuperSocket backed by a QEMU I2C "remote target" TCP stream.

    QEMU invocation example (illustrative — the QEMU-side device is being
    built in parallel)::

        -device i2c-target-remote,bus=...,host=127.0.0.1,port=5561,address=0x10

    Corresponding socket creation::

        sock = QemuI2CStreamSocket(host="127.0.0.1", port=5561, id_str="i2c0")
    """

    desc = "read/write to a QEMU I2C remote-target TCP stream"

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        id_str: str = "",
        dump_hex: bool = True,
        dump_packet: bool = False,
        poll_period_ms: int = 10,
        connect_timeout: float = 5.0,
        master: bool = False,
        target_address: int | None = None,
        **kwargs,
    ):
        """Create the socket.

        Args:
            master: When True, speak the peer-as-master wire format (see the
                module docstring) instead of the default slave/target model.
            target_address: The 7-bit SMBus address of the BMC-side target
                that master-mode WRITE frames should be addressed to (used to
                build the leading ``addr_byte`` in :meth:`send`). Required
                when ``master=True``; ignored otherwise.
        """
        self.id_str = id_str
        self.dump_hex = dump_hex
        self.dump_packet = dump_packet
        self._poll_period_ms = poll_period_ms
        self.host = host
        self.port = port
        self.master = master
        self.target_address = target_address

        if self.master and self.target_address is None:
            msg = f"{id_str}: master=True requires a target_address (BMC SMBus address)"
            raise ValueError(msg)

        self._decoder = FrameDecoder()
        self._pending_frames: collections.deque[tuple[int, bytes]] = collections.deque()
        # Bytes queued by send() awaiting the next READ_REQ from the master.
        # Unused in master mode, where send() transmits immediately.
        self._read_buffer = bytearray()

        fd = socket.create_connection((host, port), timeout=connect_timeout)
        fd.settimeout(None)
        assert fd != -1
        self.ins = self.outs = fd

        self._send_hello()

    # ------------------------------------------------------------------
    # High-level send helpers
    # ------------------------------------------------------------------

    def send_write(self, payload: bytes) -> int:
        """Send a WRITE frame directly (mostly useful for tests/tools)."""
        return self._send_raw(I2CStreamMsgType.WRITE, payload)

    def send_read_rsp(self, payload: bytes) -> int:
        """Send a READ_RSP frame with the given bytes."""
        return self._send_raw(I2CStreamMsgType.READ_RSP, payload)

    def send_alert(self, body: bytes = b"") -> int:
        """Send an ALERT frame (SMBus-alert analog) to notify the master."""
        return self._send_raw(I2CStreamMsgType.ALERT, body)

    # ------------------------------------------------------------------
    # SuperSocket overrides
    # ------------------------------------------------------------------

    def send(self, x: Packet) -> int:
        """Send an already SMBus/MCTP-wrapped packet to the QEMU peer.

        In slave mode (default), QEMU is the I2C master's target/slave in
        this topology, so a response cannot be pushed onto the bus; it is
        only delivered once the master issues a READ_REQ (see :meth:`recv`).

        In master mode, QEMU masters the bus on our behalf, so the frame is
        transmitted immediately, address-prefixed with ``target_address``
        (see the module docstring's "Master mode" section).
        """
        sx = raw(x)
        with contextlib.suppress(AttributeError):
            x.sent_time = time.time()

        if self.dump_hex:
            print(f"{self.id_str}>TX> {linehexdump(sx, onlyhex=1, dump=True)}")
        if self.dump_packet:
            print(f"{self.id_str}>TX> {x.summary()}")

        if self.master:
            self._send_master_write(sx)
            return len(sx)

        self._read_buffer.extend(sx)
        return len(sx)

    def recv(self, x: int = MTU) -> Packet | None:
        """Receive from the TCP stream and dispatch the next decoded frame.

        Handles partial reads and multiple frames arriving in a single TCP
        segment the same way as :class:`~pymctp_exerciser_qemu.qemu_i3c_stream.QemuI3CStreamSocket`.

        Returns:
            A parsed :class:`~pymctp.layers.mctp.SmbusTransportPacket` for
            WRITE frames, or ``None`` for control frames (HELLO, READ_REQ,
            ALERT) and errors.
        """
        if not self._pending_frames:
            try:
                raw_bytes = self.ins.recv(x)
            except socket.error:
                return None

            if not raw_bytes:
                logger.info("%s: peer closed the TCP connection", self.id_str)
                return None

            if self.dump_hex:
                print(f"{self.id_str}<RX< {linehexdump(raw_bytes, onlyhex=1, dump=True)}")

            self._pending_frames.extend(self._decoder.feed(raw_bytes))

        if not self._pending_frames:
            return None

        msg_type, payload = self._pending_frames.popleft()
        return self._dispatch(msg_type, payload)

    @staticmethod
    def select(sockets: list[SuperSocket], remain: float | None = None) -> list[SuperSocket]:
        """Custom select that avoids blocking indefinitely on stream sockets."""
        qemu_sockets = [sock for sock in sockets if isinstance(sock, QemuI2CStreamSocket)]
        if not qemu_sockets:
            return []

        ready = [sock for sock in qemu_sockets if sock._pending_frames]
        need_poll = [sock for sock in qemu_sockets if not sock._pending_frames]
        if not need_poll:
            return ready

        # A closed socket's fileno() is -1, which select() rejects with
        # ValueError rather than OSError. That happens routinely during
        # shutdown, when the socket is closed while the sniffer is still
        # polling, so drop closed sockets instead of tearing down the loop.
        need_poll = [sock for sock in need_poll if sock.ins is not None and sock.ins.fileno() >= 0]
        if not need_poll:
            return ready

        socket_fds = [sock.ins for sock in need_poll]
        poll_periods = [x._poll_period_ms for x in need_poll]
        timeout_ms = min(poll_periods + [(remain or 1) * 1000])
        timeout_s = timeout_ms / 1000.0

        try:
            ready_fds, _, _ = select.select(socket_fds, [], [], timeout_s)
        except (select.error, ValueError):
            return ready

        ready.extend(sock for sock in need_poll if sock.ins in ready_fds)
        return ready

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _dispatch(self, msg_type: int, payload: bytes) -> Packet | None:
        """Dispatch a single decoded ``(msg_type, payload)`` frame."""
        if msg_type == I2CStreamMsgType.WRITE:
            if self.master:
                return self._parse_master_write(payload)
            if len(payload) < _MIN_SMBUS_PAYLOAD_LEN:
                logger.warning("%s: WRITE frame too short (%d bytes)", self.id_str, len(payload))
                return None
            pkt = SmbusTransport(payload)
            pkt.time = time.time()
            if pkt and self.dump_packet:
                print(f"{self.id_str}<RX< {pkt.summary()}")
            return pkt

        if msg_type == I2CStreamMsgType.READ_REQ:
            self._handle_read_req(payload)
            return None

        if msg_type == I2CStreamMsgType.READ_RSP:
            logger.warning("%s: unexpected inbound READ_RSP (%d bytes)", self.id_str, len(payload))
            return None

        if msg_type == I2CStreamMsgType.ALERT:
            logger.info("%s: ALERT (%d bytes)", self.id_str, len(payload))
            return None

        if msg_type == I2CStreamMsgType.HELLO:
            self._handle_hello(payload)
            return None

        logger.warning("%s: unknown frame type 0x%02X (%d payload bytes)", self.id_str, msg_type, len(payload))
        return None

    def _handle_read_req(self, payload: bytes) -> None:
        """Answer a READ_REQ with up to ``len`` queued bytes as a READ_RSP.

        QEMU deliberately requests the capacity of its receive buffer rather
        than the exact response length: an I2C slave cannot know how many
        bytes the master intends to read. Returning fewer bytes is therefore
        the normal case for short MCTP responses, not a truncated transfer.
        """
        if len(payload) < 2:
            logger.warning("%s: READ_REQ frame too short (%d bytes)", self.id_str, len(payload))
            return
        (length,) = struct.unpack(">H", payload[:2])

        available = len(self._read_buffer)
        if available < length:
            logger.debug("%s: READ_REQ for %d bytes; returning %d queued bytes", self.id_str, length, available)

        chunk = bytes(self._read_buffer[:length])
        del self._read_buffer[:length]
        self.send_read_rsp(chunk)

    def _parse_master_write(self, payload: bytes) -> Packet | None:
        """Parse a master-mode WRITE frame body: ``[addr_byte][smbus payload...]``.

        ``addr_byte`` is this endpoint's own SMBus address — the BMC mastered
        the bus and wrote to us at it. The whole frame (address byte included)
        is parsed as a :class:`~pymctp.layers.mctp.SmbusTransportPacket`, exactly
        like the ``qemu_i2c_netdev`` transport, so the packet's ``dst_addr``
        field is populated. Stripping the address first would leave ``dst_addr``
        unset (the SMBus command code 0x0F would lead the buffer), and downstream
        consumers that compute ``dst_addr >> 1`` would raise on ``None``.
        """
        if len(payload) < _MIN_MASTER_WRITE_PAYLOAD_LEN:
            logger.warning("%s: master-mode WRITE frame too short (%d bytes)", self.id_str, len(payload))
            return None

        logger.debug(
            "%s: master-mode WRITE addressed to 0x%02X (7-bit 0x%02X)", self.id_str, payload[0], payload[0] >> 1
        )

        pkt = SmbusTransport(payload)
        pkt.time = time.time()
        if pkt and self.dump_packet:
            print(f"{self.id_str}<RX< {pkt.summary()}")
        return pkt

    def _send_master_write(self, data: bytes) -> int:
        """Send a master-mode WRITE frame: ``[addr_byte][smbus payload...]``.

        QEMU masters the (virtual) I2C bus on our behalf, so the frame is
        transmitted immediately — there is no READ_REQ/READ_RSP turn-around
        in master mode.

        ``data`` is ``raw(x)`` of a :class:`SmbusTransportPacket`. Such a packet
        may already carry a physical destination address byte (the conditional
        ``dst_addr`` field, present iff the first byte is not the 0x0F MCTP-over-
        SMBus command code). When present, that byte *is* the on-wire address
        QEMU strips and masters the bus to, and the packet's PEC was computed
        over it — so the frame is sent unchanged, exactly like the proven
        ``qemu_i2c_netdev`` transport. Prefixing our own ``target_address`` here
        would emit a *second* address byte, shifting the 0x0F command code,
        byte-count and PEC by one and causing the BMC to drop the packet.

        Only when the packet has no embedded address (first byte == 0x0F) do we
        prefix the configured BMC ``target_address`` so QEMU has an address to
        master the bus to.
        """
        if data[:1] == b"\x0f":
            addr_byte = (self.target_address << 1) & 0xFF
            data = bytes([addr_byte]) + data
        return self._send_raw(I2CStreamMsgType.WRITE, data)

    def _send_raw(self, msg_type: int, body: bytes = b"") -> int:
        """Encode and transmit a frame to the QEMU peer over the TCP stream."""
        if not self.outs:
            return 0

        frame = encode_frame(int(msg_type), body)
        try:
            self.outs.sendall(frame)
        except Exception as e:
            print(f"Failed sending data: {e}")
            raise
        return len(frame)

    def _send_hello(self) -> int:
        """Send the initial HELLO frame carrying the wire protocol version."""
        return self._send_raw(I2CStreamMsgType.HELLO, struct.pack(">I", PROTO_VERSION))

    def _handle_hello(self, payload: bytes) -> None:
        """Validate a peer HELLO frame's protocol version, logging a warning on mismatch."""
        if len(payload) < 4:
            logger.warning("%s: HELLO frame too short (%d bytes)", self.id_str, len(payload))
            return
        (peer_version,) = struct.unpack(">I", payload[:4])
        if peer_version != PROTO_VERSION:
            logger.warning(
                "%s: HELLO protocol version mismatch: local=0x%08X peer=0x%08X",
                self.id_str,
                PROTO_VERSION,
                peer_version,
            )
        else:
            logger.info("%s: HELLO version check OK (0x%08X)", self.id_str, peer_version)
