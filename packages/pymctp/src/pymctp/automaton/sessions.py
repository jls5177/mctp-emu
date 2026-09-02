# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, NamedTuple

from scapy.compat import raw
from scapy.config import conf
from scapy.packet import Packet, Raw
from scapy.plist import PacketList
from scapy.sendrecv import sndrcv
from scapy.sessions import DefaultSession
from scapy.supersocket import SuperSocket
from scapy.utils import hexdump, linehexdump

from ..layers import SmbusTransportPacket, UartTransport, UartTransportPacket
from ..layers.mctp import (
    AnyPhysicalAddress,
    EndpointContext,
    Smbus7bitAddress,
    SmbusTransport,
    TransportHdr,
    TransportHdrPacket,
)
from ..layers.mctp.control import ControlHdr, ControlHdrPacket, IControlMsgPacket
from ..layers.mctp.types import AnyPacketType, MsgTypes
from .reassembly import MctpReassemblyManager, ReassemblyUpdateKind
from .transcript import (
    PacketTraceEvent,
    TraceDirection,
    TraceEventKind,
    logical_transport_packet,
    packet_trace_event,
)

if TYPE_CHECKING:
    from scapy.ansmachine import AnsweringMachine
    from scapy.plist import PacketList


def _is_tty_serial_socket(sock: SuperSocket) -> bool:
    """Check if socket is a TTYSerialSocket without requiring the package at import time."""
    try:
        from ..exerciser import TTYSerialSocket
    except ImportError:
        return False
    return isinstance(sock, TTYSerialSocket)


def _is_i3c_netdev_socket(sock: SuperSocket) -> bool:
    """Check if socket is a QemuI3CNetDevSocket without requiring the package at import time."""
    try:
        from ..exerciser import QemuI3CNetDevSocket
    except ImportError:
        return False
    return isinstance(sock, QemuI3CNetDevSocket)


class HandlerResponse(NamedTuple):
    stop_processing: bool
    reply: AnyPacketType


class EndpointSession(DefaultSession):
    """Manages sending and receiving MCTP messages on the specified socket for a single endpoint."""

    def __init__(
        self,
        *args,
        context: EndpointContext,
        socket: SuperSocket,
        endpoint_name: str = "",
        observer: Callable[[PacketTraceEvent], None] | None = None,
        **kwargs,
    ):
        """
        Overloaded the DefaultSession.__init__() to add type hints for class specific parameters.
        :param args: Arguments to pass to DefaultSession
        :param context: MCTP Endpoint content to store runtime state
        :param socket: Socket to send and receive packets
        :param kwargs: Any additional arguments available in Scapy DefaultSession
        """
        super().__init__(*args, **kwargs)
        self.context = context
        self.socket = socket
        self.endpoint_name = endpoint_name
        self.observer = observer
        self.reassembly = MctpReassemblyManager(
            max_contexts=context.max_reassembly_contexts,
            timeout_s=context.reassembly_timeout_s,
        )
        self.pending_rqs: list[tuple[Packet, Callable[[Packet], None]]] = []
        self._next_tag_number = 0
        self._next_instance_id = 0
        self._responder_lock = threading.Lock()

        # Not allowed during init due to the AnsweringMachine needing the session to initialize properly.
        # Instead, the AnsweringMachine will register itself during initialization.
        self.am: AnsweringMachine | None = None
        self.default_handlers: dict[type, Callable[[Packet, EndpointContext], HandlerResponse | None]] = {}

    def _observe(
        self,
        packet: Packet | None,
        *,
        direction: TraceDirection,
        kind: TraceEventKind,
        detail: str | None = None,
    ) -> None:
        if self.observer is None:
            return
        self.observer(
            packet_trace_event(
                packet,
                endpoint=self.endpoint_name,
                direction=direction,
                kind=kind,
                detail=detail,
            )
        )

    def observe_tx_packet(self, packet: Packet) -> None:
        self._observe(packet, direction=TraceDirection.TX, kind=TraceEventKind.PACKET)

    def observe_tx_message(self, packets: list[Packet]) -> None:
        logical = logical_transport_packet(packets)
        if logical is not None:
            self._observe(logical, direction=TraceDirection.TX, kind=TraceEventKind.MESSAGE)

    @staticmethod
    def _replace_transport(original: Packet, transport: TransportHdrPacket) -> Packet:
        smbus = original.getlayer(SmbusTransportPacket)
        if smbus is not None:
            return smbus.copy(transport)
        uart = original.getlayer(UartTransportPacket)
        if uart is not None:
            return uart.copy(transport)
        return transport

    def register_handler(self, layer_cls: type, handler: Callable[[Packet, EndpointContext], HandlerResponse | None]):
        """
        Registers the specified handler to allow the handler to be invoked anytime a msg is received that
        contains the specified layer class.
        :param layer_cls: Class that needs to be present to trigger handler (should be the lowest layer possible)
        :param handler: Callback handler when matching msg is received
        """
        self.default_handlers[layer_cls] = handler

    @property
    def next_tag_number(self) -> int:
        """
        Generates a tag number that automatically increments (and rolls over) on each access
        :return: the next tag number generated
        """
        next_tag = self._next_tag_number
        self._next_tag_number = (next_tag + 1) % 8
        return next_tag

    @property
    def next_instance_id(self) -> int:
        """
        Generates an instance id that automatically increments (and rolls over) on each access

        :return: the next instance id number generated
        """
        next_id = self._next_instance_id
        self._next_instance_id = (next_id + 1) % 32
        return next_id

    def on_packet_received(self, rq_pkt: Packet | None) -> None:
        """
        Will be called by sniff() for each received packet (that passes the filters).

        :param rq_pkt: The received packet
        :return: None
        """
        if not rq_pkt or not rq_pkt.haslayer(TransportHdrPacket):
            return

        self._observe(rq_pkt, direction=TraceDirection.RX, kind=TraceEventKind.PACKET)
        transport: TransportHdrPacket = rq_pkt.getlayer(TransportHdrPacket)
        logical_transport: TransportHdrPacket | None = None
        for update in self.reassembly.feed(transport):
            if update.kind in (ReassemblyUpdateKind.SINGLE, ReassemblyUpdateKind.COMPLETED):
                logical_transport = update.packet
                continue
            kind = {
                ReassemblyUpdateKind.STARTED: TraceEventKind.REASSEMBLY_STARTED,
                ReassemblyUpdateKind.CONTINUED: TraceEventKind.REASSEMBLY_CONTINUED,
                ReassemblyUpdateKind.REJECTED: TraceEventKind.REASSEMBLY_REJECTED,
                ReassemblyUpdateKind.EXPIRED: TraceEventKind.REASSEMBLY_EXPIRED,
            }[update.kind]
            detail = f"{update.key}: {update.detail}" if update.detail else str(update.key)
            self._observe(rq_pkt, direction=TraceDirection.RX, kind=kind, detail=detail)

        if logical_transport is None:
            return

        rq_pkt = self._replace_transport(rq_pkt, logical_transport)
        mctp_pkt_hdr = logical_transport
        self._observe(rq_pkt, direction=TraceDirection.RX, kind=TraceEventKind.MESSAGE)
        is_request = bool(self.am.is_request(rq_pkt))

        # MCTP echo is handled here because it has no upper-layer behavior.
        if mctp_pkt_hdr.haslayer(Raw) and mctp_pkt_hdr.msg_type == 0x7F:
            response_pkts = mctp_pkt_hdr.build_reply(self.context, bytes(mctp_pkt_hdr.payload))
            smbus = rq_pkt.getlayer(SmbusTransportPacket)
            uart = rq_pkt.getlayer(UartTransportPacket)
            if smbus is not None:
                response_pkts = smbus.build_reply(self.context, response_pkts)
            elif uart is not None:
                response_pkts = uart.build_reply(self.context, response_pkts)
            self.am.send_reply(response_pkts)
            return

        # Lock the session to prevent another thread trying to send a request on the bus before we finish replying
        with self._responder_lock:
            plist = self.pending_rqs

            # 1) look for responses to pending requests
            for i, pending_rq in enumerate(plist):
                sentpkt, callback = pending_rq
                if not rq_pkt.answers(sentpkt):
                    continue
                del self.pending_rqs[i]
                callback(rq_pkt)
                return

            # 2) Check if we have a handler registered for this type of packet
            stop_processing = False
            response_pkts: PacketList = []
            for cls, handler in self.default_handlers.items():
                if cls in rq_pkt or mctp_pkt_hdr.haslayer(cls.__name__):
                    resp: HandlerResponse = handler(rq_pkt, self.context)
                    if not resp:
                        resp = HandlerResponse(False, None)
                    stop_processing = resp.stop_processing
                    if resp.reply:
                        if isinstance(resp.reply, PacketList):
                            response_pkts += resp.reply
                        else:
                            response_pkts.append(resp.reply)
                        if stop_processing:
                            break
                    elif stop_processing:
                        return

            # 3) if a request, use the default reply methods to generate response
            if is_request and not stop_processing:
                reply = self.am.make_reply(rq_pkt)
                if reply:
                    response_pkts += reply

            # send any queued replies
            if response_pkts:
                self.am.send_reply(response_pkts)

    def sndrcv_control_msg(
        self,
        pkt: Packet,
        dst_eid: int,
        *,
        dst_phy_addr: AnyPhysicalAddress = None,
        instance_id: int | None = None,
        timeout_s: float | None = None,
        threaded: bool = False,
    ) -> Packet | None:
        """
        Sends the specified MCTP Control Payload to the destination and waits for a
        response. This method will detect if the ControlHdrPacket, TransportHdrPacket,
        and the SmbusTransportPacket are present and add them if missing.

        Example:

            >>> rsp = sndrcv_control_msg(GetEndpointID(), 0x15, Smbus7bitAddress(0x20 >> 1))

        :param pkt: The MCTP Control Msg packet to send
        :param dst_eid: The destination endpoint id
        :param dst_phy_addr: The physical address of the destination (endpoint or bridge/next hop)
        :param instance_id: The instance to differentiate different MCTP Control requests (autogenerated if not present)
        :param timeout_s: Max time to wait for a response (in seconds)
        :param threaded: Set to `True` if
        :return: the received packet or None
        """
        if not isinstance(pkt, IControlMsgPacket):
            msg = "Packet is malformed, does not implement the IControlMsgPacket protocol"
            raise TypeError(msg)
        cmd_code = pkt.cmd_code

        if not pkt.haslayer(ControlHdrPacket):
            pkt = (
                ControlHdr(
                    rq=True,
                    cmd_code=cmd_code,
                    instance_id=(instance_id or self.next_instance_id),
                )
                / pkt
            )
        return self.sndrcv_mctp_msg(
            pkt=pkt, dst_eid=dst_eid, dst_phy_addr=dst_phy_addr, timeout_s=timeout_s, threaded=threaded
        )

    def sndrcv_mctp_msg(
        self,
        pkt: Packet,
        dst_eid: int,
        *,
        dst_phy_addr: AnyPhysicalAddress = None,
        msg_type: MsgTypes = MsgTypes.CTRL,
        msg_tag: int | None = None,
        timeout_s: float | None = None,
        threaded: bool = False,
    ) -> Packet | None:
        # TODO: handle packet fragments
        pkt = (
            TransportHdr(
                src=self.context.eid,
                dst=dst_eid,
                som=1,
                eom=1,
                pkt_seq=0,
                to=1,
                tag=msg_tag or self.next_tag_number,
                msg_type=msg_type,
            )
            / pkt
        )

        src_phy_addr = self.context.physical_address
        if isinstance(dst_phy_addr, Smbus7bitAddress) and isinstance(src_phy_addr, Smbus7bitAddress):
            pkt = SmbusTransport(dst_addr=dst_phy_addr, src_addr=src_phy_addr, load=pkt)
        elif _is_tty_serial_socket(self.socket):
            pkt = UartTransport(load=pkt)
        elif _is_i3c_netdev_socket(self.socket):
            # I3C is point-to-point: send the raw MCTP transport packet with no
            # physical addressing wrapper. The address is dynamically assigned
            # via ENTDAA and cannot be known ahead of time.
            pass
        else:
            msg = f"Only Smbus7bitAddress are supported: {type(dst_phy_addr)}"
            raise TypeError(msg)

        # hexdump(pkt)
        # if drop_pec:
        #     data = raw(pkt)
        #     pkt = Raw(data[:-1])

        if threaded or (self.am and hasattr(self.am, "sniffer") and self.am.sniffer.running):
            return self.sr1threaded(pkt=pkt, timeout_s=timeout_s)
        return self.sr1(pkt=pkt, timeout_s=timeout_s)

    def sr1(self, pkt: Packet, timeout_s: float | None = None) -> Packet | None:
        """
        Sends and receives one packet on the socket. This method will stall
        the main thread until a response is received or the timeout is reached.

        :param pkt: The packet to send
        :param timeout_s: Max time to wait for a response (in seconds)
        :return: the received packet or None
        """
        with self._responder_lock:
            self.observe_tx_packet(pkt)
            self.observe_tx_message([pkt])
            a, b = sndrcv(self.socket, pkt, timeout=int(timeout_s) if timeout_s else None, session=self)
            if len(a) > 0:
                return a[0][1]
        return None

    def sr1threaded(self, pkt: Packet, timeout_s: float | None = None) -> Packet | None:
        """
        Sends and receives on packet on the socket. This method will queue the response
        handler (callback) and start a timer to handle no response. This method is meant
        to be used when an AnsweringMachine is already running in the session (as there
        can only be one service bound to the socket at a time). The AnsweringMachine will
        invoke the "on_packet_received()" method when a response is received, which will
        check if the response is for a pending request.

        :param pkt: The packet to send
        :param timeout_s: Max time to wait for a response (in seconds)
        :return: The received packet or None
        """
        completed = threading.Event()
        rsp: list[Packet] = []

        # print(f"Sending request using threading")

        def callback(pkt: Packet):
            # print(f"response received, triggering callback")
            rsp.append(pkt)
            completed.set()

        # queue event
        item = (pkt, callback)
        self.pending_rqs.append(item)

        # send event
        with self._responder_lock:
            self.observe_tx_packet(pkt)
            self.observe_tx_message([pkt])
            self.socket.send(pkt)

        # wait for completion
        timed_out = completed.wait(timeout=timeout_s)
        if not timed_out or not rsp:
            # remove the item from the list (ignoring any errors)
            try:
                with self._responder_lock:
                    self.pending_rqs.remove(item)
            finally:
                pass
            return None
        return rsp[0]
