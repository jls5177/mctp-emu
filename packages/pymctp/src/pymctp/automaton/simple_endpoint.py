# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import logging
import threading
import time
from collections.abc import Callable
from typing import cast

from scapy.ansmachine import AnsweringMachine
from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.plist import PacketList, _PacketIterable  # imported for type hinting on overloaded methods
from scapy.sendrecv import AsyncSniffer
from scapy.supersocket import SuperSocket

from ..layers import TransportHdrPacket
from ..layers.interfaces import AnyPacketType
from ..layers.mctp.control import ControlHdrPacket
from ..layers.mctp.types import EndpointContext, ICanReply
from .sessions import EndpointSession

logger = logging.getLogger(__name__)

#: Backoff between attempts to re-assert a sniffer stop (see stop_sniffer).
_STOP_RETRY_INTERVAL_S = 0.005

#: How long stop_sniffer waits for a sniffer that has not started yet before
#: concluding it never will.
_STOP_STARTUP_GRACE_S = 0.25


class SimpleEndpointAM(AnsweringMachine):
    """AnsweringMachine which emulates the basic behavior of a real MCTP endpoint.

    Usage:
        >>> import threading
        >>> from pymctp.automaton import SimpleEndpointAM
        >>> from pymctp.layers.mctp import *
        >>> from pymctp.exerciser import QemuI2CNetDevSocket
        >>> context = EndpointContext(physical_address=Smbus7bitAddress(0x20 >> 1), \
                              supported_msg_types=[MsgTypes.CTRL, MsgTypes.PLDM])
        >>> sock = QemuI2CNetDevSocket(iface="127.0.0.1", in_port=5559, out_port=5558)
        >>> session = EndpointSession(context=context, socket=sock)
        >>> am = SimpleEndpointAM(socket=sock, context=context, session=session)
        >>> sim = threading.Thread(target=am, kwargs={'count': 10, 'timeout':5*60})
        >>> sim.start()
        >>> rsp = session.sndrcv_control_msg(GetEndpointID(), 0x15, Smbus7bitAddress(0x20 >> 1))
        >>> rsp.show2() if rsp else print(f"No response received, timeout?")
    """

    context: EndpointContext
    socket: SuperSocket

    function_name = "simple_bus_owner"
    # removed the "iface", "promisc", "count", and "type" options as they are ethernet specific
    sniff_options_list = [
        "store",
        "opened_socket",
        "count",
        "filter",
        "prn",
        "stop_filter",
        "timeout",  # added timeout to stop sniffer after designated time period
    ]
    # removed the "socket" option to allow it to be passed to "parse_options"
    send_options_list = ["iface", "inter", "loop", "verbose"]

    #: Delay in seconds before writing a reply. Zero by default: a responder
    #: that dawdles makes a requester time out and retry, and a retry racing an
    #: in-flight fragmented reply is what corrupts a reassembled message.
    response_delay_s: float = 0.0

    #: Gap in seconds between the packets of one fragmented message.
    #:
    #: Deliberately non-zero. The QEMU transports we talk to hand one frame at
    #: a time to the emulated controller, so packets written back to back are
    #: accepted on the socket and then dropped before the requester ever sees
    #: them -- every multi-packet reply silently disappears while single-packet
    #: replies keep working. There is no flow control on this link to wait for,
    #: so the gap is the only means of pacing. Lower it only against a
    #: transport you have shown can keep up.
    inter_packet_delay_s: float = 0.005

    def __init__(
        self,
        session: EndpointSession | None = None,
        socket: SuperSocket | None = None,
        context: EndpointContext | None = None,
        timeout: float | None = None,
        downstream_endpoints: map | None = None,
        response_delay_s: float | None = None,
        inter_packet_delay_s: float | None = None,
        **kwargs,
    ):
        """
        Overloaded the AnsweringMachine.__init__() to add type hints for class specific parameters.

        :param session: Endpoint Session which oversees AM interactions
        :param socket: Socket to send and receive packets
        :param context: MCTP Endpoint content to store runtime state
        :param timeout: Specifies the sniffing timeout (seconds)
        :param kwargs: Any additional sniff/send options available in Scapy AnsweringMachine
        """
        self.context = context or EndpointContext()
        self.socket = socket
        self.session = session
        if self.session:
            self.session.am = self
        self.downstream_endpoints = downstream_endpoints or {}
        if response_delay_s is not None:
            self.response_delay_s = response_delay_s
        if inter_packet_delay_s is not None:
            self.inter_packet_delay_s = inter_packet_delay_s

        self.sniffer: AsyncSniffer | None = None
        self._sniff_ready = threading.Event()
        self._sniff_started = threading.Event()
        self._stop_requested = threading.Event()
        # A multi-packet message must reach the wire as one uninterrupted run.
        # MCTP reassembly is keyed on source, destination and tag, so if a
        # second response interleaves its packets with an in-flight one the
        # receiver splices both into a single message that is complete and
        # correctly sequenced but has the wrong contents.
        self._send_lock = threading.Lock()
        super().__init__(timeout=timeout, **kwargs)

    def sniff(self) -> PacketList | None:
        """
        Overloaded the AnsweringMachine.sniff() method to always capture the sniffer in an instance attribute
        """
        self.sniffer = AsyncSniffer()
        self._sniff_ready.clear()
        self._sniff_started.clear()
        if self._stop_requested.is_set():
            # stop_sniffer() beat this thread to the punch; never start.
            return None
        opts = dict(self.optsniff)
        opts.setdefault("started_callback", self._sniff_started_callback)
        try:
            self.sniffer._run(**opts)  # noqa: SLF001
        finally:
            self._sniff_ready.clear()
            self._sniff_started.clear()
            self._on_sniff_stopped()
        return cast(PacketList, self.sniffer.results)

    def _sniff_started_callback(self) -> None:
        """Sniffer startup callback: records readiness, then runs the subclass hook.

        Two distinct signals are published because they answer different
        questions:

        ``_sniff_ready``
            scapy has installed its ``stop_cb``; :meth:`stop_sniffer` may now
            call ``stop()`` without it raising.
        ``_sniff_started``
            the behaviors' ``on_start`` hooks have run, so the endpoint is
            fully up.  This is what :meth:`wait_until_started` reports, so a
            caller that starts an endpoint and immediately sends a request is
            not racing its own initiator behaviors.

        This deliberately does *not* stop the sniffer when a stop is already
        pending: scapy re-arms ``continue_sniff = True`` immediately after
        invoking this callback, so a stop issued here would be undone.
        :meth:`stop_sniffer` re-asserts the stop instead.
        """
        self._sniff_ready.set()
        if self._stop_requested.is_set():
            # Shutting down before we ever really started: skip the behaviors'
            # on_start so they are not brought up just to be torn down.
            return
        try:
            self._on_sniff_started()
        finally:
            self._sniff_started.set()

    def _on_sniff_started(self) -> None:
        """Hook invoked once the sniffer is live and the socket can be used."""

    def _on_sniff_stopped(self) -> None:
        """Hook invoked after the sniff loop exits (normally or via exception)."""

    def parse_options(
        self,
        session: EndpointSession | None = None,
        socket: SuperSocket | None = None,
        timeout: float | None = None,
    ) -> None:
        """
        Sets up any additional sniffing/sending options that are not part of the
        standard AnsweringMachine.

        :param session: Endpoint Session which oversees AM interactions
        :param socket: Socket to send and receive packets
        :param timeout: Specifies the sniffing timeout (seconds)
        """
        if self.session:
            self.sniff_options["session"] = self.session
        self.sniff_options["timeout"] = timeout
        self.sniff_options["opened_socket"] = self.socket

    def is_request(self, req: Packet) -> int:
        """
        Called within AnsweringMachine.reply() to determine if the received
        packet requires a response.
        :param req: The received packet
        :return: 0 if no reply is necessary and 1 if a reply is required.
        """
        if isinstance(req, ICanReply):
            return req.is_request()
        return req.haslayer(ControlHdrPacket) and req.getlayer(ControlHdrPacket).rq == 1

    def get_context_for_endpoint(self, req: Packet):
        if not req.haslayer(TransportHdrPacket):
            return self.context
        hdrPkt = req.getlayer(TransportHdrPacket)
        dst_eid = hdrPkt.dst
        if not dst_eid or self.context.eid == dst_eid or not self.downstream_endpoints:
            return self.context
        return self.downstream_endpoints.get(dst_eid, None)

    def make_reply(self, req: Packet | ICanReply) -> _PacketIterable:
        """
        Creates a reply to the incoming request (pre-confirmed by is_request())

        :param req: The received request packet
        :return: The fully formed response packet, or None (if no response can be generated)
        """
        rsp = None
        if isinstance(req, ICanReply):
            ctx = self.get_context_for_endpoint(req)
            if ctx:
                rsp = req.make_reply(ctx)
        # TODO: add any custom responses here
        return rsp

    def send_reply(self, reply: _PacketIterable, send_function: Callable[..., None] | None = None) -> None:
        """
        Sends the reply packets (sequentially) on the socket or using the "send_function" (if specified).

        The packets of one message are written under a lock, so a second
        response cannot get its packets into the middle of an in-flight one.
        MCTP reassembly is keyed on source EID, destination EID and tag, so
        interleaved packets are spliced by the receiver into a single message
        that reassembles cleanly, with consecutive sequence numbers, but
        carries bytes from both messages. That surfaces far from its cause --
        as a bad PLDM FRU table checksum, for instance -- so emission is kept
        atomic rather than left to chance.

        Packets are paced by ``inter_packet_delay_s``, because the emulated
        controllers on the other end take one frame at a time and drop the
        rest of a burst.

        @note This method does not wait for a response before sending the next reply

        :param reply: The fully formed packet(s) to send
        :param send_function: An optional callable method to invoke to send each packet (instead of the socket)
        """
        packets = list(reply)
        with self._send_lock:
            if self.response_delay_s:
                time.sleep(self.response_delay_s)
            for index, p in enumerate(packets):
                if index and self.inter_packet_delay_s:
                    time.sleep(self.inter_packet_delay_s)
                if self.session is not None:
                    self.session.observe_tx_packet(p)
                if send_function is not None:
                    send_function(p)
                elif self.socket:
                    self.socket.send(p)
            if self.session is not None:
                self.session.observe_tx_message(packets)

    def print_reply(self, req: AnyPacketType, reply: AnyPacketType) -> None:
        if isinstance(reply, PacketList):
            print("")
            print(f"{req.summary()} ==> {[res.summary() for res in reply]}")
        else:
            print(f"{req.summary()} ==> {reply.summary()}")

    @property
    def sniffer_running(self):
        return self.sniffer is not None and self.sniffer.running

    def wait_until_started(self, timeout: float = 5.0) -> bool:
        """Block until the sniffer is live (or *timeout* elapses)."""
        return self._sniff_started.wait(timeout)

    def stop_sniffer(self, join: bool = False, timeout: float = 5.0) -> PacketList | None:
        """Stop the sniff loop, tolerating a sniffer that has not started yet.

        Shutdown races endpoint startup in several ways, all handled here:

        * The endpoint thread has not reached the sniff loop — the request is
          latched in ``_stop_requested`` and :meth:`sniff` returns without ever
          starting.
        * ``AsyncSniffer`` sets ``running`` at the top of ``_run`` but installs
          the ``stop_cb`` that ``stop()`` needs a few statements later, so an
          early ``stop()`` raises ``Scapy_Exception``.
        * scapy assigns ``continue_sniff = True`` *after* invoking
          ``started_callback``, so a stop landing in that window is silently
          undone.

        The last two are why this re-asserts the stop until it actually sticks
        rather than calling ``stop()`` once.  Without it an endpoint torn down
        immediately after being started keeps sniffing until its own timeout.
        """
        self._stop_requested.set()
        if self.sniffer is None:
            # sniff() has not run: the latched request stops it before it starts.
            return None

        deadline = time.monotonic() + max(timeout, 0.0)
        grace_deadline = time.monotonic() + _STOP_STARTUP_GRACE_S
        result: PacketList | None = None
        observed_running = False

        while True:
            sniffer = self.sniffer
            if sniffer is not None and sniffer.running:
                observed_running = True
                self._sniff_ready.wait(max(deadline - time.monotonic(), 0.0))
                try:
                    result = sniffer.stop(join=join)
                except Scapy_Exception:
                    # stop_cb is not installed yet; retry.
                    pass
            elif observed_running or time.monotonic() >= grace_deadline:
                # The loop has genuinely exited, or was never going to start.
                return result

            now = time.monotonic()
            if now >= deadline:
                logger.warning("Sniffer kept running %.1fs after stop() was requested", timeout)
                return result
            time.sleep(_STOP_RETRY_INTERVAL_S)
