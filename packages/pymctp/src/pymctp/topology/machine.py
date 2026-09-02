# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Runtime orchestration for machine topology specs."""

from __future__ import annotations

import logging
import signal
import time
from collections.abc import Callable
from typing import Any

from pymctp.automaton.manager import EndpointManager
from pymctp.automaton.role_endpoint import RoleBasedEndpointAM
from pymctp.automaton.transcript import PacketTraceEvent

from pymctp.topology.types import EidMap, MachineSpec

logger = logging.getLogger(__name__)


class MachineBuildError(RuntimeError):
    """Raised when an endpoint in a machine topology cannot be created.

    Carries the device and transport that failed so the message is actionable,
    rather than surfacing the deserialization error the socket failure gets
    wrapped in.
    """

    def __init__(self, device_name: str, transport: dict[str, Any], cause: BaseException) -> None:
        self.device_name = device_name
        self.transport = dict(transport)
        self.cause = cause
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        transport_type = self.transport.get("type", "?")
        host = self.transport.get("host")
        port = self.transport.get("port")
        where = f"{host}:{port}" if host is not None and port is not None else "its transport"

        root = _root_cause(self.cause)
        lines = [f"Could not bring up endpoint {self.device_name!r} ({transport_type}) on {where}: {root}"]
        if isinstance(root, ConnectionRefusedError):
            lines.append(
                f"Nothing is listening on {where}. These transports connect to QEMU as a TCP client, "
                "so QEMU must already be running with the matching -device ...,server=on options. "
                "Use 'pymctp machine show <machine>' or '--print-spec' to see every port the topology expects."
            )
        return "\n".join(lines)


def _root_cause(exc: BaseException) -> BaseException:
    """Return the deepest chained cause, which is where the real failure is."""
    seen: set[int] = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        nxt = current.__cause__ or current.__context__
        if nxt is None:
            return current
        current = nxt
    return exc


class BusOwnerHandle:
    """Small defensive facade around an endpoint's bus-owner behavior."""

    def __init__(self, endpoint: EndpointManager, behavior: Any) -> None:
        self.endpoint = endpoint
        self.behavior = behavior

    @property
    def routing_table(self) -> Any:
        """Return the behavior routing table when present, else the endpoint context table."""

        if hasattr(self.behavior, "routing_table"):
            return getattr(self.behavior, "routing_table")
        return getattr(self.endpoint.context, "routing_table", None)

    @property
    def report(self) -> Any:
        """Return the behavior's last discovery report when the behavior exposes one."""

        return getattr(self.behavior, "report", None)

    def rediscover(self, timeout_s: float | None = None) -> Any:
        """Run bus-owner rediscovery if the behavior implements it."""

        rediscover = getattr(self.behavior, "rediscover", None)
        if not callable(rediscover):
            msg = "Attached bus-owner behavior does not expose rediscover()"
            raise AttributeError(msg)
        return rediscover(timeout_s=timeout_s)


class Machine:
    """Build, start, stop, and summarize a topology of MCTP endpoints."""

    def __init__(
        self,
        spec: MachineSpec,
        *,
        eids: EidMap | dict[str, int] | None = None,
        start: bool = False,
        verbose: bool = False,
        observer: Callable[[PacketTraceEvent], None] | None = None,
    ) -> None:
        self.spec = spec.with_eids(eids) if eids is not None else spec
        self.verbose = verbose
        self.observer = observer
        self.endpoints: dict[str, EndpointManager] = {}
        if start:
            self.start()

    def build(self) -> None:
        """Create endpoint managers without starting their sniffer threads.

        Endpoint transports connect eagerly, so a device whose peer is not
        listening fails here.  Anything already built is torn down before the
        error propagates, so a failed build never leaks open sockets.
        """

        if self.endpoints:
            return
        self.spec.validate()
        for device in self.spec.devices:
            if not device.enabled:
                continue
            config = device.to_endpoint_config(self.spec, self.spec.eids)
            try:
                manager_kwargs: dict[str, Any] = {
                    "start_thread": False,
                    "verbose": self.verbose,
                }
                if self.observer is not None:
                    manager_kwargs["observer"] = self.observer
                self.endpoints[device.name] = EndpointManager.from_config(config, **manager_kwargs)
            except Exception as exc:
                self.stop()
                self.endpoints.clear()
                raise MachineBuildError(device.name, config.get("config", {}), exc) from exc

    def start(self, timeout: float = 5.0) -> Machine:
        """Build and start all endpoint threads. Safe to call repeatedly.

        Returns only once every endpoint's sniffer is actually live, so callers
        may send immediately afterwards and :meth:`stop` always acts on a
        fully-started endpoint rather than racing its startup.
        """
        if not self.endpoints:
            self.build()
        for endpoint in self.endpoints.values():
            thread = endpoint.thread
            if not thread.is_alive() and getattr(thread, "ident", None) is None:
                thread.start()
        self.wait_until_started(timeout)
        return self

    def wait_until_started(self, timeout: float = 5.0) -> bool:
        """Wait for every endpoint's sniffer to come up; True when all are live."""
        deadline = time.monotonic() + max(timeout, 0.0)
        all_started = True
        for name, endpoint in self.endpoints.items():
            wait_fn = getattr(endpoint.am, "wait_until_started", None)
            if wait_fn is None:
                continue
            if not wait_fn(max(deadline - time.monotonic(), 0.0)):
                all_started = False
                logger.warning("Endpoint %s did not start within %.1fs", name, timeout)
        return all_started

    def stop(self, join: bool = True, timeout: float = 5.0) -> None:
        """Stop sniffers and close sockets in reverse build order, never raising.

        The endpoint's own thread is joined *between* stopping the sniffer and
        closing its socket.  ``AsyncSniffer.stop()`` only sets a stop event —
        its ``join()`` is a no-op here because ``SimpleEndpointAM.sniff()`` runs
        the sniff loop directly on the endpoint thread rather than through
        ``AsyncSniffer.start()``.  Closing the socket without waiting therefore
        pulls the file descriptor out from under a live ``select()``.
        """
        for endpoint in reversed(list(self.endpoints.values())):
            try:
                endpoint.stop_sniffer(join=join)
            except Exception:
                logger.exception("Failed to stop sniffer for endpoint %s", endpoint.name)
            if join:
                self._join_endpoint_thread(endpoint, timeout)
            self._close_endpoint_socket(endpoint)

    @staticmethod
    def _join_endpoint_thread(endpoint: EndpointManager, timeout: float) -> None:
        thread = getattr(endpoint, "thread", None)
        if thread is None or not thread.is_alive():
            return
        try:
            thread.join(timeout)
        except Exception:
            logger.exception("Failed to join thread for endpoint %s", endpoint.name)
        if thread.is_alive():
            logger.warning("Endpoint %s did not stop within %.1fs", endpoint.name, timeout)

    def join(self, timeout: float | None = None) -> None:
        """Wait for all endpoint threads; Ctrl-C stops everything and prints a summary."""

        try:
            for endpoint in self.endpoints.values():
                endpoint.thread.join(timeout)
        except KeyboardInterrupt:
            self.stop()
            print(self.summary())
            raise

    def __getitem__(self, name: str) -> EndpointManager:
        return self.endpoints[name]

    def __getattr__(self, name: str) -> EndpointManager:
        try:
            endpoints = object.__getattribute__(self, "endpoints")
        except AttributeError as exc:
            raise AttributeError(name) from exc
        if name in endpoints:
            return endpoints[name]
        raise AttributeError(name)

    def __enter__(self) -> Machine:
        return self.start()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.stop()

    @property
    def bus_owner(self) -> BusOwnerHandle | None:
        """Return a handle to the first endpoint with a behavior named ``bus-owner``."""

        for endpoint in self.endpoints.values():
            am = endpoint.am
            if not isinstance(am, RoleBasedEndpointAM):
                continue
            behavior = am.get_behavior("bus-owner")
            if behavior is not None:
                return BusOwnerHandle(endpoint, behavior)
        return None

    def summary(self) -> str:
        """Return per-endpoint packet counts."""

        lines = []
        for endpoint in self.endpoints.values():
            sniffer = getattr(endpoint.am, "sniffer", None)
            count = getattr(sniffer, "count", 0) if sniffer is not None else 0
            socket = getattr(endpoint, "socket", None)
            name = getattr(socket, "id_str", None) or endpoint.name
            lines.append(f"{name} processed {count} packets")
        return "\n".join(lines)

    def install_signal_handler(self) -> None:
        """Install a Ctrl-C handler that stops endpoints and prints a summary."""

        def _handler(signum: int, frame: object) -> None:
            self.stop()
            print(self.summary())
            raise KeyboardInterrupt

        signal.signal(signal.SIGINT, _handler)

    def _close_endpoint_socket(self, endpoint: EndpointManager) -> None:
        config = getattr(endpoint.config, "config", None)
        close_socket = getattr(config, "close_socket", None)
        if callable(close_socket):
            try:
                close_socket()
                return
            except Exception:
                logger.exception("Failed to close socket config for endpoint %s", endpoint.name)
        socket = getattr(endpoint, "socket", None)
        close = getattr(socket, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                logger.exception("Failed to close socket for endpoint %s", endpoint.name)
