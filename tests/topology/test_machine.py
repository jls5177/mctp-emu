# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

from typing import Any

import pytest

from pymctp.automaton.behaviors.base import Behavior
from pymctp.automaton.role_endpoint import RoleBasedEndpointAM
from pymctp.layers.mctp.types import EndpointContext
from pymctp.topology.machine import Machine
from pymctp.topology.types import DeviceSpec, MachineSpec


class FakeThread:
    def __init__(self) -> None:
        self.ident: int | None = None
        self.started = 0
        self.joined: list[float | None] = []
        self._alive = False

    def is_alive(self) -> bool:
        return self._alive

    def start(self) -> None:
        self.started += 1
        self.ident = 1
        self._alive = True

    def join(self, timeout: float | None = None) -> None:
        self.joined.append(timeout)
        self._alive = False


class FakeSniffer:
    def __init__(self, count: int) -> None:
        self.count = count
        self.running = True


class FakeSocket:
    def __init__(self, name: str) -> None:
        self.id_str = name
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeConfigObject:
    def __init__(self) -> None:
        self.closed = False

    def close_socket(self) -> None:
        self.closed = True


class FakeEndpoint:
    def __init__(self, name: str, count: int = 0, am: Any | None = None) -> None:
        self.name = name
        self.thread = FakeThread()
        self.socket = FakeSocket(name)
        self.config = type("FakeEndpointConfig", (), {"config": FakeConfigObject()})()
        self.context = EndpointContext(assigned_eid=count)
        self.am = am or type("FakeAM", (), {"sniffer": FakeSniffer(count)})()
        self.stop_calls: list[bool] = []

    def stop_sniffer(self, join: bool = False) -> None:
        self.stop_calls.append(join)


def test_machine_build_start_stop_getattr_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    from pymctp.topology import machine as machine_module

    created: list[FakeEndpoint] = []

    def fake_from_config(config: dict[str, Any], start_thread: bool = False, verbose: bool = False) -> FakeEndpoint:
        endpoint = FakeEndpoint(config["name"], len(created) + 1)
        created.append(endpoint)
        return endpoint

    monkeypatch.setattr(machine_module.EndpointManager, "from_config", staticmethod(fake_from_config))
    spec = MachineSpec(
        name="unit",
        devices=[
            DeviceSpec(name="hsp1", transport={"type": "fake"}, eid=34),
            DeviceSpec(name="hsp2", transport={"type": "fake"}, eid=35),
        ],
    )

    machine = Machine(spec, verbose=True)
    machine.build()
    machine.start().start()

    assert machine["hsp1"] is created[0]
    assert machine.hsp2 is created[1]
    assert created[0].thread.started == 1
    assert created[1].thread.started == 1
    assert machine.summary() == "hsp1 processed 1 packets\nhsp2 processed 2 packets"

    machine.stop(join=True)

    assert created[1].stop_calls == [True]
    assert created[0].stop_calls == [True]
    assert created[0].config.config.closed is True
    assert created[1].config.config.closed is True


def test_machine_forwards_an_optional_packet_observer(monkeypatch: pytest.MonkeyPatch) -> None:
    from pymctp.topology import machine as machine_module

    seen: list[object] = []

    def fake_from_config(
        config: dict[str, Any],
        start_thread: bool = False,
        verbose: bool = False,
        observer=None,
    ) -> FakeEndpoint:
        seen.append(observer)
        return FakeEndpoint(config["name"])

    monkeypatch.setattr(machine_module.EndpointManager, "from_config", staticmethod(fake_from_config))
    observer = object()
    machine = Machine(
        MachineSpec(name="unit", devices=[DeviceSpec(name="rot", transport={"type": "fake"}, eid=0x20)]),
        observer=observer,
    )

    machine.build()

    assert seen == [observer]


def test_machine_context_manager_starts_and_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    from pymctp.topology import machine as machine_module

    endpoint = FakeEndpoint("hsp1")
    monkeypatch.setattr(machine_module.EndpointManager, "from_config", staticmethod(lambda *args, **kwargs: endpoint))
    spec = MachineSpec(name="unit", devices=[DeviceSpec(name="hsp1", transport={"type": "fake"}, eid=34)])

    with Machine(spec) as machine:
        assert machine.hsp1.thread.started == 1

    assert endpoint.stop_calls == [True]


class FakeBusOwnerBehavior(Behavior):
    @property
    def name(self) -> str:
        return "bus-owner"

    @property
    def report(self) -> str:
        return "last-report"

    def can_handle(self, pkt: Any, ctx: EndpointContext) -> bool:
        return False

    def handle(self, pkt: Any, ctx: EndpointContext) -> None:
        return None

    def rediscover(self, timeout_s: float | None = None) -> str:
        return f"rediscovered:{timeout_s}"


def test_bus_owner_handle_is_discovered_defensively() -> None:
    behavior = FakeBusOwnerBehavior()
    am = RoleBasedEndpointAM(behaviors=[behavior], context=EndpointContext())
    endpoint = FakeEndpoint("owner", am=am)
    machine = Machine(MachineSpec(name="unit"))
    machine.endpoints["owner"] = endpoint

    handle = machine.bus_owner

    assert handle is not None
    assert handle.behavior is behavior
    assert handle.report == "last-report"
    assert handle.rediscover(timeout_s=1.5) == "rediscovered:1.5"


class TestMachineBuildErrors:
    """A transport that cannot connect must fail with an actionable message.

    Endpoint transports connect eagerly in their config's ``__post_init__``, so
    the underlying ``ConnectionRefusedError`` gets wrapped in a mashumaro
    deserialization error. Surfacing that raw is useless to a user whose only
    real problem is that QEMU is not running yet.
    """

    def _spec(self):
        return MachineSpec(
            name="unreachable",
            devices=[
                DeviceSpec(
                    name="ep1",
                    eid=0x10,
                    transport={"type": "fake-unreachable", "host": "127.0.0.1", "port": 5580},
                )
            ],
        )

    def test_raises_machine_build_error_naming_the_device(self, monkeypatch):
        from pymctp.topology.machine import MachineBuildError

        def boom(config, start_thread=True, verbose=False):
            raise ConnectionRefusedError(61, "Connection refused")

        monkeypatch.setattr(
            "pymctp.topology.machine.EndpointManager.from_config", staticmethod(boom), raising=False
        )
        machine = Machine(self._spec())

        with pytest.raises(MachineBuildError) as excinfo:
            machine.build()

        message = str(excinfo.value)
        assert "ep1" in message
        assert "fake-unreachable" in message
        assert "127.0.0.1:5580" in message
        assert "Connection refused" in message
        # and the actionable hint
        assert "QEMU" in message
        assert excinfo.value.device_name == "ep1"

    def test_unwraps_a_wrapped_root_cause(self, monkeypatch):
        from pymctp.topology.machine import MachineBuildError

        def boom(config, start_thread=True, verbose=False):
            try:
                raise ConnectionRefusedError(61, "Connection refused")
            except ConnectionRefusedError as exc:
                raise ValueError("Field 'config' has invalid value {...}") from exc

        monkeypatch.setattr(
            "pymctp.topology.machine.EndpointManager.from_config", staticmethod(boom), raising=False
        )

        with pytest.raises(MachineBuildError) as excinfo:
            Machine(self._spec()).build()

        # The user needs the root cause, not the deserialization wrapper.
        assert "Connection refused" in str(excinfo.value)

    def test_partial_build_is_torn_down(self, monkeypatch):
        from pymctp.topology.machine import MachineBuildError

        built: list[FakeEndpoint] = []

        def from_config(config, start_thread=True, verbose=False):
            if config["name"] == "ep2":
                raise ConnectionRefusedError(61, "Connection refused")
            endpoint = FakeEndpoint(config["name"])
            built.append(endpoint)
            return endpoint

        monkeypatch.setattr(
            "pymctp.topology.machine.EndpointManager.from_config", staticmethod(from_config), raising=False
        )
        spec = MachineSpec(
            name="partial",
            devices=[
                DeviceSpec(name="ep1", eid=0x10, transport={"type": "fake", "host": "h", "port": 1}),
                DeviceSpec(name="ep2", eid=0x11, transport={"type": "fake", "host": "h", "port": 2}),
            ],
        )
        machine = Machine(spec)

        with pytest.raises(MachineBuildError):
            machine.build()

        # The endpoint that did come up must not be left dangling.
        assert machine.endpoints == {}
        assert built and built[0].stop_calls, "already-built endpoints must be stopped"

    def test_non_connection_errors_still_name_the_device(self, monkeypatch):
        from pymctp.topology.machine import MachineBuildError

        def boom(config, start_thread=True, verbose=False):
            raise ValueError("Unknown config type 'nope'")

        monkeypatch.setattr(
            "pymctp.topology.machine.EndpointManager.from_config", staticmethod(boom), raising=False
        )

        with pytest.raises(MachineBuildError) as excinfo:
            Machine(self._spec()).build()

        message = str(excinfo.value)
        assert "ep1" in message
        assert "Unknown config type" in message
        # no misleading QEMU hint for a non-connection failure
        assert "QEMU" not in message
