# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Serializable topology types for mocked MCTP machines."""

from __future__ import annotations

import dataclasses
import logging
from copy import deepcopy
from dataclasses import field
from pathlib import Path
from typing import Any

from mashumaro import DataClassDictMixin

from pymctp.automaton.manager import registered_config_types

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class EidAssignment(DataClassDictMixin):
    """An EID a bus owner assigns to another endpoint."""

    target: str
    eid: int
    pool_start: int | None = None
    pool_size: int = 0


@dataclasses.dataclass
class EidMap(DataClassDictMixin):
    """Machine-specific logical device name to EID mapping."""

    eids: dict[str, int] = field(default_factory=dict)
    assignments: list[EidAssignment] = field(default_factory=list)

    def __getitem__(self, name: str) -> int:
        try:
            return self.eids[name]
        except KeyError as exc:
            known = ", ".join(sorted(self.eids)) or "<none>"
            msg = f"Unknown EID key {name!r}. Available EID keys: {known}"
            raise KeyError(msg) from exc

    def get(self, name: str, default: int | None = None) -> int | None:
        """Return the EID for *name*, or *default* when it is not present."""

        return self.eids.get(name, default)

    def merged_with(self, other: EidMap | dict[str, int]) -> EidMap:
        """Return a new EID map with *other* merged in; values in *other* win."""

        merged = deepcopy(self)
        if isinstance(other, EidMap):
            merged.eids.update(other.eids)
            merged.assignments.extend(deepcopy(other.assignments))
        else:
            merged.eids.update(other)
        return merged


@dataclasses.dataclass
class MachineDefaults(DataClassDictMixin):
    """Defaults applied to every endpoint in a machine topology."""

    thread_kwargs: dict[str, Any] = field(default_factory=lambda: {"count": 0, "timeout": 1800, "bg": False})
    dump_packet: bool = True
    dump_hex: bool = False
    host: str | None = None
    transport_defaults: dict[str, Any] = field(default_factory=dict)


@dataclasses.dataclass
class DeviceSpec(DataClassDictMixin):
    """Description of one mocked endpoint in a machine topology."""

    name: str
    transport: dict[str, Any]
    eid: int | None = None
    eid_key: str | None = None
    physical_address: int | None = None
    supported_msg_types: list[str] = field(default_factory=lambda: ["CTRL"])
    supported_vdm_msg_types: list[dict[str, Any]] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    role_options: dict[str, dict[str, Any]] = field(default_factory=dict)
    endpoint_uuid: str | None = None
    pool_size: int = 0
    static_eid: int | None = None
    mtu_size: int | None = None
    max_reassembly_contexts: int | None = None
    reassembly_timeout_s: float | None = None
    downstream: list[str] = field(default_factory=list)
    thread_kwargs: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    context_overrides: dict[str, Any] = field(default_factory=dict)

    def to_endpoint_config(self, machine: MachineSpec, eids: EidMap) -> dict[str, Any]:
        """Build the dict accepted by :meth:`EndpointManager.from_config`."""

        config = self._transport_config(machine)
        context = self._context_dict(machine, eids)
        downstream_endpoints: dict[int, dict[str, Any]] = {}
        for downstream_name in self.downstream:
            downstream_device = machine.device(downstream_name)
            downstream_eid = downstream_device._resolve_eid(eids)
            downstream_endpoints[downstream_eid] = downstream_device._context_dict(machine, eids)

        thread_kwargs = dict(machine.defaults.thread_kwargs)
        thread_kwargs.update(self.thread_kwargs)

        role_options = _resolve_role_option_paths(
            deepcopy(self.role_options),
            getattr(machine, "_source_dir", None),
            self.name,
        )
        pldm_options = role_options.get("pldm-sensor")
        if isinstance(pldm_options, dict):
            pldm_options.setdefault("_device_name", self.name)

        return {
            "context": context,
            "config": config,
            "thread_kwargs": thread_kwargs,
            "role": list(self.roles),
            "role_options": role_options,
            "name": self.name,
            "downstream_endpoints": downstream_endpoints,
        }

    def _transport_config(self, machine: MachineSpec) -> dict[str, Any]:
        config = dict(machine.defaults.transport_defaults)
        config.update(self.transport)
        config.setdefault("name", self.name)
        if machine.defaults.host is not None:
            config.setdefault("host", machine.defaults.host)
        config.setdefault("dump_packet", machine.defaults.dump_packet)
        config.setdefault("dump_hex", machine.defaults.dump_hex)
        return config

    def _context_dict(self, machine: MachineSpec, eids: EidMap) -> dict[str, Any]:
        context: dict[str, Any] = {
            "assigned_eid": self._resolve_eid(eids),
            "supported_msg_types": list(self.supported_msg_types),
            "supported_vdm_msg_types": deepcopy(self.supported_vdm_msg_types),
            "pool_size": self.pool_size,
        }
        if self.physical_address is not None:
            context["physical_address"] = {"address": self.physical_address}
        if self.static_eid is not None:
            context["static_eid"] = self.static_eid
        if self.mtu_size is not None:
            context["mtu_size"] = self.mtu_size
        if self.max_reassembly_contexts is not None:
            context["max_reassembly_contexts"] = self.max_reassembly_contexts
        if self.reassembly_timeout_s is not None:
            context["reassembly_timeout_s"] = self.reassembly_timeout_s
        if self.endpoint_uuid is not None:
            context["endpoint_uuid"] = self.endpoint_uuid
        context.update(deepcopy(self.context_overrides))
        return context

    def _resolve_eid(self, eids: EidMap) -> int:
        if self.eid is not None:
            return self.eid
        key = self.eid_key or self.name
        value = eids.get(key)
        if value is None:
            known = ", ".join(sorted(eids.eids)) or "<none>"
            msg = f"Device {self.name!r} could not resolve EID key {key!r}. Available EID keys: {known}"
            raise ValueError(msg)
        return value


@dataclasses.dataclass
class MachineSpec(DataClassDictMixin):
    """Serializable description of a board or system of MCTP endpoints."""

    name: str
    description: str = ""
    devices: list[DeviceSpec] = field(default_factory=list)
    eids: EidMap = field(default_factory=EidMap)
    defaults: MachineDefaults = field(default_factory=MachineDefaults)

    def device(self, name: str) -> DeviceSpec:
        """Return the device named *name* or raise a helpful :class:`KeyError`."""

        for device in self.devices:
            if device.name == name:
                return device
        known = ", ".join(self.device_names()) or "<none>"
        msg = f"Unknown device {name!r}. Available devices: {known}"
        raise KeyError(msg)

    def device_names(self) -> list[str]:
        """Return device names in topology order."""

        return [device.name for device in self.devices]

    def with_eids(self, eids: EidMap | dict[str, int]) -> MachineSpec:
        """Return a new machine spec with merged EIDs; this spec is not mutated."""

        spec = deepcopy(self)
        spec.eids = spec.eids.merged_with(eids)
        return spec

    def resolve_eid(self, device: DeviceSpec) -> int:
        """Resolve a device's effective assigned EID."""

        return device._resolve_eid(self.eids)

    def validate(self) -> None:
        """Validate topology-internal references and log optional transport warnings."""

        self._validate_device_names()
        known_names = set(self.device_names())
        seen_eids: dict[int, str] = {}
        for device in self.devices:
            eid = self.resolve_eid(device)
            if eid in seen_eids:
                msg = f"Duplicate EID {eid}: devices {seen_eids[eid]!r} and {device.name!r}"
                raise ValueError(msg)
            seen_eids[eid] = device.name
            for downstream_name in device.downstream:
                if downstream_name not in known_names:
                    known = ", ".join(sorted(known_names)) or "<none>"
                    msg = (
                        f"Device {device.name!r} references unknown downstream device {downstream_name!r}. "
                        f"Available devices: {known}"
                    )
                    raise ValueError(msg)
            if device.max_reassembly_contexts is not None and not 1 <= device.max_reassembly_contexts <= 8:
                msg = (
                    f"Device {device.name!r} max_reassembly_contexts must be between 1 and 8, "
                    f"got {device.max_reassembly_contexts}"
                )
                raise ValueError(msg)
            if device.reassembly_timeout_s is not None and device.reassembly_timeout_s <= 0:
                msg = (
                    f"Device {device.name!r} reassembly_timeout_s must be positive, "
                    f"got {device.reassembly_timeout_s}"
                )
                raise ValueError(msg)
            self._warn_unknown_transport(device)
            self._warn_vdpci_without_capability_set(device)

    def _validate_device_names(self) -> None:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for device in self.devices:
            if device.name in seen:
                duplicates.add(device.name)
            seen.add(device.name)
        if duplicates:
            msg = f"Duplicate device names: {', '.join(sorted(duplicates))}"
            raise ValueError(msg)

    def _warn_vdpci_without_capability_set(self, device: DeviceSpec) -> None:
        """Warn when an endpoint offers VDPCI but reports no vendor capability set.

        ``GetVendorDefinedMessageSupport`` answers ERROR_INVALID_DATA when the
        endpoint has no capability sets, so a bus owner that follows up on the
        advertised VDPCI message type fails discovery against it.
        """
        msg_types = {str(msg_type).upper() for msg_type in device.supported_msg_types}
        if "VDPCI" in msg_types and not device.supported_vdm_msg_types:
            logger.warning(
                "Device %r supports VDPCI but declares no supported_vdm_msg_types; "
                "GetVendorDefinedMessageSupport will answer ERROR_INVALID_DATA",
                device.name,
            )

    def _warn_unknown_transport(self, device: DeviceSpec) -> None:
        transport_type = device.transport.get("type")
        if transport_type is None:
            msg = f"Device {device.name!r} transport is missing required 'type' discriminator"
            raise ValueError(msg)
        registry = registered_config_types()
        if registry and str(transport_type) not in registry:
            logger.warning(
                "Device %r uses unregistered transport type %r. Registered types: %s",
                device.name,
                transport_type,
                sorted(registry),
            )


def _resolve_role_option_paths(value: Any, base_dir: Path | None, device_name: str, option_name: str = "") -> Any:
    if isinstance(value, dict):
        return {
            key: _resolve_role_option_paths(item, base_dir, device_name, str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_resolve_role_option_paths(item, base_dir, device_name, option_name) for item in value]
    if not option_name.endswith("_from") or not isinstance(value, str) or not value:
        return value

    path = Path(value)
    if path.is_absolute():
        resolved = path
    elif base_dir is not None:
        resolved = Path(base_dir) / path
    else:
        resolved = Path.cwd() / path

    if not resolved.exists():
        msg = f"Device {device_name!r} role option {option_name!r} file not found: {resolved}"
        if base_dir is None and not path.is_absolute():
            # Nothing declared where the spec came from, so a relative path has
            # no anchor other than wherever the process happens to be running.
            msg += (
                f". The relative path {value!r} was resolved against the current directory because this "
                "machine spec was built in memory rather than loaded from a file. Pass an absolute path, "
                "or load the spec with load_machine_spec() so paths resolve against the spec's directory."
            )
        raise ValueError(msg)
    return str(resolved)
