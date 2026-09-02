# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Fluent builder for machine topology specs."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from pymctp.topology.types import DeviceSpec, EidMap, MachineDefaults, MachineSpec

#: Distinguishes "leave this default alone" from an explicit ``None``. A sniff
#: timeout of ``None`` means run until stopped, so it has to be expressible.
_UNSET: Any = object()


class MachineBuilder:
    """Fluent helper for constructing :class:`MachineSpec` instances."""

    def __init__(self, name: str, description: str = "") -> None:
        self._name = name
        self._description = description
        self._devices: list[DeviceSpec] = []
        self._eids = EidMap()
        self._defaults = MachineDefaults()

    def defaults(
        self,
        *,
        count: int | None = None,
        timeout: float | None = _UNSET,
        bg: bool | None = None,
        thread_kwargs: Mapping[str, Any] | None = None,
        dump_packet: bool | None = None,
        dump_hex: bool | None = None,
        host: str | None = None,
        transport_defaults: Mapping[str, Any] | None = None,
    ) -> MachineBuilder:
        """Update machine-level defaults applied to subsequently built configs."""

        merged_thread_kwargs = dict(self._defaults.thread_kwargs)
        if thread_kwargs is not None:
            merged_thread_kwargs.update(thread_kwargs)
        if count is not None:
            merged_thread_kwargs["count"] = count
        if timeout is not _UNSET:
            # ``None`` is meaningful here: it runs the sniffer until stopped.
            merged_thread_kwargs["timeout"] = timeout
        if bg is not None:
            merged_thread_kwargs["bg"] = bg
        self._defaults.thread_kwargs = merged_thread_kwargs
        if dump_packet is not None:
            self._defaults.dump_packet = dump_packet
        if dump_hex is not None:
            self._defaults.dump_hex = dump_hex
        if host is not None:
            self._defaults.host = host
        if transport_defaults is not None:
            merged_transport_defaults = dict(self._defaults.transport_defaults)
            merged_transport_defaults.update(transport_defaults)
            self._defaults.transport_defaults = merged_transport_defaults
        return self

    def eids(self, eids: EidMap | Mapping[str, int]) -> MachineBuilder:
        """Merge EIDs into the topology's built-in EID map."""

        self._eids = self._eids.merged_with(eids if isinstance(eids, EidMap) else dict(eids))
        return self

    def device(
        self,
        name: str,
        *,
        transport: Mapping[str, Any],
        eid: int | None = None,
        eid_key: str | None = None,
        physical_address: int | None = None,
        msg_types: Iterable[str] | None = None,
        supported_msg_types: Iterable[str] | None = None,
        supported_vdm_msg_types: Iterable[Mapping[str, Any]] | None = None,
        roles: Iterable[str] | None = None,
        role_options: Mapping[str, Mapping[str, Any]] | None = None,
        endpoint_uuid: str | None = None,
        pool_size: int = 0,
        static_eid: int | None = None,
        mtu_size: int | None = None,
        max_reassembly_contexts: int | None = None,
        reassembly_timeout_s: float | None = None,
        downstream: Iterable[str] | None = None,
        thread_kwargs: Mapping[str, Any] | None = None,
        enabled: bool = True,
        context_overrides: Mapping[str, Any] | None = None,
    ) -> MachineBuilder:
        """Append one device to the topology."""

        msg_type_values = supported_msg_types if supported_msg_types is not None else msg_types
        self._devices.append(
            DeviceSpec(
                name=name,
                transport=dict(transport),
                eid=eid,
                eid_key=eid_key,
                physical_address=physical_address,
                supported_msg_types=list(msg_type_values) if msg_type_values is not None else ["CTRL"],
                supported_vdm_msg_types=[dict(item) for item in supported_vdm_msg_types or []],
                roles=list(roles or []),
                role_options={key: dict(value) for key, value in (role_options or {}).items()},
                endpoint_uuid=endpoint_uuid,
                pool_size=pool_size,
                static_eid=static_eid,
                mtu_size=mtu_size,
                max_reassembly_contexts=max_reassembly_contexts,
                reassembly_timeout_s=reassembly_timeout_s,
                downstream=list(downstream or []),
                thread_kwargs=dict(thread_kwargs or {}),
                enabled=enabled,
                context_overrides=dict(context_overrides or {}),
            )
        )
        return self

    def devices(
        self,
        names: Iterable[str],
        transport_factory: Callable[[int, str], dict[str, Any]],
        **common: Any,
    ) -> MachineBuilder:
        """Append several devices whose transport differs by index/name."""

        for index, name in enumerate(names):
            self.device(name, transport=transport_factory(index, name), **common)
        return self

    def build(self) -> MachineSpec:
        """Return a validated machine spec."""

        spec = MachineSpec(
            name=self._name,
            description=self._description,
            devices=list(self._devices),
            eids=self._eids,
            defaults=self._defaults,
        )
        spec.validate()
        return spec
