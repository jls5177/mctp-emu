# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest

from pymctp.topology import DeviceSpec, EidMap, MachineBuilder, MachineDefaults, MachineSpec


def test_builder_produces_hand_written_equivalent_spec() -> None:
    built = (
        MachineBuilder("l4a40", description="example")
        .defaults(timeout=1800, dump_packet=True, host="localhost")
        .eids({"hsp1": 34})
        .device(
            "hsp1",
            transport={"type": "i2c-stream", "port": 5570, "master": True, "target_address": 0x12},
            physical_address=0x58,
            msg_types=["CTRL", "PLDM"],
            roles=["simple"],
        )
        .build()
    )
    expected = MachineSpec(
        name="l4a40",
        description="example",
        eids=EidMap({"hsp1": 34}),
        defaults=MachineDefaults(thread_kwargs={"count": 0, "timeout": 1800, "bg": False}, host="localhost"),
        devices=[
            DeviceSpec(
                name="hsp1",
                transport={"type": "i2c-stream", "port": 5570, "master": True, "target_address": 0x12},
                physical_address=0x58,
                supported_msg_types=["CTRL", "PLDM"],
                roles=["simple"],
            )
        ],
    )

    assert built == expected


def test_devices_bulk_helper_uses_index_and_name() -> None:
    spec = (
        MachineBuilder("bulk")
        .eids({"hsp1": 34, "hsp2": 35})
        .devices(
            ["hsp1", "hsp2"],
            lambda index, name: {"type": "i2c-stream", "port": 5570 + index, "name": name.upper()},
            physical_address=0x58,
        )
        .build()
    )

    assert spec.device_names() == ["hsp1", "hsp2"]
    assert spec.device("hsp1").transport["port"] == 5570
    assert spec.device("hsp2").transport["port"] == 5571


def test_an_explicit_none_timeout_runs_until_stopped() -> None:
    """``None`` is a meaningful sniff timeout, so it must survive the builder.

    Treating it as "no value supplied" left the 30-minute default in place and
    no caller could ask for a long-lived rig.
    """
    builder = MachineBuilder("board").defaults(timeout=None)

    assert builder.build().defaults.thread_kwargs["timeout"] is None


def test_omitting_the_timeout_keeps_the_existing_default() -> None:
    builder = MachineBuilder("board").defaults(timeout=90).defaults(count=0)

    assert builder.build().defaults.thread_kwargs["timeout"] == 90


def test_reassembly_limits_flow_into_the_endpoint_context() -> None:
    spec = (
        MachineBuilder("board")
        .eids({"rot": 0x20})
        .device(
            "rot",
            transport={"type": "fake"},
            max_reassembly_contexts=8,
            reassembly_timeout_s=12.5,
        )
        .build()
    )

    context = spec.device("rot").to_endpoint_config(spec, spec.eids)["context"]
    assert context["max_reassembly_contexts"] == 8
    assert context["reassembly_timeout_s"] == 12.5


@pytest.mark.parametrize(("value", "message"), [(0, "between 1 and 8"), (9, "between 1 and 8")])
def test_invalid_reassembly_context_limit_is_rejected(value: int, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        (
            MachineBuilder("board")
            .eids({"rot": 0x20})
            .device("rot", transport={"type": "fake"}, max_reassembly_contexts=value)
            .build()
        )
