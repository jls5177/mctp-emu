# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the SPDM requester behavior."""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from collections.abc import Callable

import pytest
from scapy.packet import Packet

from pymctp.automaton.behaviors.spdm_requester import (
    AttestationReport,
    SpdmAttestationTarget,
    SpdmRequesterBehavior,
    SpdmRequesterProfile,
)
from pymctp.automaton.behaviors.spdm_responder import SpdmResponderBehavior, SpdmResponderProfile
from pymctp.automaton.roles import create_endpoint
from pymctp.layers.mctp.control import ControlHdr, GetMessageTypeSupportResponsePacket
from pymctp.layers.mctp.control.types import ContrlCmdCodes
from pymctp.layers.mctp.spdm import (
    AlgorithmsPacket,
    CapabilitiesPacket,
    CertificatePacket,
    ChallengeAuthPacket,
    ChallengePacket,
    DigestsPacket,
    GetCapabilitiesPacket,
    GetCertificatePacket,
    GetMeasurementsPacket,
    MeasurementsPacket,
    SpdmHdr,
    SpdmHdrPacket,
    VersionPacket,
)
from pymctp.layers.mctp.spdm.types import SpdmErrorCode, SpdmRequestCode, SpdmResponseCode
from pymctp.layers.mctp.transport import SmbusTransport, TransportHdr
from pymctp.layers.mctp.types import EndpointContext, MsgTypes, Smbus7bitAddress


class FakeSession:
    def __init__(
        self,
        responder: Callable[[Packet, int, MsgTypes | None], Packet | None],
    ) -> None:
        self.control_sent: list[tuple[Packet, int, Smbus7bitAddress | None, bool]] = []
        self.spdm_sent: list[tuple[Packet, int, Smbus7bitAddress | None, MsgTypes, bool]] = []
        self.control_timeouts: list[float | None] = []
        self.spdm_timeouts: list[float | None] = []
        self._responder = responder

    def sndrcv_control_msg(
        self,
        pkt: Packet,
        dst_eid: int,
        *,
        dst_phy_addr: Smbus7bitAddress | None = None,
        timeout_s: float | None = None,
        threaded: bool = False,
        instance_id: int | None = None,
    ) -> Packet | None:
        self.control_sent.append((pkt, dst_eid, dst_phy_addr, threaded))
        self.control_timeouts.append(timeout_s)
        return self._responder(pkt, dst_eid, None)

    def sndrcv_mctp_msg(
        self,
        pkt: Packet,
        dst_eid: int,
        *,
        dst_phy_addr: Smbus7bitAddress | None = None,
        msg_type: MsgTypes = MsgTypes.CTRL,
        msg_tag: int | None = None,
        timeout_s: float | None = None,
        threaded: bool = False,
    ) -> Packet | None:
        self.spdm_sent.append((pkt, dst_eid, dst_phy_addr, msg_type, threaded))
        self.spdm_timeouts.append(timeout_s)
        return self._responder(pkt, dst_eid, msg_type)


class FakeAM:
    def __init__(self, session: FakeSession, context: EndpointContext) -> None:
        self.session = session
        self.context = context


def _ctx() -> EndpointContext:
    return EndpointContext(
        physical_address=Smbus7bitAddress(0x20),
        assigned_eid=0x0C,
        supported_msg_types=[MsgTypes.CTRL, MsgTypes.SPDM],
    )


def _behavior_with_fake_am(
    behavior: SpdmRequesterBehavior,
    responder: Callable[[Packet, int, MsgTypes | None], Packet | None],
) -> tuple[FakeSession, FakeAM, EndpointContext]:
    ctx = _ctx()
    session = FakeSession(responder)
    am = FakeAM(session, ctx)
    behavior.on_attach(ctx)
    behavior._am = am
    behavior._ctx = ctx
    return session, am, ctx


def _msg_type_response(msg_types: list[int]) -> Packet:
    return ControlHdr(rq=False, cmd_code=ContrlCmdCodes.GetMessageTypeSupport, completion_code=0) / (
        GetMessageTypeSupportResponsePacket(msg_type_cnt=len(msg_types), msg_type_list=msg_types)
    )


def _spdm_response(
    code: SpdmResponseCode,
    payload: Packet | bytes | None = None,
    *,
    version: int = 0x12,
    param1: int = 0,
    param2: int = 0,
) -> Packet:
    hdr = SpdmHdr(spdm_version=version, request_response_code=code, param1=param1, param2=param2)
    return hdr / payload if payload is not None else hdr


def _version_response(*versions: int) -> Packet:
    return _spdm_response(
        SpdmResponseCode.VERSION,
        VersionPacket(version_number_list=[_version_entry(version) for version in versions]),
        version=0x10,
    )


def _version_entry(version: int) -> int:
    return (((version >> 4) & 0x0F) << 12) | ((version & 0x0F) << 8)


def _der_cert(total_length: int, fill: int) -> bytes:
    return b"\x30\x82" + (total_length - 4).to_bytes(2, "big") + bytes([fill]) * (total_length - 4)


def _cert_chain(cert_lengths: list[int], *, hash_size: int = 48) -> bytes:
    certs = b"".join(_der_cert(length, index + 1) for index, length in enumerate(cert_lengths))
    total = 4 + hash_size + len(certs)
    return total.to_bytes(4, "little") + (b"H" * hash_size) + certs


def _scripted_responder(
    *,
    versions: list[int] | None = None,
    chain: bytes | None = None,
    spdm_supported: bool = True,
    base_hash_algo: int = 0x00000002,
    base_asym_algo: int = 0x00000080,
    data_transfer_size: int = 0x1000,
) -> Callable[[Packet, int, MsgTypes | None], Packet | None]:
    versions = versions or [0x10, 0x12]
    chain = chain if chain is not None else _cert_chain([16], hash_size=48 if base_hash_algo == 0x02 else 32)

    def responder(pkt: Packet, dst_eid: int, msg_type: MsgTypes | None) -> Packet | None:
        if msg_type is None:
            msg_types = [int(MsgTypes.CTRL), int(MsgTypes.SPDM)] if spdm_supported else [int(MsgTypes.CTRL)]
            return _msg_type_response(msg_types)

        spdm = pkt.getlayer(SpdmHdrPacket)
        assert spdm is not None
        version = int(spdm.spdm_version)
        code = SpdmRequestCode(int(spdm.request_response_code))
        if code == SpdmRequestCode.GET_VERSION:
            return _version_response(*versions)
        if code == SpdmRequestCode.GET_CAPABILITIES:
            return _spdm_response(
                SpdmResponseCode.CAPABILITIES,
                CapabilitiesPacket(data_transfer_size=data_transfer_size, max_spdm_msg_size=data_transfer_size),
                version=version,
            )
        if code == SpdmRequestCode.NEGOTIATE_ALGORITHMS:
            return _spdm_response(
                SpdmResponseCode.ALGORITHMS,
                AlgorithmsPacket(base_hash_sel=base_hash_algo, base_asym_sel=base_asym_algo),
                version=version,
            )
        if code == SpdmRequestCode.GET_DIGESTS:
            return _spdm_response(SpdmResponseCode.DIGESTS, DigestsPacket(), version=version, param2=0x01)
        if code == SpdmRequestCode.GET_CERTIFICATE:
            request = pkt.getlayer(GetCertificatePacket)
            assert request is not None
            offset = int(request.offset)
            length = int(request.length)
            portion = chain[offset : offset + length]
            return _spdm_response(
                SpdmResponseCode.CERTIFICATE,
                CertificatePacket(portion_length=len(portion), remainder_length=max(0, len(chain) - offset - len(portion)))
                / portion,
                version=version,
                param1=int(spdm.param1),
            )
        if code == SpdmRequestCode.CHALLENGE:
            return _spdm_response(SpdmResponseCode.CHALLENGE_AUTH, ChallengeAuthPacket(), version=version)
        if code == SpdmRequestCode.GET_MEASUREMENTS:
            return _spdm_response(
                SpdmResponseCode.MEASUREMENTS,
                MeasurementsPacket(number_of_blocks=1, measurement_record_length=0),
                version=version,
            )
        return None

    return responder


def _spdm_codes(session: FakeSession) -> list[SpdmRequestCode]:
    return [SpdmRequestCode(int(pkt[SpdmHdrPacket].request_response_code)) for pkt, *_ in session.spdm_sent]


def _wait_until(predicate: Callable[[], bool], timeout_s: float = 0.5) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


def test_role_registration_create_endpoint_and_options_targets_accept_dicts() -> None:
    ctx = _ctx()
    am = create_endpoint(
        (
            "spdm-requester",
            {
                "targets": [{"name": "rot", "eid": 0x1D, "physical_address": 0x30}],
                "profile": {"supported_versions": [0x12]},
                "start_delay_s": 0,
                "ct_exponent": 3,
            },
        ),
        context=ctx,
    )

    behavior = am.get_behavior("spdm-requester")

    assert am.role == ["spdm-requester"]
    assert isinstance(behavior, SpdmRequesterBehavior)
    assert behavior.profile.supported_versions == [0x12]
    assert behavior.profile.ct_exponent == 3
    assert behavior._targets == [SpdmAttestationTarget(name="rot", eid=0x1D, physical_address=0x30)]


def test_eid_resolver_is_called_first_and_receives_pci_identity() -> None:
    behavior = SpdmRequesterBehavior(
        targets=[
            {
                "name": "pcie-rot",
                "vendor_id": 0x8086,
                "device_id": 0x000A,
                "subsystem_vendor_id": 0x1414,
                "subsystem_device_id": 0x00FF,
                "instance": 1,
                "full_attestation": False,
            }
        ]
    )
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder())
    resolved_targets: list[SpdmAttestationTarget] = []

    def resolver(target: SpdmAttestationTarget) -> int:
        assert session.control_sent == []
        assert session.spdm_sent == []
        assert target.vendor_id == 0x8086
        assert target.device_id == 0x000A
        assert target.subsystem_vendor_id == 0x1414
        assert target.subsystem_device_id == 0x00FF
        assert target.instance == 1
        resolved_targets.append(target)
        return 0x1D

    behavior.set_eid_resolver(resolver)

    report = behavior.attest()

    assert report.ok is True
    assert report.resolved_eid == 0x1D
    assert report.steps[0].name == "resolve-eid"
    assert resolved_targets == [behavior._targets[0]]


def test_eid_resolver_absent_result_skips_without_traffic() -> None:
    for absent in (0, None):
        behavior = SpdmRequesterBehavior(
            targets=[{"name": f"absent-{absent}", "vendor_id": 0x8086}],
            eid_resolver=lambda target, value=absent: value,
        )
        session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder())

        report = behavior.attest()

        assert report.ok is True
        assert report.skipped is True
        assert report.steps == [
            report.steps[0],
        ]
        assert report.steps[0].name == "resolve-eid"
        assert report.steps[0].ok is True
        assert "device absent" in report.steps[0].detail
        assert session.control_sent == []
        assert session.spdm_sent == []


def test_eid_resolver_result_is_used_for_all_subsequent_requests() -> None:
    behavior = SpdmRequesterBehavior(
        targets=[{"name": "pcie-rot", "vendor_id": 0x8086, "full_attestation": False}],
        eid_resolver=lambda target: 0x40,
    )
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder())

    report = behavior.attest()

    assert report.ok is True
    assert report.resolved_eid == 0x40
    assert behavior._targets[0].eid == 0x40
    assert {dst_eid for _, dst_eid, *_ in session.control_sent} == {0x40}
    assert {dst_eid for _, dst_eid, *_ in session.spdm_sent} == {0x40}


def test_eid_resolver_exception_records_failure_and_attest_all_continues() -> None:
    def resolver(target: SpdmAttestationTarget) -> int:
        if target.name == "bad":
            raise RuntimeError("boom")
        return 0x40

    behavior = SpdmRequesterBehavior(
        targets=[
            {"name": "bad", "vendor_id": 0x8086, "full_attestation": False},
            {"name": "good", "vendor_id": 0x8086, "full_attestation": False},
        ],
        eid_resolver=resolver,
    )
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder())

    reports = behavior.attest_all()

    assert [report.ok for report in reports] == [False, True]
    assert reports[0].steps[0].name == "resolve-eid"
    assert "resolver error" in reports[0].steps[0].detail
    assert {dst_eid for _, dst_eid, *_ in session.control_sent} == {0x40}
    assert {dst_eid for _, dst_eid, *_ in session.spdm_sent} == {0x40}


def test_no_resolver_and_no_static_eid_fails_without_traffic() -> None:
    behavior = SpdmRequesterBehavior(targets=[{"name": "unresolved", "vendor_id": 0x8086}])
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder())

    report = behavior.attest()

    assert report.ok is False
    assert report.skipped is False
    assert report.failures()[0].name == "resolve-eid"
    assert "no EID resolved" in report.failures()[0].detail
    assert session.control_sent == []
    assert session.spdm_sent == []


def test_attest_all_returns_reports_for_skipped_targets() -> None:
    def resolver(target: SpdmAttestationTarget) -> int:
        return 0 if target.name == "absent" else 0x40

    behavior = SpdmRequesterBehavior(
        targets=[
            {"name": "absent", "vendor_id": 0x8086, "full_attestation": False},
            {"name": "present", "vendor_id": 0x8086, "full_attestation": False},
        ],
        eid_resolver=resolver,
    )
    _behavior_with_fake_am(behavior, _scripted_responder())

    reports = behavior.attest_all()

    assert [report.steps[0].target for report in reports] == ["absent", "present"]
    assert [report.skipped for report in reports] == [True, False]
    assert [report.ok for report in reports] == [True, True]


def test_auto_attest_is_off_by_default_starting_endpoint_sends_nothing() -> None:
    behavior = SpdmRequesterBehavior(targets=[{"name": "rot", "eid": 0x1D}], start_delay_s=0)
    session, am, ctx = _behavior_with_fake_am(behavior, _scripted_responder())

    # The exact interval is a tunable that boards override; what matters here is
    # that startup is deferred at all and that nothing is sent without opt-in.
    assert behavior.profile.initial_delay_s > 0
    assert behavior.auto_attest is False
    behavior.on_start(am, ctx)
    try:
        assert session.control_sent == []
        assert session.spdm_sent == []
        assert behavior._worker is None
    finally:
        behavior.on_stop(am, ctx)


def test_auto_attest_with_zero_initial_delay_runs_one_cycle() -> None:
    behavior = SpdmRequesterBehavior(
        targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}],
        auto_attest=True,
        initial_delay_s=0,
        success_retry_s=1000,
    )
    session, am, ctx = _behavior_with_fake_am(behavior, _scripted_responder())

    behavior.on_start(am, ctx)
    try:
        assert _wait_until(lambda: bool(session.spdm_sent))
        assert SpdmRequestCode.GET_VERSION in _spdm_codes(session)
    finally:
        behavior.on_stop(am, ctx)


def test_report_listener_receives_attest_report_with_target_and_ok() -> None:
    behavior = SpdmRequesterBehavior(targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}])
    _behavior_with_fake_am(behavior, _scripted_responder())
    seen: list[AttestationReport] = []

    def listener(report: AttestationReport) -> None:
        assert report.finished_at is not None
        assert behavior.reports[report.target_name or ""] is report
        seen.append(report)

    behavior.add_report_listener(listener)

    report = behavior.attest()

    assert seen == [report]
    assert seen[0].target_name == "rot"
    assert seen[0].ok is True


def test_report_listeners_receive_attest_all_reports_in_target_order() -> None:
    behavior = SpdmRequesterBehavior(
        targets=[
            {"name": "first", "eid": 0x1D, "full_attestation": False},
            {"name": "second", "eid": 0x40, "full_attestation": False},
        ]
    )
    _behavior_with_fake_am(behavior, _scripted_responder())
    seen: list[str | None] = []
    behavior.add_report_listener(lambda report: seen.append(report.target_name))

    reports = behavior.attest_all()

    assert [report.target_name for report in reports] == ["first", "second"]
    assert seen == ["first", "second"]


def test_report_listener_receives_skipped_target() -> None:
    behavior = SpdmRequesterBehavior(
        targets=[{"name": "absent", "vendor_id": 0x8086}],
        eid_resolver=lambda target: 0,
    )
    _behavior_with_fake_am(behavior, _scripted_responder())
    seen: list[AttestationReport] = []
    behavior.add_report_listener(seen.append)

    report = behavior.attest()

    assert seen == [report]
    assert seen[0].target_name == "absent"
    assert seen[0].skipped is True


def test_report_listener_receives_failing_target() -> None:
    behavior = SpdmRequesterBehavior(targets=[{"name": "bad", "eid": 0x1D, "full_attestation": False}], retries=0)
    _behavior_with_fake_am(
        behavior,
        lambda pkt, dst_eid, msg_type: _msg_type_response([int(MsgTypes.CTRL), int(MsgTypes.SPDM)])
        if msg_type is None
        else None,
    )
    seen: list[AttestationReport] = []
    behavior.add_report_listener(seen.append)

    report = behavior.attest()

    assert report.ok is False
    assert seen == [report]
    assert seen[0].target_name == "bad"
    assert seen[0].ok is False


def test_raising_report_listener_is_logged_and_swallowed(caplog: pytest.LogCaptureFixture) -> None:
    behavior = SpdmRequesterBehavior(targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}])
    _behavior_with_fake_am(behavior, _scripted_responder())
    calls: list[tuple[str, AttestationReport]] = []

    def raising_listener(report: AttestationReport) -> None:
        calls.append(("raising", report))
        raise RuntimeError("listener boom")

    def second_listener(report: AttestationReport) -> None:
        calls.append(("second", report))

    behavior.add_report_listener(raising_listener)
    behavior.add_report_listener(second_listener)

    with caplog.at_level(logging.ERROR, logger="pymctp.automaton.behaviors.spdm_requester"):
        report = behavior.attest()

    assert report.ok is True
    assert calls == [("raising", report), ("second", report)]
    assert "SPDM attestation report listener failed for target rot" in caplog.text


def test_remove_report_listener_stops_notifications_and_ignores_missing_listener() -> None:
    behavior = SpdmRequesterBehavior(targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}])
    _behavior_with_fake_am(behavior, _scripted_responder())
    seen: list[AttestationReport] = []

    def listener(report: AttestationReport) -> None:
        seen.append(report)

    def never_added(report: AttestationReport) -> None:
        seen.append(report)

    behavior.add_report_listener(listener)
    first = behavior.attest()
    behavior.remove_report_listener(listener)
    behavior.remove_report_listener(never_added)

    behavior.attest()

    assert seen == [first]
    assert behavior.report_listeners == []


def test_multiple_report_listeners_fire_in_registration_order() -> None:
    behavior = SpdmRequesterBehavior(targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}])
    _behavior_with_fake_am(behavior, _scripted_responder())
    calls: list[str] = []
    behavior.add_report_listener(lambda report: calls.append("first"))
    behavior.add_report_listener(lambda report: calls.append("second"))

    behavior.attest()

    assert calls == ["first", "second"]


def test_scheduler_report_listener_receives_auto_attestation_report() -> None:
    behavior = SpdmRequesterBehavior(
        targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}],
        auto_attest=True,
        initial_delay_s=0,
        success_retry_s=1000,
    )
    seen: list[tuple[str | None, bool, str]] = []
    notified = threading.Event()

    def listener(report: AttestationReport) -> None:
        seen.append((report.target_name, report.ok, threading.current_thread().name))
        notified.set()

    behavior.add_report_listener(listener)
    _, am, ctx = _behavior_with_fake_am(behavior, _scripted_responder())

    behavior.on_start(am, ctx)
    try:
        assert notified.wait(timeout=0.5)
        assert seen == [("rot", True, f"mctp-spdm-requester-{ctx.eid}")]
    finally:
        behavior.on_stop(am, ctx)


def test_scheduler_deadline_uses_success_fail_and_discovery_retry_intervals() -> None:
    now = 100.0

    success = SpdmRequesterBehavior(
        targets=[{"name": "ok", "eid": 0x1D, "full_attestation": False}],
        success_retry_s=11,
        time_source=lambda: now,
    )
    _behavior_with_fake_am(success, _scripted_responder())
    assert success.attest().ok is True
    assert success.next_attempt_at("ok") == now + 11

    fail = SpdmRequesterBehavior(
        targets=[{"name": "bad", "eid": 0x1D, "full_attestation": False}],
        fail_retry_s=22,
        retries=0,
        time_source=lambda: now,
    )
    _behavior_with_fake_am(fail, lambda pkt, dst_eid, msg_type: _msg_type_response([0, 5]) if msg_type is None else None)
    assert fail.attest().ok is False
    assert fail.next_attempt_at("bad") == now + 22

    skipped = SpdmRequesterBehavior(
        targets=[{"name": "absent", "vendor_id": 0x8086}],
        discovery_fail_retry_s=33,
        eid_resolver=lambda target: 0,
        time_source=lambda: now,
    )
    _behavior_with_fake_am(skipped, _scripted_responder())
    report = skipped.attest()
    assert report.skipped is True
    assert skipped.next_attempt_at("absent") == now + 33


def test_per_target_retry_overrides_profile_defaults() -> None:
    now = 200.0
    behavior = SpdmRequesterBehavior(
        targets=[
            {
                "name": "ok",
                "eid": 0x1D,
                "full_attestation": False,
                "success_retry_s": 7,
                "fail_retry_s": 8,
                "discovery_fail_retry_s": 9,
            }
        ],
        success_retry_s=70,
        fail_retry_s=80,
        discovery_fail_retry_s=90,
        time_source=lambda: now,
    )
    _behavior_with_fake_am(behavior, _scripted_responder())

    assert behavior.attest().ok is True
    assert behavior.next_attempt_at("ok") == now + 7


def test_attest_now_clears_deadline_and_kicks_scheduler() -> None:
    now = 300.0
    behavior = SpdmRequesterBehavior(
        targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}],
        auto_attest=True,
        initial_delay_s=300,
        success_retry_s=1000,
        time_source=lambda: now,
    )
    session, am, ctx = _behavior_with_fake_am(behavior, _scripted_responder())

    behavior.on_start(am, ctx)
    try:
        assert behavior.next_attempt_at("rot") == now + 300
        behavior.attest_now("rot")
        assert behavior.next_attempt_at("rot") == now
        assert _wait_until(lambda: bool(session.spdm_sent))
    finally:
        behavior.on_stop(am, ctx)


def test_on_stop_interrupts_long_initial_delay_promptly() -> None:
    behavior = SpdmRequesterBehavior(
        targets=[{"name": "rot", "eid": 0x1D}],
        auto_attest=True,
        initial_delay_s=300,
    )
    _, am, ctx = _behavior_with_fake_am(behavior, _scripted_responder())

    behavior.on_start(am, ctx)
    started = time.monotonic()
    behavior.on_stop(am, ctx)

    assert time.monotonic() - started < 0.5


def test_happy_path_full_attestation_emits_expected_request_order() -> None:
    chain = _cert_chain([16, 18, 20])
    behavior = SpdmRequesterBehavior(
        targets=[SpdmAttestationTarget(name="rot", eid=0x1D, measurement_indices=[1, 2])],
        nonce_provider=lambda: b"N" * 32,
    )
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder(chain=chain))

    report = behavior.attest()

    assert report.ok is True
    assert [ContrlCmdCodes(pkt.cmd_code) for pkt, *_ in session.control_sent] == [
        ContrlCmdCodes.GetMessageTypeSupport
    ]
    assert _spdm_codes(session) == [
        SpdmRequestCode.GET_VERSION,
        SpdmRequestCode.GET_CAPABILITIES,
        SpdmRequestCode.NEGOTIATE_ALGORITHMS,
        SpdmRequestCode.GET_DIGESTS,
        SpdmRequestCode.GET_CERTIFICATE,
        SpdmRequestCode.GET_CERTIFICATE,
        SpdmRequestCode.GET_CERTIFICATE,
        SpdmRequestCode.GET_CERTIFICATE,
        SpdmRequestCode.GET_CERTIFICATE,
        SpdmRequestCode.GET_CERTIFICATE,
        SpdmRequestCode.GET_CERTIFICATE,
        SpdmRequestCode.CHALLENGE,
        SpdmRequestCode.GET_MEASUREMENTS,
        SpdmRequestCode.GET_MEASUREMENTS,
    ]
    assert all(threaded for *_, threaded in session.spdm_sent)
    assert all(threaded for *_, threaded in session.control_sent)


def test_a_bridged_target_adds_the_pcd_timeout_to_every_request() -> None:
    """PCD bridge latency is additional to the PA-RoT's base MCTP timeout."""
    behavior = SpdmRequesterBehavior(
        targets=[
            SpdmAttestationTarget(
                name="bridged-rot",
                eid=0x40,
                mctp_bridge_additional_timeout_s=6.5,
            )
        ],
        timeout_s=1.0,
        nonce_provider=lambda: b"N" * 32,
    )
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder(chain=_cert_chain([16, 18, 20])))

    report = behavior.attest("bridged-rot")

    assert report.ok
    assert session.control_timeouts
    assert session.spdm_timeouts
    assert set(session.control_timeouts + session.spdm_timeouts) == {7.5}


def test_get_version_uses_10_then_highest_mutual_version_for_subsequent_requests() -> None:
    behavior = SpdmRequesterBehavior(
        targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}],
        profile=SpdmRequesterProfile(supported_versions=[0x10, 0x12]),
    )
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder(versions=[0x10, 0x11, 0x12]))

    report = behavior.attest()

    versions_by_code = [(SpdmRequestCode(pkt.request_response_code), int(pkt.spdm_version)) for pkt, *_ in session.spdm_sent]
    assert report.negotiated_version == 0x12
    assert versions_by_code[0] == (SpdmRequestCode.GET_VERSION, 0x10)
    assert all(version == 0x12 for _, version in versions_by_code[1:])


def test_get_capabilities_body_varies_by_negotiated_version() -> None:
    v10 = SpdmRequesterBehavior(
        targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}],
        profile=SpdmRequesterProfile(supported_versions=[0x10]),
    )
    v10_session, _, _ = _behavior_with_fake_am(v10, _scripted_responder(versions=[0x10]))
    v10.attest()

    v12 = SpdmRequesterBehavior(
        targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}],
        profile=SpdmRequesterProfile(supported_versions=[0x12]),
    )
    v12_session, _, _ = _behavior_with_fake_am(v12, _scripted_responder(versions=[0x12]))
    v12.attest()

    v10_caps = [pkt[GetCapabilitiesPacket] for pkt, *_ in v10_session.spdm_sent if pkt.haslayer(GetCapabilitiesPacket)][0]
    v12_caps = [pkt[GetCapabilitiesPacket] for pkt, *_ in v12_session.spdm_sent if pkt.haslayer(GetCapabilitiesPacket)][0]
    assert bytes(v10_caps) == b""
    assert v10_caps.ct_exponent is None
    assert v12_caps.ct_exponent == 0x1F
    assert v12_caps.data_transfer_size == 0x1000
    assert v12_caps.max_spdm_msg_size == 0x1000


@pytest.mark.parametrize(
    ("base_hash_algo", "base_asym_algo", "hash_size", "expected_header_read"),
    [
        (0x00000002, 0x00000080, 48, 0x0034),
        (0x00000001, 0x00000010, 32, 0x0024),
    ],
)
def test_certificate_header_read_derived_from_negotiated_hash(
    base_hash_algo: int,
    base_asym_algo: int,
    hash_size: int,
    expected_header_read: int,
) -> None:
    chain = _cert_chain([16], hash_size=hash_size)
    behavior = SpdmRequesterBehavior(targets=[{"name": "rot", "eid": 0x1D}], nonce_provider=lambda: b"N" * 32)
    session, _, _ = _behavior_with_fake_am(
        behavior,
        _scripted_responder(chain=chain, base_hash_algo=base_hash_algo, base_asym_algo=base_asym_algo),
    )

    report = behavior.attest()

    cert_requests = [
        (int(pkt[GetCertificatePacket].offset), int(pkt[GetCertificatePacket].length))
        for pkt, *_ in session.spdm_sent
        if pkt.haslayer(GetCertificatePacket)
    ]
    assert report.ok is True
    assert cert_requests[0] == (0x0000, expected_header_read)
    assert report.negotiated_base_hash_algo == base_hash_algo
    assert report.negotiated_base_asym_algo == base_asym_algo
    assert report.certificate_chain == chain


def test_certificate_walk_requests_contiguous_offsets_and_reassembles_chain() -> None:
    chain = _cert_chain([16, 18, 20])
    behavior = SpdmRequesterBehavior(targets=[{"name": "rot", "eid": 0x1D}], nonce_provider=lambda: b"N" * 32)
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder(chain=chain))

    report = behavior.attest()

    cert_requests = [
        (int(pkt[GetCertificatePacket].offset), int(pkt[GetCertificatePacket].length))
        for pkt, *_ in session.spdm_sent
        if pkt.haslayer(GetCertificatePacket)
    ]
    assert cert_requests[0] == (0x0000, 0x0034)
    assert all(next_offset == offset + length for (offset, length), (next_offset, _) in zip(cert_requests, cert_requests[1:]))
    assert cert_requests == [(0x0000, 0x0034), (0x0034, 0x0007), (0x003B, 0x0009), (0x0044, 0x0007), (0x004B, 0x000B), (0x0056, 0x0007), (0x005D, 0x000D)]
    assert report.certificate_chain == chain


def test_certificate_body_larger_than_max_chunk_uses_multiple_contiguous_reads_without_extra_probe() -> None:
    chain = _cert_chain([0x260])
    behavior = SpdmRequesterBehavior(
        targets=[{"name": "rot", "eid": 0x1D, "max_cert_chunk_size": 0x1D6}],
        nonce_provider=lambda: b"N" * 32,
    )
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder(chain=chain))

    report = behavior.attest()

    cert_requests = [
        (int(pkt[GetCertificatePacket].offset), int(pkt[GetCertificatePacket].length))
        for pkt, *_ in session.spdm_sent
        if pkt.haslayer(GetCertificatePacket)
    ]
    assert cert_requests == [
        (0x0000, 0x0034),
        (0x0034, 0x0007),
        (0x003B, 0x01D6),
        (0x0211, 0x0083),
    ]
    assert all(next_offset == offset + length for (offset, length), (next_offset, _) in zip(cert_requests, cert_requests[1:]))
    assert report.certificate_chain == chain


def test_multi_certificate_multi_chunk_walk_is_contiguous_and_reassembles() -> None:
    chain = _cert_chain([0x20, 0x260])
    behavior = SpdmRequesterBehavior(
        targets=[{"name": "rot", "eid": 0x1D, "max_cert_chunk_size": 0x1D6}],
        nonce_provider=lambda: b"N" * 32,
    )
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder(chain=chain))

    report = behavior.attest()

    cert_requests = [
        (int(pkt[GetCertificatePacket].offset), int(pkt[GetCertificatePacket].length))
        for pkt, *_ in session.spdm_sent
        if pkt.haslayer(GetCertificatePacket)
    ]
    assert cert_requests == [
        (0x0000, 0x0034),
        (0x0034, 0x0007),
        (0x003B, 0x0019),
        (0x0054, 0x0007),
        (0x005B, 0x01D6),
        (0x0231, 0x0083),
    ]
    assert all(next_offset == offset + length for (offset, length), (next_offset, _) in zip(cert_requests, cert_requests[1:]))
    assert report.certificate_chain == chain


def test_target_without_spdm_message_type_is_skipped() -> None:
    behavior = SpdmRequesterBehavior(targets=[{"name": "rot", "eid": 0x1D}])
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder(spdm_supported=False))

    report = behavior.attest()

    assert report.ok is False
    assert report.failures()[0].name == "get-message-type-support"
    assert "missing SPDM" in report.failures()[0].detail
    assert session.spdm_sent == []


def test_timeout_on_get_version_fails_one_target_but_attest_all_continues() -> None:
    calls_by_eid: dict[int, int] = defaultdict(int)

    def responder(pkt: Packet, dst_eid: int, msg_type: MsgTypes | None) -> Packet | None:
        if msg_type is None:
            return _msg_type_response([int(MsgTypes.CTRL), int(MsgTypes.SPDM)])
        calls_by_eid[dst_eid] += 1
        if dst_eid == 0x1D and pkt[SpdmHdrPacket].request_response_code == SpdmRequestCode.GET_VERSION:
            return None
        return _scripted_responder()(pkt, dst_eid, msg_type)

    behavior = SpdmRequesterBehavior(
        targets=[
            {"name": "off", "eid": 0x1D, "full_attestation": False},
            {"name": "on", "eid": 0x40, "full_attestation": False},
        ],
        retries=0,
    )
    _behavior_with_fake_am(behavior, responder)

    reports = behavior.attest_all()

    assert [report.ok for report in reports] == [False, True]
    assert reports[0].failures()[0].name == "get-version"
    assert calls_by_eid[0x40] > 0


def test_retries_retry_timeouts() -> None:
    attempts = 0

    def responder(pkt: Packet, dst_eid: int, msg_type: MsgTypes | None) -> Packet | None:
        nonlocal attempts
        if msg_type is None:
            return _msg_type_response([int(MsgTypes.CTRL), int(MsgTypes.SPDM)])
        if pkt[SpdmHdrPacket].request_response_code == SpdmRequestCode.GET_VERSION:
            attempts += 1
            if attempts == 1:
                return None
        return _scripted_responder()(pkt, dst_eid, msg_type)

    behavior = SpdmRequesterBehavior(targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}], retries=1)
    _behavior_with_fake_am(behavior, responder)

    report = behavior.attest()

    assert attempts == 2
    assert report.ok is True


def test_response_not_ready_retries_until_success_and_records_count() -> None:
    attempts = 0

    def responder(pkt: Packet, dst_eid: int, msg_type: MsgTypes | None) -> Packet | None:
        nonlocal attempts
        if msg_type is None:
            return _msg_type_response([int(MsgTypes.CTRL), int(MsgTypes.SPDM)])
        if pkt[SpdmHdrPacket].request_response_code == SpdmRequestCode.GET_VERSION:
            attempts += 1
            if attempts <= 2:
                return _spdm_response(
                    SpdmResponseCode.ERROR,
                    version=0x10,
                    param1=SpdmErrorCode.RESPONSE_NOT_READY,
                )
        return _scripted_responder()(pkt, dst_eid, msg_type)

    behavior = SpdmRequesterBehavior(
        targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}],
        rsp_not_ready_max_retry=3,
        rsp_not_ready_max_duration_s=0,
    )
    _behavior_with_fake_am(behavior, responder)

    report = behavior.attest()

    get_version = [step for step in report.steps if step.name == "get-version"][0]
    assert report.ok is True
    assert attempts == 3
    assert "rsp_not_ready_retries=2" in get_version.detail


def test_response_not_ready_fails_after_configured_max_retry() -> None:
    attempts = 0

    def responder(pkt: Packet, dst_eid: int, msg_type: MsgTypes | None) -> Packet | None:
        nonlocal attempts
        if msg_type is None:
            return _msg_type_response([int(MsgTypes.CTRL), int(MsgTypes.SPDM)])
        if pkt[SpdmHdrPacket].request_response_code == SpdmRequestCode.GET_VERSION:
            attempts += 1
            return _spdm_response(
                SpdmResponseCode.ERROR,
                version=0x10,
                param1=SpdmErrorCode.RESPONSE_NOT_READY,
            )
        return _scripted_responder()(pkt, dst_eid, msg_type)

    behavior = SpdmRequesterBehavior(
        targets=[
            {
                "name": "rot",
                "eid": 0x1D,
                "full_attestation": False,
                "rsp_not_ready_max_retry": 2,
                "rsp_not_ready_max_duration_s": 0,
            }
        ],
        rsp_not_ready_max_retry=5,
    )
    _behavior_with_fake_am(behavior, responder)

    report = behavior.attest()

    assert report.ok is False
    assert attempts == 3
    assert report.failures()[0].name == "get-version"
    assert "spdm_error=0x42" in report.failures()[0].detail
    assert "rsp_not_ready_retries=2" in report.failures()[0].detail


def test_measurements_only_refresh_skips_digests_certificates_and_challenge() -> None:
    behavior = SpdmRequesterBehavior(targets=[{"name": "rot", "eid": 0x1D, "full_attestation": False}])
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder())

    report = behavior.attest()

    assert report.ok is True
    assert SpdmRequestCode.GET_DIGESTS not in _spdm_codes(session)
    assert SpdmRequestCode.GET_CERTIFICATE not in _spdm_codes(session)
    assert SpdmRequestCode.CHALLENGE not in _spdm_codes(session)


def test_measurement_indices_raw_bit_and_fixed_nonce_control_requests() -> None:
    behavior = SpdmRequesterBehavior(
        targets=[
            {
                "name": "rot",
                "eid": 0x1D,
                "full_attestation": False,
                "measurement_indices": [2, 3],
                "raw_bit_request": True,
            }
        ],
        nonce_provider=lambda: b"Z" * 32,
    )
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder())

    report = behavior.attest()

    measurement_requests = [pkt for pkt, *_ in session.spdm_sent if pkt.haslayer(GetMeasurementsPacket)]
    assert report.ok is True
    assert [(int(pkt.param1), int(pkt.param2)) for pkt in measurement_requests] == [(0x03, 2), (0x03, 3)]
    assert [pkt[GetMeasurementsPacket].nonce for pkt in measurement_requests] == [b"Z" * 32, b"Z" * 32]


def test_fixed_nonce_provider_makes_full_attestation_requests_deterministic() -> None:
    behavior = SpdmRequesterBehavior(targets=[{"name": "rot", "eid": 0x1D}], nonce_provider=lambda: b"Q" * 32)
    session, _, _ = _behavior_with_fake_am(behavior, _scripted_responder())

    report = behavior.attest()

    challenge = [pkt for pkt, *_ in session.spdm_sent if pkt.haslayer(ChallengePacket)][0]
    measurements = [pkt for pkt, *_ in session.spdm_sent if pkt.haslayer(GetMeasurementsPacket)][0]
    assert report.ok is True
    assert challenge[ChallengePacket].nonce == b"Q" * 32
    assert measurements[GetMeasurementsPacket].nonce == b"Q" * 32


def test_requester_drives_real_spdm_responder_end_to_end() -> None:
    chain = _cert_chain([24])
    requester_ctx = EndpointContext(
        physical_address=Smbus7bitAddress(0x20),
        assigned_eid=0x0C,
        supported_msg_types=[MsgTypes.CTRL, MsgTypes.SPDM],
    )
    responder_ctx = EndpointContext(
        physical_address=Smbus7bitAddress(0x30),
        assigned_eid=0x1D,
        mtu_size=4096,
        supported_msg_types=[MsgTypes.CTRL, MsgTypes.SPDM],
    )
    responder_behavior = SpdmResponderBehavior(
        profile=SpdmResponderProfile(
            cert_chains={0: chain},
            measurements={1: b"measurement"},
            nonce_provider=lambda: b"R" * 32,
        )
    )
    responder_behavior.on_attach(responder_ctx)

    def forwarder(pkt: Packet, dst_eid: int, msg_type: MsgTypes | None) -> Packet | None:
        if msg_type is None:
            return _msg_type_response([int(MsgTypes.CTRL), int(MsgTypes.SPDM)])
        request = SmbusTransport(
            dst_addr=responder_ctx.physical_address,
            src_addr=requester_ctx.physical_address,
            load=TransportHdr(
                msg_type=MsgTypes.SPDM,
                dst=dst_eid,
                src=requester_ctx.eid,
                som=True,
                eom=True,
                to=True,
                tag=3,
            )
            / pkt,
        )
        response = responder_behavior.handle(SmbusTransport(bytes(request)), responder_ctx)
        assert response is not None
        assert response.reply is not None
        reply = response.reply[0] if hasattr(response.reply, "__getitem__") else response.reply
        return SmbusTransport(bytes(reply))

    requester = SpdmRequesterBehavior(
        targets=[{"name": "rot", "eid": 0x1D}],
        nonce_provider=lambda: b"Q" * 32,
    )
    session = FakeSession(forwarder)
    requester.on_attach(requester_ctx)
    requester._am = FakeAM(session, requester_ctx)
    requester._ctx = requester_ctx

    report = requester.attest()

    assert report.ok is True
    assert report.certificate_chain == chain
    assert report.certificate_chain
