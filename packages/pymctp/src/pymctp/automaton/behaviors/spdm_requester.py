# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""SPDM requester behavior for driving attestation against MCTP endpoints."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, fields
import logging
import os
import struct
import threading
import time
from typing import TYPE_CHECKING, Any

from scapy.packet import Packet

from ...layers.mctp.control import ControlHdrPacket, GetMessageTypeSupport, GetMessageTypeSupportResponsePacket
from ...layers.mctp.control.types import CompletionCodes
from ...layers.mctp.spdm import (
    AlgorithmsPacket,
    CapabilitiesPacket,
    CertificatePacket,
    ChallengeAuthPacket,
    ChallengePacket,
    DigestsPacket,
    GetCapabilitiesPacket,
    GetCertificatePacket,
    GetDigestsPacket,
    GetMeasurementsPacket,
    GetVersionPacket,
    MeasurementsPacket,
    NegotiateAlgorithmsPacket,
    SpdmHdr,
    SpdmHdrPacket,
    VersionPacket,
)
from ...layers.mctp.spdm.types import SpdmErrorCode, SpdmRequestCode, SpdmResponseCode
from ...layers.mctp.types import EndpointContext, MsgTypes, Smbus7bitAddress
from ..sessions import HandlerResponse
from .base import Behavior

if TYPE_CHECKING:
    from ..role_endpoint import RoleBasedEndpointAM

logger = logging.getLogger(__name__)

_SPDM_MESSAGE_TYPE = int(MsgTypes.SPDM)
_SPDM_NONCE_SIZE = 32


@dataclass
class SpdmAttestationTarget:
    """One SPDM-capable endpoint to attest."""

    name: str
    eid: int | None = None
    vendor_id: int | None = None
    device_id: int | None = None
    subsystem_vendor_id: int | None = None
    subsystem_device_id: int | None = None
    instance: int = 0
    physical_address: int | None = None
    slot_id: int = 0
    measurement_indices: list[int] = field(default_factory=lambda: [1])
    raw_bit_request: bool = False
    full_attestation: bool = True
    success_retry_s: float | None = None
    fail_retry_s: float | None = None
    discovery_fail_retry_s: float | None = None
    mctp_bridge_additional_timeout_s: float = 0.0
    rsp_not_ready_max_retry: int | None = None
    rsp_not_ready_max_duration_s: float | None = None
    max_cert_chunk_size: int | None = None


@dataclass
class AttestationStep:
    """One request/response in an SPDM attestation run."""

    name: str
    target: str
    ok: bool
    detail: str = ""
    response: Any = None


@dataclass
class AttestationReport:
    """SPDM attestation result for one target."""

    steps: list[AttestationStep] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    negotiated_version: int | None = None
    negotiated_base_hash_algo: int | None = None
    negotiated_base_asym_algo: int | None = None
    negotiated_data_transfer_size: int | None = None
    certificate_chain: bytes | None = None
    resolved_eid: int | None = None
    skipped: bool = False
    target_name: str | None = None

    @property
    def ok(self) -> bool:
        """True when every recorded attestation step succeeded."""
        return all(step.ok for step in self.steps)

    def failures(self) -> list[AttestationStep]:
        """Return failed attestation steps."""
        return [step for step in self.steps if not step.ok]

    def __str__(self) -> str:
        """Return a readable multi-line step summary."""
        return "\n".join(
            f"{'OK' if step.ok else 'FAIL'} {step.target}: {step.name}"
            f"{f' - {step.detail}' if step.detail else ''}"
            for step in self.steps
        )


#: Called with each completed AttestationReport. Never raises into the requester.
#: Listeners run on the thread that produced the report and must be thread-safe.
AttestationListener = Callable[[AttestationReport], None]


@dataclass
class SpdmRequesterProfile:
    """Requester-side SPDM policy and defaults."""

    supported_versions: list[int] = field(default_factory=lambda: [0x10, 0x11, 0x12])
    ct_exponent: int = 0x1F
    flags: int = 0x00000000
    data_transfer_size: int = 0x1000
    max_spdm_msg_size: int = 0x1000
    measurement_specification: int = 0x01
    base_hash_algo: int = 0x02
    base_asym_algo: int = 0x190
    challenge_hash_type: int = 0xFF
    cert_chain_header_size: int | None = None
    der_probe_size: int = 0x07
    max_cert_chunk_size: int = 0x300
    nonce_provider: Callable[[], bytes] | None = None
    check_message_type_support: bool = True
    initial_delay_s: float = 30.0
    success_retry_s: float = 180.0
    fail_retry_s: float = 60.0
    discovery_fail_retry_s: float = 30.0
    rsp_not_ready_max_retry: int = 3
    rsp_not_ready_max_duration_s: float = 1.0

    def __post_init__(self) -> None:
        self.supported_versions = [int(version) for version in self.supported_versions]


EidResolver = Callable[[SpdmAttestationTarget], int | None]


class SpdmRequesterBehavior(Behavior):
    """Initiates scheduled SPDM attestation against configured targets.

    SPDM ERROR/RESPONSE_NOT_READY is handled with a bounded re-send of the same
    request rather than RESPOND_IF_READY so tests can exercise timing without
    adding a fuller SPDM deferred-response state machine.
    """

    def __init__(
        self,
        *,
        targets: list[SpdmAttestationTarget] | list[dict] | None = None,
        profile: SpdmRequesterProfile | dict[str, Any] | None = None,
        eid_resolver: EidResolver | None = None,
        auto_attest: bool = False,
        start_delay_s: float = 0.5,
        timeout_s: float = 2.0,
        retries: int = 1,
        time_source: Callable[[], float] = time.monotonic,
        **overrides: Any,
    ) -> None:
        base_profile = self._coerce_profile(profile)
        if overrides:
            profile_fields = {item.name for item in fields(SpdmRequesterProfile)}
            unknown = sorted(set(overrides) - profile_fields)
            if unknown:
                msg = f"Unknown SPDM requester profile option(s): {', '.join(unknown)}"
                raise TypeError(msg)
            data = {item.name: getattr(base_profile, item.name) for item in fields(SpdmRequesterProfile)}
            data.update(overrides)
            base_profile = SpdmRequesterProfile(**data)

        self._targets = [self._coerce_target(target) for target in (targets or [])]
        self.profile = base_profile
        self._eid_resolver = eid_resolver
        self.auto_attest = auto_attest
        self.start_delay_s = start_delay_s
        self.timeout_s = timeout_s
        self.retries = retries
        self._time_source = time_source

        self._am: RoleBasedEndpointAM | None = None
        self._ctx: EndpointContext | None = None
        self._reports: dict[str, AttestationReport] = {}
        self._last_reports: list[AttestationReport] = []
        self._report_listeners: list[AttestationListener] = []
        self._shutdown_event = threading.Event()
        self._request_event = threading.Event()
        self._condition = threading.Condition()
        self._worker: threading.Thread | None = None
        self._sweep_generation = 0
        self._pending_timeout_s: float | None = None
        self._pending_target: SpdmAttestationTarget | None = None
        self._pending_all = False
        self._schedule: dict[str, float] = {}
        self._last_rsp_not_ready_retries = 0

    @property
    def name(self) -> str:
        return "spdm-requester"

    @property
    def reports(self) -> dict[str, AttestationReport]:
        """Most recent attestation reports keyed by target name."""
        return dict(self._reports)

    def add_report_listener(self, listener: AttestationListener) -> None:
        """Register a completed-report listener.

        Listeners are invoked synchronously on whichever thread produced the report,
        so scheduler callbacks run on the scheduler worker and listeners must be
        thread-safe.
        """
        with self._condition:
            self._report_listeners.append(listener)

    def remove_report_listener(self, listener: AttestationListener) -> None:
        """Remove a completed-report listener if it is registered."""
        with self._condition:
            try:
                self._report_listeners.remove(listener)
            except ValueError:
                pass

    @property
    def report_listeners(self) -> list[AttestationListener]:
        """Registered completed-report listeners in invocation order."""
        with self._condition:
            return list(self._report_listeners)

    def add_target(self, target: SpdmAttestationTarget | dict) -> None:
        """Add an SPDM attestation target."""
        self._targets.append(self._coerce_target(target))

    def set_eid_resolver(self, resolver: EidResolver | None) -> None:
        """Set or clear the runtime EID resolver used before each attestation."""
        self._eid_resolver = resolver

    def next_attempt_at(self, target_name: str) -> float | None:
        """Return the monotonic deadline for a target's next scheduled attempt."""
        with self._condition:
            return self._schedule.get(target_name)

    def schedule(self) -> dict[str, float]:
        """Return the current per-target monotonic attestation schedule."""
        with self._condition:
            return dict(self._schedule)

    def attest_now(self, target_name: str | None = None) -> None:
        """Clear scheduled deadline(s) and kick the scheduler worker."""
        now = self._time_source()
        names = [target.name for target in self._targets] if target_name is None else [target_name]
        with self._condition:
            for name in names:
                self._schedule[name] = now
        self._request_event.set()

    def on_attach(self, ctx: EndpointContext) -> None:
        self._ctx = ctx

    def on_bind(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        self._am = am
        self._ctx = ctx

    def on_start(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        self._am = am
        self._ctx = ctx
        if not self.auto_attest:
            return
        if self._worker and self._worker.is_alive():
            self._request_event.set()
            return

        self._shutdown_event.clear()
        now = self._time_source()
        with self._condition:
            for target in self._targets:
                self._schedule.setdefault(target.name, now + self.profile.initial_delay_s)
        self._worker = threading.Thread(target=self._worker_main, name=f"mctp-spdm-requester-{ctx.eid}", daemon=True)
        self._worker.start()

    def on_stop(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        self._shutdown_event.set()
        self._request_event.set()
        worker = self._worker
        if worker and worker.is_alive():
            worker.join(timeout=2.0)
        if worker and not worker.is_alive():
            self._worker = None

    def can_handle(self, pkt: Packet, ctx: EndpointContext) -> bool:
        return False

    def handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse | None:
        return None

    def attest(
        self,
        target: SpdmAttestationTarget | dict | str | int | None = None,
        *,
        timeout_s: float | None = None,
        block: bool = True,
    ) -> AttestationReport:
        """Run attestation for one target."""
        resolved = self._resolve_target(target)
        worker = self._worker
        if not worker or not worker.is_alive():
            if not block:
                return self._reports.get(resolved.name) or AttestationReport(steps=[], started_at=time.time())
            report = self._run_target_attestation(resolved, timeout_s=timeout_s)
            with self._condition:
                reports, listeners = self._record_reports_locked([report], [resolved])
            self._notify_report_listeners(reports, listeners)
            return report

        with self._condition:
            start_generation = self._sweep_generation
        self._request_worker_attestation(target=resolved, timeout_s=timeout_s)
        if not block:
            return self._reports.get(resolved.name) or AttestationReport(steps=[], started_at=time.time())

        with self._condition:
            while self._sweep_generation == start_generation and worker.is_alive() and not self._shutdown_event.is_set():
                self._condition.wait(timeout=0.1)
            return self._reports.get(resolved.name) or AttestationReport(steps=[], started_at=time.time())

    def attest_all(self, *, timeout_s: float | None = None) -> list[AttestationReport]:
        """Run attestation for all configured targets."""
        worker = self._worker
        if not worker or not worker.is_alive():
            reports = self._run_all_attestations(timeout_s=timeout_s)
            with self._condition:
                reports_to_notify, listeners = self._record_reports_locked(reports, list(self._targets))
            self._notify_report_listeners(reports_to_notify, listeners)
            return reports

        with self._condition:
            start_generation = self._sweep_generation
        self._request_worker_attestation(timeout_s=timeout_s, all_targets=True)
        with self._condition:
            while self._sweep_generation == start_generation and worker.is_alive() and not self._shutdown_event.is_set():
                self._condition.wait(timeout=0.1)
            return list(self._last_reports)

    @staticmethod
    def _coerce_target(target: SpdmAttestationTarget | dict) -> SpdmAttestationTarget:
        if isinstance(target, SpdmAttestationTarget):
            return target
        return SpdmAttestationTarget(**target)

    @staticmethod
    def _coerce_profile(profile: SpdmRequesterProfile | dict[str, Any] | None) -> SpdmRequesterProfile:
        if profile is None:
            return SpdmRequesterProfile()
        if isinstance(profile, SpdmRequesterProfile):
            return profile
        return SpdmRequesterProfile(**profile)

    def _resolve_target(self, target: SpdmAttestationTarget | dict | str | int | None) -> SpdmAttestationTarget:
        if isinstance(target, (SpdmAttestationTarget, dict)):
            return self._coerce_target(target)
        if target is None:
            if not self._targets:
                msg = "no SPDM attestation targets configured"
                raise ValueError(msg)
            return self._targets[0]
        for candidate in self._targets:
            if candidate.name == target or candidate.eid == target:
                return candidate
        msg = f"unknown SPDM attestation target: {target!r}"
        raise ValueError(msg)

    def _request_worker_attestation(
        self,
        *,
        target: SpdmAttestationTarget | None = None,
        timeout_s: float | None = None,
        all_targets: bool = False,
    ) -> None:
        with self._condition:
            self._pending_target = target
            self._pending_all = all_targets
            if timeout_s is not None:
                self._pending_timeout_s = timeout_s
        self._request_event.set()

    def _worker_main(self) -> None:
        while not self._shutdown_event.is_set():
            with self._condition:
                timeout_s = self._pending_timeout_s
                target = self._pending_target
                all_targets = self._pending_all
                self._pending_timeout_s = None
                self._pending_target = None
                self._pending_all = False
                due_targets = self._due_targets_locked()
                wait_s = self._next_wait_s_locked()

            if not all_targets and target is None and not due_targets:
                self._request_event.wait(timeout=wait_s)
                self._request_event.clear()
                continue

            targets = list(self._targets) if all_targets else ([target] if target is not None else due_targets)
            reports = self._run_targets_safely(targets, timeout_s=timeout_s)
            with self._condition:
                reports_to_notify, listeners = self._record_reports_locked(reports, targets)
            self._notify_report_listeners(reports_to_notify, listeners)

    def _due_targets_locked(self) -> list[SpdmAttestationTarget]:
        now = self._time_source()
        return [target for target in self._targets if self._schedule.get(target.name, now) <= now]

    def _next_wait_s_locked(self) -> float | None:
        if not self._schedule:
            return None
        now = self._time_source()
        return max(0.0, min(self._schedule.values()) - now)

    def _run_targets_safely(
        self,
        targets: list[SpdmAttestationTarget],
        *,
        timeout_s: float | None = None,
    ) -> list[AttestationReport]:
        reports: list[AttestationReport] = []
        for target in targets:
            if self._shutdown_event.is_set():
                break
            try:
                reports.append(self._run_target_attestation(target, timeout_s=timeout_s))
            except Exception as exc:
                logger.exception("SPDM attestation failed for target %s", target.name)
                reports.append(
                    AttestationReport(
                        target_name=target.name,
                        steps=[AttestationStep("target-attestation", target.name, False, str(exc))],
                        started_at=time.time(),
                        finished_at=time.time(),
                    )
                )
        return reports

    def _record_reports_locked(
        self,
        reports: list[AttestationReport],
        targets: list[SpdmAttestationTarget],
    ) -> tuple[list[AttestationReport], list[AttestationListener]]:
        for target, report in zip(targets, reports):
            self._reports[target.name] = report
            self._schedule[target.name] = self._time_source() + self._retry_interval_s(target, report)
        self._last_reports = reports
        self._sweep_generation += 1
        self._condition.notify_all()
        return list(reports), list(self._report_listeners)

    def _notify_report_listeners(
        self,
        reports: list[AttestationReport],
        listeners: list[AttestationListener],
    ) -> None:
        if not listeners:
            return
        for report in reports:
            for listener in listeners:
                try:
                    listener(report)
                except Exception:
                    logger.exception("SPDM attestation report listener failed for target %s", report.target_name)

    def _retry_interval_s(self, target: SpdmAttestationTarget, report: AttestationReport) -> float:
        if self._is_discovery_failure(report):
            return self._target_or_profile_float(target.discovery_fail_retry_s, self.profile.discovery_fail_retry_s)
        if report.ok and not report.skipped:
            return self._target_or_profile_float(target.success_retry_s, self.profile.success_retry_s)
        if report.skipped:
            return self._target_or_profile_float(target.discovery_fail_retry_s, self.profile.discovery_fail_retry_s)
        return self._target_or_profile_float(target.fail_retry_s, self.profile.fail_retry_s)

    @staticmethod
    def _is_discovery_failure(report: AttestationReport) -> bool:
        if not report.steps:
            return False
        first = report.steps[0]
        return first.name == "resolve-eid" and (report.skipped or not first.ok)

    @staticmethod
    def _target_or_profile_float(target_value: float | None, profile_value: float) -> float:
        return profile_value if target_value is None else float(target_value)

    @staticmethod
    def _target_or_profile_int(target_value: int | None, profile_value: int) -> int:
        return profile_value if target_value is None else int(target_value)

    def _run_all_attestations(self, timeout_s: float | None = None) -> list[AttestationReport]:
        return self._run_targets_safely(list(self._targets), timeout_s=timeout_s)

    def _run_target_attestation(
        self,
        target: SpdmAttestationTarget,
        *,
        timeout_s: float | None = None,
    ) -> AttestationReport:
        report = AttestationReport(target_name=target.name, started_at=time.time())
        timeout = (self.timeout_s if timeout_s is None else timeout_s) + target.mctp_bridge_additional_timeout_s

        try:
            resolved_eid = self._resolve_eid_for_attestation(report, target)
            if not resolved_eid:
                return report

            target_phy_addr = self._target_phy_addr(target)
            if self.profile.check_message_type_support and not self._check_message_type_support(
                report,
                target,
                target_phy_addr,
                timeout,
            ):
                return report

            version = self._get_version(report, target, target_phy_addr, timeout)
            if version is None:
                return report
            report.negotiated_version = version

            if not self._get_capabilities(report, target, target_phy_addr, timeout, version):
                return report
            if not self._negotiate_algorithms(report, target, target_phy_addr, timeout, version):
                return report

            if target.full_attestation:
                if not self._get_digests(report, target, target_phy_addr, timeout, version):
                    return report
                certificate_chain = self._get_certificate_chain(report, target, target_phy_addr, timeout, version)
                if certificate_chain is None:
                    return report
                report.certificate_chain = certificate_chain
                if not self._challenge(report, target, target_phy_addr, timeout, version):
                    return report

            self._get_measurements(report, target, target_phy_addr, timeout, version)
        finally:
            report.finished_at = time.time()

        return report

    def _resolve_eid_for_attestation(
        self,
        report: AttestationReport,
        target: SpdmAttestationTarget,
    ) -> int | None:
        resolver = self._eid_resolver
        if resolver is not None:
            try:
                resolved = resolver(target)
            except Exception as exc:
                logger.exception("SPDM EID resolver failed for target %s", target.name)
                report.steps.append(AttestationStep("resolve-eid", target.name, False, f"resolver error: {exc}"))
                return None

            eid = int(resolved or 0)
            report.resolved_eid = eid
            if eid == 0:
                report.skipped = True
                report.steps.append(AttestationStep("resolve-eid", target.name, True, "device absent (eid=0)"))
                return None

            target.eid = eid
            report.steps.append(AttestationStep("resolve-eid", target.name, True, f"eid=0x{eid:02X}"))
            return eid

        if target.eid:
            report.resolved_eid = int(target.eid)
            return int(target.eid)

        report.steps.append(AttestationStep("resolve-eid", target.name, False, "no EID resolved for target"))
        return None

    def _check_message_type_support(
        self,
        report: AttestationReport,
        target: SpdmAttestationTarget,
        target_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
    ) -> bool:
        rsp = self._send_control(
            GetMessageTypeSupport(),
            dst_eid=int(target.eid or 0),
            dst_phy_addr=target_phy_addr,
            timeout_s=timeout_s,
        )
        payload = self._payload(rsp, GetMessageTypeSupportResponsePacket)
        if rsp is None or not self._completion_ok(rsp) or payload is None:
            report.steps.append(AttestationStep("get-message-type-support", target.name, False, self._failure_detail(rsp), rsp))
            return False

        msg_types = [int(msg_type) for msg_type in payload.msg_type_list]
        detail = "msg_types=[%s]" % ", ".join(f"0x{msg_type:02X}" for msg_type in msg_types)
        ok = _SPDM_MESSAGE_TYPE in msg_types
        if not ok:
            detail += " missing SPDM(0x05)"
        report.steps.append(AttestationStep("get-message-type-support", target.name, ok, detail, rsp))
        return ok

    def _get_version(
        self,
        report: AttestationReport,
        target: SpdmAttestationTarget,
        target_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
    ) -> int | None:
        pkt = SpdmHdr(spdm_version=0x10, request_response_code=SpdmRequestCode.GET_VERSION) / GetVersionPacket()
        rsp = self._send_spdm(pkt, target=target, dst_phy_addr=target_phy_addr, timeout_s=timeout_s)
        version_payload = self._payload(rsp, VersionPacket)
        if not self._spdm_ok(rsp, SpdmResponseCode.VERSION) or version_payload is None:
            report.steps.append(AttestationStep("get-version", target.name, False, self._spdm_failure_detail(rsp), rsp))
            return None

        response_versions = [_version_entry_to_byte(int(entry)) for entry in version_payload.version_number_list]
        mutual = sorted(set(response_versions) & set(self.profile.supported_versions))
        if not mutual:
            detail = "no mutually-supported version response=[%s] profile=[%s]" % (
                ", ".join(f"0x{version:02X}" for version in response_versions),
                ", ".join(f"0x{version:02X}" for version in self.profile.supported_versions),
            )
            report.steps.append(AttestationStep("get-version", target.name, False, detail, rsp))
            return None

        selected = mutual[-1]
        detail = "versions=[%s] selected=0x%02X" % (
            ", ".join(f"0x{version:02X}" for version in response_versions),
            selected,
        )
        report.steps.append(AttestationStep("get-version", target.name, True, self._with_rsp_retry_detail(detail), rsp))
        return selected

    def _get_capabilities(
        self,
        report: AttestationReport,
        target: SpdmAttestationTarget,
        target_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
        spdm_version: int,
    ) -> bool:
        payload = GetCapabilitiesPacket(
            ct_exponent=self.profile.ct_exponent,
            flags=self.profile.flags,
            data_transfer_size=self.profile.data_transfer_size,
            max_spdm_msg_size=self.profile.max_spdm_msg_size,
        )
        pkt = SpdmHdr(
            spdm_version=spdm_version,
            request_response_code=SpdmRequestCode.GET_CAPABILITIES,
        ) / payload
        rsp = self._send_spdm(pkt, target=target, dst_phy_addr=target_phy_addr, timeout_s=timeout_s)
        caps = self._payload(rsp, CapabilitiesPacket)
        ok = self._spdm_ok(rsp, SpdmResponseCode.CAPABILITIES) and caps is not None
        if ok and spdm_version >= 0x12:
            report.negotiated_data_transfer_size = _optional_int(getattr(caps, "data_transfer_size", None))
        detail = "version=0x%02X flags=0x%08X ct_exponent=0x%02X" % (
            spdm_version,
            self.profile.flags,
            self.profile.ct_exponent,
        )
        if spdm_version >= 0x12:
            detail += " data_transfer_size=0x%08X max_spdm_msg_size=0x%08X" % (
                self.profile.data_transfer_size,
                self.profile.max_spdm_msg_size,
            )
        report.steps.append(
            AttestationStep(
                "get-capabilities",
                target.name,
                ok,
                self._with_rsp_retry_detail(detail) if ok else self._spdm_failure_detail(rsp),
                rsp,
            )
        )
        return ok

    def _negotiate_algorithms(
        self,
        report: AttestationReport,
        target: SpdmAttestationTarget,
        target_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
        spdm_version: int,
    ) -> bool:
        pkt = SpdmHdr(spdm_version=spdm_version, request_response_code=SpdmRequestCode.NEGOTIATE_ALGORITHMS) / (
            NegotiateAlgorithmsPacket(
                length=32,
                measurement_specification=self.profile.measurement_specification,
                base_hash_algo=self.profile.base_hash_algo,
                base_asym_algo=self.profile.base_asym_algo,
            )
        )
        rsp = self._send_spdm(pkt, target=target, dst_phy_addr=target_phy_addr, timeout_s=timeout_s)
        algorithms = self._payload(rsp, AlgorithmsPacket)
        ok = self._spdm_ok(rsp, SpdmResponseCode.ALGORITHMS) and algorithms is not None
        if ok:
            report.negotiated_base_hash_algo = int(algorithms.base_hash_sel)
            report.negotiated_base_asym_algo = int(algorithms.base_asym_sel)
        detail = "meas_spec=0x%02X base_hash=0x%08X base_asym=0x%08X selected_hash=0x%08X selected_asym=0x%08X" % (
            self.profile.measurement_specification,
            self.profile.base_hash_algo,
            self.profile.base_asym_algo,
            report.negotiated_base_hash_algo or 0,
            report.negotiated_base_asym_algo or 0,
        )
        report.steps.append(
            AttestationStep(
                "negotiate-algorithms",
                target.name,
                ok,
                self._with_rsp_retry_detail(detail) if ok else self._spdm_failure_detail(rsp),
                rsp,
            )
        )
        return ok

    def _get_digests(
        self,
        report: AttestationReport,
        target: SpdmAttestationTarget,
        target_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
        spdm_version: int,
    ) -> bool:
        pkt = SpdmHdr(spdm_version=spdm_version, request_response_code=SpdmRequestCode.GET_DIGESTS) / GetDigestsPacket()
        rsp = self._send_spdm(pkt, target=target, dst_phy_addr=target_phy_addr, timeout_s=timeout_s)
        digests = self._payload(rsp, DigestsPacket)
        ok = self._spdm_ok(rsp, SpdmResponseCode.DIGESTS) and digests is not None
        detail = "version=0x%02X" % spdm_version
        report.steps.append(
            AttestationStep(
                "get-digests",
                target.name,
                ok,
                self._with_rsp_retry_detail(detail) if ok else self._spdm_failure_detail(rsp),
                rsp,
            )
        )
        return ok

    def _get_certificate_chain(
        self,
        report: AttestationReport,
        target: SpdmAttestationTarget,
        target_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
        spdm_version: int,
    ) -> bytes | None:
        header_size = self._cert_chain_header_size(report)
        if header_size is None:
            detail = "cannot derive certificate-chain header size from negotiated hash"
            report.steps.append(AttestationStep("get-certificate", target.name, False, detail))
            return None
        max_read_len = self._max_cert_read_len(target, report, spdm_version)
        header = self._get_certificate_portion(
            report,
            target,
            target_phy_addr,
            timeout_s,
            spdm_version,
            0,
            header_size,
        )
        if header is None:
            return None
        if len(header) < 4:
            report.steps.append(AttestationStep("get-certificate", target.name, False, "certificate header too short"))
            return None

        total_length = struct.unpack_from("<I", header, 0)[0]
        if total_length < header_size:
            detail = f"invalid total chain length 0x{total_length:04X}"
            report.steps.append(AttestationStep("get-certificate", target.name, False, detail))
            return None

        chain = bytearray(header)
        cursor = header_size
        while cursor < total_length:
            probe = self._get_certificate_portion(
                report,
                target,
                target_phy_addr,
                timeout_s,
                spdm_version,
                cursor,
                self.profile.der_probe_size,
            )
            if probe is None:
                return None
            if len(probe) < 4 or probe[0] != 0x30 or probe[1] != 0x82:
                detail = f"invalid DER certificate header at offset=0x{cursor:04X}"
                report.steps.append(AttestationStep("get-certificate", target.name, False, detail))
                return None

            cert_length = 4 + int.from_bytes(probe[2:4], "big")
            if cert_length < self.profile.der_probe_size:
                detail = f"invalid DER certificate length 0x{cert_length:04X} at offset=0x{cursor:04X}"
                report.steps.append(AttestationStep("get-certificate", target.name, False, detail))
                return None
            if cursor + cert_length > total_length:
                detail = "DER certificate overruns chain length offset=0x%04X cert_length=0x%04X total=0x%04X" % (
                    cursor,
                    cert_length,
                    total_length,
                )
                report.steps.append(AttestationStep("get-certificate", target.name, False, detail))
                return None

            chain.extend(probe)
            body_cursor = cursor + self.profile.der_probe_size
            remaining = cert_length - self.profile.der_probe_size
            while remaining > 0:
                read_len = min(remaining, max_read_len)
                chunk = self._get_certificate_portion(
                    report,
                    target,
                    target_phy_addr,
                    timeout_s,
                    spdm_version,
                    body_cursor,
                    read_len,
                )
                if chunk is None:
                    return None
                chain.extend(chunk)
                body_cursor += read_len
                remaining -= read_len
            cursor += cert_length

        certificate_chain = bytes(chain[:total_length])
        report.steps.append(
            AttestationStep(
                "certificate-chain",
                target.name,
                len(certificate_chain) == total_length,
                f"length=0x{total_length:04X}",
            )
        )
        return certificate_chain

    def _cert_chain_header_size(self, report: AttestationReport) -> int | None:
        if self.profile.cert_chain_header_size is not None:
            return int(self.profile.cert_chain_header_size)
        hash_size = _hash_size_for_algo(report.negotiated_base_hash_algo)
        if hash_size is None:
            return None
        return 4 + hash_size

    def _max_cert_read_len(
        self,
        target: SpdmAttestationTarget,
        report: AttestationReport,
        spdm_version: int,
    ) -> int:
        max_read_len = self._target_or_profile_int(target.max_cert_chunk_size, self.profile.max_cert_chunk_size)
        if spdm_version >= 0x12 and report.negotiated_data_transfer_size:
            max_read_len = min(max_read_len, int(report.negotiated_data_transfer_size))
        return max(1, max_read_len)

    def _get_certificate_portion(
        self,
        report: AttestationReport,
        target: SpdmAttestationTarget,
        target_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
        spdm_version: int,
        offset: int,
        length: int,
    ) -> bytes | None:
        pkt = SpdmHdr(
            spdm_version=spdm_version,
            request_response_code=SpdmRequestCode.GET_CERTIFICATE,
            param1=target.slot_id & 0x0F,
        ) / GetCertificatePacket(offset=offset, length=length)
        rsp = self._send_spdm(pkt, target=target, dst_phy_addr=target_phy_addr, timeout_s=timeout_s)
        certificate = self._payload(rsp, CertificatePacket)
        ok = self._spdm_ok(rsp, SpdmResponseCode.CERTIFICATE) and certificate is not None
        detail = f"slot=0x{target.slot_id:02X} offset=0x{offset:04X} length=0x{length:04X}"
        if not ok:
            report.steps.append(AttestationStep("get-certificate", target.name, False, self._spdm_failure_detail(rsp), rsp))
            return None

        portion = bytes(certificate.payload)
        detail += " portion=0x%04X remainder=0x%04X" % (int(certificate.portion_length), int(certificate.remainder_length))
        if len(portion) != int(certificate.portion_length):
            report.steps.append(AttestationStep("get-certificate", target.name, False, detail + " malformed portion", rsp))
            return None

        report.steps.append(AttestationStep("get-certificate", target.name, True, self._with_rsp_retry_detail(detail), rsp))
        return portion

    def _challenge(
        self,
        report: AttestationReport,
        target: SpdmAttestationTarget,
        target_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
        spdm_version: int,
    ) -> bool:
        nonce = self._nonce()
        pkt = SpdmHdr(
            spdm_version=spdm_version,
            request_response_code=SpdmRequestCode.CHALLENGE,
            param1=target.slot_id,
            param2=self.profile.challenge_hash_type,
        ) / ChallengePacket(nonce=nonce)
        rsp = self._send_spdm(pkt, target=target, dst_phy_addr=target_phy_addr, timeout_s=timeout_s)
        challenge = self._payload(rsp, ChallengeAuthPacket)
        ok = self._spdm_ok(rsp, SpdmResponseCode.CHALLENGE_AUTH) and challenge is not None
        detail = "slot=0x%02X hash_type=0x%02X nonce=%s" % (
            target.slot_id,
            self.profile.challenge_hash_type,
            nonce.hex(),
        )
        report.steps.append(
            AttestationStep(
                "challenge",
                target.name,
                ok,
                self._with_rsp_retry_detail(detail) if ok else self._spdm_failure_detail(rsp),
                rsp,
            )
        )
        return ok

    def _get_measurements(
        self,
        report: AttestationReport,
        target: SpdmAttestationTarget,
        target_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
        spdm_version: int,
    ) -> bool:
        attributes = 0x03 if target.raw_bit_request else 0x01
        for index in target.measurement_indices:
            nonce = self._nonce()
            pkt = SpdmHdr(
                spdm_version=spdm_version,
                request_response_code=SpdmRequestCode.GET_MEASUREMENTS,
                param1=attributes,
                param2=index,
            ) / GetMeasurementsPacket(nonce=nonce, slot_id_param=target.slot_id)
            rsp = self._send_spdm(pkt, target=target, dst_phy_addr=target_phy_addr, timeout_s=timeout_s)
            measurements = self._payload(rsp, MeasurementsPacket)
            ok = self._spdm_ok(rsp, SpdmResponseCode.MEASUREMENTS) and measurements is not None
            detail = "attributes=0x%02X index=0x%02X slot=0x%02X nonce=%s" % (
                attributes,
                index,
                target.slot_id,
                nonce.hex(),
            )
            report.steps.append(
                AttestationStep(
                    "get-measurements",
                    target.name,
                    ok,
                    self._with_rsp_retry_detail(detail) if ok else self._spdm_failure_detail(rsp),
                    rsp,
                )
            )
            if not ok:
                return False
        return True

    def _send_control(
        self,
        pkt: Packet,
        *,
        dst_eid: int,
        dst_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
    ) -> Packet | None:
        if self._am is None:
            msg = "SPDM requester behavior is not attached to an answering machine"
            raise RuntimeError(msg)

        response: Packet | None = None
        for _ in range(self.retries + 1):
            if self._shutdown_event.is_set():
                return None
            response = self._am.session.sndrcv_control_msg(
                pkt,
                dst_eid=dst_eid,
                dst_phy_addr=dst_phy_addr,
                timeout_s=timeout_s,
                threaded=True,
            )
            if response is not None:
                return response
        return response

    def _send_spdm(
        self,
        pkt: Packet,
        *,
        target: SpdmAttestationTarget,
        dst_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
    ) -> Packet | None:
        if self._am is None:
            msg = "SPDM requester behavior is not attached to an answering machine"
            raise RuntimeError(msg)

        response: Packet | None = None
        self._last_rsp_not_ready_retries = 0
        rsp_not_ready_retries = 0
        max_rsp_not_ready_retries = self._target_or_profile_int(
            target.rsp_not_ready_max_retry,
            self.profile.rsp_not_ready_max_retry,
        )
        rsp_not_ready_wait_s = self._target_or_profile_float(
            target.rsp_not_ready_max_duration_s,
            self.profile.rsp_not_ready_max_duration_s,
        )
        for _ in range(self.retries + 1):
            if self._shutdown_event.is_set():
                return None
            response = self._am.session.sndrcv_mctp_msg(
                pkt,
                dst_eid=int(target.eid or 0),
                msg_type=MsgTypes.SPDM,
                dst_phy_addr=dst_phy_addr,
                timeout_s=timeout_s,
                threaded=True,
            )
            while (
                self._is_response_not_ready(response)
                and rsp_not_ready_retries < max_rsp_not_ready_retries
                and not self._shutdown_event.is_set()
            ):
                rsp_not_ready_retries += 1
                self._last_rsp_not_ready_retries = rsp_not_ready_retries
                if rsp_not_ready_wait_s > 0 and self._shutdown_event.wait(timeout=rsp_not_ready_wait_s):
                    return None
                response = self._am.session.sndrcv_mctp_msg(
                    pkt,
                    dst_eid=int(target.eid or 0),
                    msg_type=MsgTypes.SPDM,
                    dst_phy_addr=dst_phy_addr,
                    timeout_s=timeout_s,
                    threaded=True,
                )
            if response is not None:
                return response
        return response

    @staticmethod
    def _target_phy_addr(target: SpdmAttestationTarget) -> Smbus7bitAddress | None:
        if target.physical_address is None:
            return None
        return Smbus7bitAddress(target.physical_address)

    @staticmethod
    def _payload(pkt: Packet | None, layer_cls: type[Packet]) -> Any | None:
        if pkt is None:
            return None
        if isinstance(pkt, layer_cls):
            return pkt
        if pkt.haslayer(layer_cls):
            return pkt.getlayer(layer_cls)
        return None

    @staticmethod
    def _completion_ok(pkt: Packet) -> bool:
        if not pkt.haslayer(ControlHdrPacket):
            return True
        ctrl: ControlHdrPacket = pkt.getlayer(ControlHdrPacket)
        return int(ctrl.completion_code) == int(CompletionCodes.SUCCESS)

    @staticmethod
    def _spdm_ok(pkt: Packet | None, expected_code: SpdmResponseCode) -> bool:
        spdm = _spdm_layer(pkt)
        return spdm is not None and int(spdm.request_response_code) == int(expected_code)

    @staticmethod
    def _is_response_not_ready(pkt: Packet | None) -> bool:
        spdm = _spdm_layer(pkt)
        return (
            spdm is not None
            and int(spdm.request_response_code) == int(SpdmResponseCode.ERROR)
            and int(spdm.param1) == int(SpdmErrorCode.RESPONSE_NOT_READY)
        )

    @staticmethod
    def _failure_detail(pkt: Packet | None) -> str:
        if pkt is None:
            return "timeout"
        if pkt.haslayer(ControlHdrPacket):
            ctrl: ControlHdrPacket = pkt.getlayer(ControlHdrPacket)
            try:
                return f"completion_code={CompletionCodes(int(ctrl.completion_code)).name}"
            except ValueError:
                return f"completion_code=0x{int(ctrl.completion_code):02X}"
        return "missing response payload"

    def _spdm_failure_detail(self, pkt: Packet | None) -> str:
        spdm = _spdm_layer(pkt)
        if pkt is None:
            return self._with_rsp_retry_detail("timeout")
        if spdm is None:
            return self._with_rsp_retry_detail("missing SPDM response")
        if int(spdm.request_response_code) == int(SpdmResponseCode.ERROR):
            return self._with_rsp_retry_detail(f"spdm_error=0x{int(spdm.param1):02X} data=0x{int(spdm.param2):02X}")
        return self._with_rsp_retry_detail(f"unexpected_response=0x{int(spdm.request_response_code):02X}")

    def _with_rsp_retry_detail(self, detail: str) -> str:
        if self._last_rsp_not_ready_retries <= 0:
            return detail
        return f"{detail} rsp_not_ready_retries={self._last_rsp_not_ready_retries}"

    def _nonce(self) -> bytes:
        provider = self.profile.nonce_provider
        nonce = os.urandom(_SPDM_NONCE_SIZE) if provider is None else bytes(provider())
        return nonce[:_SPDM_NONCE_SIZE].ljust(_SPDM_NONCE_SIZE, b"\x00")


def _spdm_layer(pkt: Packet | None) -> SpdmHdrPacket | None:
    if pkt is None:
        return None
    if isinstance(pkt, SpdmHdrPacket):
        return pkt
    if pkt.haslayer(SpdmHdrPacket):
        return pkt.getlayer(SpdmHdrPacket)
    return None


def _version_entry_to_byte(entry: int) -> int:
    if entry <= 0xFF:
        return entry
    return (((entry >> 12) & 0x0F) << 4) | ((entry >> 8) & 0x0F)


def _hash_size_for_algo(algo: int | None) -> int | None:
    return {
        0x00000001: 32,
        0x00000002: 48,
        0x00000004: 64,
    }.get(int(algo or 0))


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)
