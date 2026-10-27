"""Coherent source simulation, not a live admission or provider factory.

Only ProductionCoordinator is public. _SourceCoordinator composes the real
SQLite adapter and final same-executor guard with explicitly synthetic fixtures.
It has no signing/network/SDK port. Observations are not provider requests.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from .sqlite_store import Job, NativeSQLiteStore, Conflict, integer


class Unavailable(Exception):
    pass


class ProductionCoordinator:
    """No argument/config/callback can manufacture a positive live factory."""
    async def enroll(self, *_args, **_kwargs):
        raise Unavailable("management/native/clock/store/role/policy providers unqualified")

    async def submit(self, *_args, **_kwargs):
        raise Unavailable("new native protocol and actual provider custody unavailable")


@dataclass(frozen=True)
class _SyntheticPolicy:
    operation_max_duration_ms: int
    device_enrollment_max_validity_ms: int
    child_max_validity_ms: int
    max_jobs: int
    max_children: int
    max_stage_reservations: int

    def __post_init__(self):
        for value in vars(self).values():
            integer(value)


@dataclass(frozen=True)
class _SyntheticAdmission:
    label: str
    job: Job
    clock_domain: str
    original_continuous_cutoff_ns: int
    required_inputs: frozenset[str]
    policy: _SyntheticPolicy
    original_issued_at_ms: int
    original_parent_issued_at_ms: int
    original_parent_expiry_ms: int


REQUIRED = frozenset({"principal", "pair_ack", "native_role", "custody", "store_restore",
                      "clock", "policy_lifetimes", "policy_counts", "provider"})


class _SourceCoordinator:
    """Private qualification composition. Never returns a native capability."""
    def __init__(self, store: NativeSQLiteStore, synthetic_clock):
        self.store, self.clock = store, synthetic_clock
        self._retired: set[str] = set()
        self._last_continuous = -1
        self._last_utc_upper = -1
        self.observations: list[dict] = []
        self._submission_handles: set[str] = set()

    def _guard(self, admission: _SyntheticAdmission):
        try:
            task = asyncio.current_task()
        except RuntimeError:
            task = None
        if task is not None and task.cancelling():
            raise asyncio.CancelledError()
        if (type(admission) is not _SyntheticAdmission or admission.label != "SYNTHETIC_SOURCE_QUALIFICATION"
                or admission.required_inputs != REQUIRED or type(admission.policy) is not _SyntheticPolicy):
            raise Unavailable("all qualification prerequisites required before writes")
        for value in (admission.original_issued_at_ms, admission.original_parent_issued_at_ms,
                      admission.original_parent_expiry_ms, admission.original_continuous_cutoff_ns):
            integer(value)
        if (not 0 < admission.job.deadline_ms - admission.original_issued_at_ms <= admission.policy.operation_max_duration_ms
                or not 0 < admission.original_parent_expiry_ms - admission.original_parent_issued_at_ms <= admission.policy.device_enrollment_max_validity_ms
                or admission.job.deadline_ms > admission.original_parent_expiry_ms):
            raise Unavailable("synthetic original policy bounds")
        continuous, utc = self.clock.continuous_ns(), self.clock.utc_upper_ms()
        if (type(continuous) is not int or type(utc) is not int
                or continuous < self._last_continuous or utc < self._last_utc_upper):
            self._retired.add(admission.job.parent_id)
            raise Unavailable("clock regression/uncertainty")
        self._last_continuous, self._last_utc_upper = continuous, utc
        if (admission.job.parent_id in self._retired or self.clock.domain != admission.clock_domain
                or continuous >= admission.original_continuous_cutoff_ns
                or utc >= admission.job.deadline_ms):
            self._retired.add(admission.job.parent_id)
            raise Unavailable("original deadline/domain/retirement fence")

    def retire(self, parent: str):
        self._retired.add(parent)  # Synchronous negative fence before any SQL/await.
        self.store.retire_parent(parent)

    def begin(self, admission: _SyntheticAdmission, operation: str, nonce: str):
        self._guard(admission)
        self.store.create_job_data(admission.job, operation, nonce, admission.policy.max_jobs)
        self._guard(admission)  # Late expiry suppresses result; never rolls commit back.

    async def step(self, admission: _SyntheticAdmission, stage: str, revision: int,
                   claim: str, operation: str, nonce: str, body_sha256: str,
                   prepare, counter=None):
        self._guard(admission)
        token = self.store.reserve_stage(admission.job, stage, revision, claim,
                                        operation, nonce, body_sha256, admission.policy.max_stage_reservations)
        try:
            self._guard(admission)
            await prepare()  # Explicit synthetic delay, never native/key/provider work.
            self._guard(admission)
            self.store.complete_stage(admission.job, token, counter)
            self._guard(admission)
            if stage == "submit":
                self._submission_handles.add(admission.job.job_id)
        except BaseException:
            # Local fence survives even if SQL settlement cannot be acknowledged.
            self._retired.add(admission.job.parent_id)
            try:
                self.store.retire_parent(admission.job.parent_id)
            except Exception:
                # No positive result. Actual committed state is not described as undone.
                pass
            raise
        return "SOURCE_QUALIFICATION_ONLY"

    def bind_child_data(self, admission: _SyntheticAdmission, child_id: str, revision: int,
                        original_issued_ms: int, original_expiry_ms: int, body: bytes):
        self._guard(admission)
        integer(original_issued_ms)
        integer(original_expiry_ms)
        if (not 0 < original_expiry_ms - original_issued_ms <= admission.policy.child_max_validity_ms
                or original_expiry_ms > admission.original_parent_expiry_ms
                or self.clock.utc_upper_ms() >= original_expiry_ms):
            raise Unavailable("synthetic original child bounds")
        self.store.bind_child_data(child_id, admission.job.parent_id, admission.job.parent_generation,
                                   revision, body, original_expiry_ms, admission.policy.max_children)
        self._guard(admission)
        if self.clock.utc_upper_ms() >= original_expiry_ms:
            raise Unavailable("child expired after actual commit; suppress result")

    def observe_final_boundary(self, admission: _SyntheticAdmission, build):
        if admission.job.job_id not in self._submission_handles:
            raise Conflict("no original in-process submission handle; never rehydrate")
        self._submission_handles.remove(admission.job.job_id)
        self._guard(admission)
        row = next((r for r in self.store.inspect_data("jobs") if r["job_id"] == admission.job.job_id), None)
        if row is None or row["phase"] != "SUBMIT_SPENT":
            raise Conflict("submission requires durable once-spent stage")
        # Local observation latch is consumed before synchronous construction.
        # A production sender is intentionally absent: this seam records DATA only.
        if any(o["job_id"] == admission.job.job_id for o in self.observations):
            raise Conflict("observation already spent")
        self.observations.append({"job_id": admission.job.job_id, "state": "SPENT"})
        payload = build()
        self._guard(admission)  # AFTER synchronous construction, no await/RPC hop.
        self.observations[-1]["state"] = "SOURCE_OBSERVATION_ONLY"
        return payload
