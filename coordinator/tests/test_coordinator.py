"""Actual local SQLite, synthetic authority/clock/delay, zero provider effects."""
import asyncio
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid

from djc_push_coordinator import ProductionCoordinator, Unavailable
from djc_push_coordinator.coordinator import _SourceCoordinator, _SyntheticAdmission, _SyntheticPolicy, REQUIRED
from djc_push_coordinator.sqlite_store import NativeSQLiteStore, Job, Conflict, UnknownCommit, Reservation
from djc_push_coordinator import wire
from djc_push_coordinator.clock import LinuxBootClock, ClockUnavailable

H = lambda s: hashlib.sha256(s.encode()).hexdigest()
U = lambda: str(uuid.uuid4())
CANON = lambda v: json.dumps(v, separators=(",", ":"), ensure_ascii=True).encode()


class SyntheticClock:
    domain = "SYNTHETIC_BOOT_NOT_REAL_UTC"
    continuous = 10
    utc = 10

    def continuous_ns(self):
        return self.continuous

    def utc_upper_ms(self):
        return self.utc


async def noop():
    pass


class StoreCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"])
        self.path = Path(self.tmp.name) / "qualification.sqlite"
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript((Path(__file__).parents[1] / "src/djc_push_coordinator/schema.sql").read_text())
        db.execute("INSERT INTO metadata VALUES(1,1,'SYNTHETIC_RESTORE')")
        db.commit()
        db.close()
        self.store = NativeSQLiteStore(self.path, "SYNTHETIC_RESTORE")
        self.parent = U()
        self.store.put_parent_data(self.parent, 1, "synthetic-pair", 1, "widget_transport", b'{"synthetic":true}', 150)
        self.job = Job(U(), self.parent, 1, "synthetic-pair", 1, H("context"), H("key-scope"), 100)
        self.clock = SyntheticClock()
        self.owner = _SourceCoordinator(self.store, self.clock)
        policy = _SyntheticPolicy(100, 200, 50, 5, 5, 10)
        self.admission = _SyntheticAdmission("SYNTHETIC_SOURCE_QUALIFICATION", self.job, self.clock.domain, 100,
                                             REQUIRED, policy, 1, 1, 150)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def begin(self):
        self.owner.begin(self.admission, U(), H(U()))

    async def stage(self, name, rev, counter=None, prepare=noop):
        return await self.owner.step(self.admission, name, rev, U(), U(), H(U()), H("body"), prepare, counter)

    async def complete_all(self):
        self.begin()
        await self.stage("prepare_key", 1)
        await self.stage("verify_key", 2, (H("key"), 0, None))
        await self.stage("prepare_target", 3)
        await self.stage("verify_target", 4, (H("key"), 1, 1))
        await self.stage("submit", 5)

    async def test_coherent_actual_sqlite_to_final_source_observation(self):
        await self.complete_all()
        self.assertEqual(self.owner.observe_final_boundary(self.admission, lambda: b"SYNTHETIC_PAYLOAD"), b"SYNTHETIC_PAYLOAD")
        self.assertEqual(self.store.inspect_data("key_counters")[0]["counter"], 1)
        self.assertEqual(self.store.inspect_data("jobs")[0]["phase"], "SUBMIT_SPENT")
        with self.assertRaises(Conflict):
            self.owner.observe_final_boundary(self.admission, lambda: b"retry")

    async def test_production_missing_before_open_or_effect(self):
        for method in (ProductionCoordinator().enroll, ProductionCoordinator().submit):
            with self.assertRaises(Unavailable):
                await method(database=self.path, enable=True, callback=lambda: self.fail("no callback"))
        self.assertEqual(self.store.inspect_data("jobs"), [])

    async def test_every_missing_prerequisite_before_job_nonce(self):
        for missing in REQUIRED:
            with self.subTest(missing=missing), self.assertRaises(Unavailable):
                self.owner.begin(replace(self.admission, required_inputs=REQUIRED - {missing}), U(), H(U()))
        for table in ("jobs", "operations", "nonces", "claims"):
            self.assertEqual(self.store.inspect_data(table), [])

    async def test_explicit_policy_no_null_bool_defaults_or_arrival_lease(self):
        for value in (None, True, 0, -1):
            with self.assertRaises(Conflict):
                _SyntheticPolicy(value, 200, 50, 5, 5, 10)
        with self.assertRaises(Unavailable):
            self.owner.begin(replace(self.admission, policy=replace(self.admission.policy, operation_max_duration_ms=10)), U(), H(U()))
        self.assertEqual(self.store.inspect_data("jobs"), [])

    async def test_domain_change_before_any_reservation(self):
        self.clock.domain = "other-boot"
        with self.assertRaises(Unavailable):
            self.begin()
        self.assertEqual(self.store.inspect_data("operations"), [])

    async def test_original_child_policy_and_atomic_count_caps(self):
        self.owner.bind_child_data(self.admission, U(), 1, 1, 40, b"SYNTHETIC_CHILD")
        with self.assertRaises(Unavailable):
            self.owner.bind_child_data(self.admission, U(), 1, 1, 60, b"SYNTHETIC_CHILD")
        with self.assertRaises(Unavailable):
            self.owner.bind_child_data(self.admission, U(), 1, 1, 5, b"EXPIRED")
        bounded = replace(self.admission, policy=replace(self.admission.policy, max_children=1))
        with self.assertRaises(Conflict):
            self.owner.bind_child_data(bounded, U(), 1, 1, 40, b"SYNTHETIC_CHILD")
        self.assertEqual(len(self.store.inspect_data("children")), 1)
        self.begin()
        bounded = replace(self.admission, job=replace(self.job, job_id=U()), policy=replace(self.admission.policy, max_jobs=1))
        with self.assertRaises(Conflict):
            self.owner.begin(bounded, U(), H(U()))
        self.assertEqual(len(self.store.inspect_data("jobs")), 1)

    async def test_reservation_cap_and_counter_uint32_boundary(self):
        self.begin()
        await self.stage("prepare_key", 1)
        bounded = replace(self.admission, policy=replace(self.admission.policy, max_stage_reservations=1))
        with self.assertRaises(Conflict):
            await self.owner.step(bounded, "verify_key", 2, U(), U(), H(U()), H("body"), noop, (H("key"), 0, None))
        self.assertEqual(len(self.store.inspect_data("operations")), 2)
        await self.stage("verify_key", 2, (H("key"), 0, None))
        await self.stage("prepare_target", 3)
        cap = self.store.reserve_stage(self.job, "verify_target", 4, U(), U(), H(U()), H("body"))
        with self.assertRaises(Conflict):
            self.store.complete_stage(self.job, cap, (H("key"), 4294967296, 1))
        self.assertEqual(self.store.inspect_data("key_counters")[0]["counter"], 0)

    async def test_expiry_domain_and_sync_build_fences(self):
        await self.complete_all()
        def build():
            self.clock.utc = 100
            return b"late"
        with self.assertRaises(Unavailable):
            self.owner.observe_final_boundary(self.admission, build)
        self.assertEqual(self.owner.observations[0]["state"], "SPENT")
        self.assertEqual(self.store.inspect_data("jobs")[0]["phase"], "SUBMIT_SPENT")
        self.clock.utc = 10
        self.clock.domain = "wrong-boot"
        with self.assertRaises(Conflict):
            self.owner.observe_final_boundary(self.admission, lambda: b"late")

    async def test_restart_never_rehydrates_submission_capability(self):
        await self.complete_all()
        restarted_owner = _SourceCoordinator(self.store, self.clock)
        with self.assertRaises(Conflict):
            restarted_owner.observe_final_boundary(self.admission, lambda: b"reissued")
        self.assertEqual(restarted_owner.observations, [])

    async def test_sqlite_process_exit_before_and_after_commit(self):
        # Actual process termination/SQLite recovery, NOT physical power-loss proof.
        for commit in (False, True):
            child_id = U()
            script = """import sqlite3,sys,os
db=sqlite3.connect(sys.argv[1],isolation_level=None)
db.execute('PRAGMA foreign_keys=ON')
db.execute('PRAGMA synchronous=FULL')
db.execute('BEGIN IMMEDIATE')
db.execute('INSERT INTO children(child_id,parent_id,parent_generation,revision,body_sha256,body,expires_ms) VALUES(?,?,1,1,?,?,100)',(sys.argv[2],sys.argv[3],'f'*64,b'SYNTHETIC'))
if sys.argv[4]=='commit': db.execute('COMMIT')
os._exit(0)
"""
            result = subprocess.run([sys.executable, "-c", script, str(self.path), child_id, self.parent,
                                     "commit" if commit else "no-commit"], timeout=10, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            found = any(row["child_id"] == child_id for row in self.store.inspect_data("children"))
            self.assertEqual(found, commit)

    async def test_expiry_after_await_retains_original_spent_operation(self):
        self.begin()
        async def delay():
            self.clock.continuous = 100
        with self.assertRaises(Unavailable):
            await self.stage("prepare_key", 1, prepare=delay)
        self.assertEqual(self.store.inspect_data("jobs")[0]["phase"], "RETIRED")
        self.assertEqual(len(self.store.inspect_data("operations")), 2)
        self.assertEqual(len(self.store.inspect_data("nonces")), 2)
        self.assertEqual(self.owner.observations, [])

    async def test_cancel_after_reservation_not_new_operation(self):
        self.begin()
        ready, gate = asyncio.Event(), asyncio.Event()
        async def delay():
            ready.set()
            await gate.wait()
        task = asyncio.create_task(self.stage("prepare_key", 1, prepare=delay))
        await ready.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.store.inspect_data("claims")[0]["outcome"], "RETIRED")
        with self.assertRaises(Unavailable):
            await self.stage("prepare_key", 1)

    async def test_late_cancel_after_actual_commit_preserves_sql_truth(self):
        self.begin()
        original = self.store._commit
        commits = 0
        def commit_then_cancel():
            nonlocal commits
            original()
            commits += 1
            if commits == 2:
                asyncio.current_task().cancel()
        self.store._commit = commit_then_cancel
        try:
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.create_task(self.stage("prepare_key", 1, prepare=lambda: asyncio.sleep(0)))
        finally:
            self.store._commit = original
        # Reservation AND completion committed; late cancellation suppresses result.
        self.assertEqual(len(self.store.inspect_data("operations")), 2)
        self.assertEqual(self.store.inspect_data("claims")[0]["outcome"], "COMMITTED")
        self.assertEqual(self.store.inspect_data("jobs")[0]["phase"], "RETIRED")
        self.assertEqual(self.owner.observations, [])

    async def test_lost_ack_after_real_commit_is_unknown_and_restart_not_retry(self):
        original = self.store._commit
        def lost_ack():
            original()
            raise OSError("synthetic lost ACK AFTER actual COMMIT")
        self.store._commit = lost_ack
        op, nonce = U(), H(U())
        with self.assertRaises(UnknownCommit):
            self.store.create_job_data(self.job, op, nonce)
        with self.assertRaises(Conflict):
            self.store.inspect_data("jobs")
        reopened = NativeSQLiteStore(self.path, "SYNTHETIC_RESTORE")
        try:
            self.assertEqual(len(reopened.inspect_data("jobs")), 1)
            with self.assertRaises(sqlite3.IntegrityError):
                reopened.create_job_data(replace(self.job, job_id=U()), op, H(U()))
            self.assertEqual(len(reopened.inspect_data("jobs")), 1)
        finally:
            reopened.close()

    async def test_restore_mismatch_and_no_automatic_database_creation(self):
        with self.assertRaises(Conflict):
            NativeSQLiteStore(self.path, "UNKNOWN_RESTORE")
        missing = self.path.with_name("does-not-exist.sqlite")
        with self.assertRaises(sqlite3.OperationalError):
            NativeSQLiteStore(missing, "SYNTHETIC_RESTORE")
        self.assertFalse(missing.exists())

    async def test_duplicate_nonce_rolls_back_partial_new_job(self):
        nonce = H("one-global-nonce")
        self.store.create_job_data(self.job, U(), nonce)
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.create_job_data(replace(self.job, job_id=U()), U(), nonce)
        self.assertEqual(len(self.store.inspect_data("jobs")), 1)
        self.assertEqual(len(self.store.inspect_data("operations")), 1)

    async def test_cas_only_one_actual_sqlite_connection_wins(self):
        self.begin()
        other = NativeSQLiteStore(self.path, "SYNTHETIC_RESTORE")
        def reserve(store):
            try:
                return store.reserve_stage(self.job, "prepare_key", 1, U(), U(), H(U()), H("body"))
            except sqlite3.IntegrityError:
                return "LOST"
        try:
            outcomes = await asyncio.gather(asyncio.to_thread(reserve, self.store), asyncio.to_thread(reserve, other))
            self.assertEqual(outcomes.count("LOST"), 1)
            self.assertEqual(len(self.store.inspect_data("claims")), 1)
            self.assertEqual(len(self.store.inspect_data("operations")), 2)
        finally:
            other.close()

    async def test_opaque_cap_once_and_foreign(self):
        self.begin()
        cap = self.store.reserve_stage(self.job, "prepare_key", 1, U(), U(), H(U()), H("body"))
        with self.assertRaises(Conflict):
            self.store.complete_stage(self.job, Reservation())
        self.store.complete_stage(self.job, cap)
        with self.assertRaises(Conflict):
            self.store.complete_stage(self.job, cap)

    async def test_counter_joint_failure_rolls_back_counter_and_job(self):
        self.begin()
        await self.stage("prepare_key", 1)
        cap = self.store.reserve_stage(self.job, "verify_key", 2, U(), U(), H(U()), H("body"))
        self.store._db.execute("CREATE TRIGGER reject_phase BEFORE UPDATE OF phase ON jobs WHEN NEW.phase='KEY_VERIFIED' BEGIN SELECT RAISE(ABORT,'synthetic partial failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.complete_stage(self.job, cap, (H("key"), 0, None))
        self.assertEqual(self.store.inspect_data("key_counters"), [])
        self.assertIsNone(self.store.inspect_data("jobs")[0]["key_ref_sha256"])
        self.assertEqual(self.store.inspect_data("jobs")[0]["revision"], 2)
        with self.assertRaises(Conflict):
            self.store.complete_stage(self.job, cap, (H("key"), 0, None))

    async def test_global_counter_survives_new_principal_epoch_and_role(self):
        await self.complete_all()
        parent2 = U()
        self.store.put_parent_data(parent2, 1, "new-pair", 2, "status_activity_transport", b"SYNTHETIC", 150)
        job2 = replace(self.job, job_id=U(), parent_id=parent2, pairing_epoch="new-pair", principal_epoch=2)
        self.store.create_job_data(job2, U(), H(U()))
        cap = self.store.reserve_stage(job2, "prepare_key", 1, U(), U(), H(U()), H("body"))
        self.store.complete_stage(job2, cap)
        cap = self.store.reserve_stage(job2, "verify_key", 2, U(), U(), H(U()), H("body"))
        with self.assertRaises(Conflict):
            self.store.complete_stage(job2, cap, (H("key"), 0, None))
        self.assertEqual(self.store.inspect_data("key_counters")[0]["counter"], 1)

    async def test_target_cannot_switch_verified_key(self):
        self.begin()
        await self.stage("prepare_key", 1)
        await self.stage("verify_key", 2, (H("key"), 0, None))
        await self.stage("prepare_target", 3)
        with self.assertRaises(Conflict):
            await self.stage("verify_target", 4, (H("other-key"), 1, 1))

    async def test_child_retirement_and_sibling_role_preserved(self):
        other = U()
        self.store.put_parent_data(other, 1, "synthetic-pair", 1, "status_activity_transport", b"SYNTHETIC", 150)
        self.store.bind_child_data(U(), self.parent, 1, 1, b"CHILD", 140)
        with self.assertRaises(Conflict):
            self.store.bind_child_data(U(), self.parent, 1, 1, b"CHILD", 151)
        self.owner.retire(self.parent)
        self.assertEqual(self.store.inspect_data("children")[0]["retired"], 1)
        self.assertEqual(next(p for p in self.store.inspect_data("parents") if p["parent_id"] == other)["retired"], 0)


class WireCase(unittest.TestCase):
    def test_clock_does_not_supply_unqualified_utc_or_mac_fallback(self):
        with self.assertRaises(ClockUnavailable):
            LinuxBootClock.__new__(LinuxBootClock).utc_upper_ms()
        if sys.platform != "linux":
            with self.assertRaises(ClockUnavailable):
                LinuxBootClock()

    def test_shared_synthetic_utf8_hex_sha_and_role_binding_vectors(self):
        packet = json.loads((Path(__file__).parents[1] / "qualification/passive-vectors.json").read_text())
        for vector in packet["vectors"]:
            raw = vector["canonical_utf8"].encode()
            self.assertEqual(raw.hex(), vector["hex"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), vector["sha256"])
            if vector["kind"] == "role":
                decoded = wire.role_state(raw, wire.ROLE_PATHS[0])
                if decoded["state"] == "AUTHORITY_CURRENT":
                    self.assertEqual(decoded["device_platform"], "ipados")
                    with self.assertRaises(wire.InvalidWire):
                        wire.role_state(raw, wire.ROLE_PATHS[1])
                    for key, value in (("client_id", "other-device"), ("client_type", "ipados"),
                                       ("operation_deadline_unix_ms", 151)):
                        with self.assertRaises(wire.InvalidWire):
                            wire.role_state(CANON(dict(decoded, **{key: value})), wire.ROLE_PATHS[0])
            else:
                wire.child_state(raw)

    def child(self):
        values = dict(version=1, state="CHILD_STATE", pairing_epoch="synthetic-pair", push_authority_id="authority",
                      push_authority_revision=1, original_operation_id=U(), parent_enrollment_id=U(),
                      parent_enrollment_generation=1, A_body_sha256=H("A"), child_id=U(), child_revision=1,
                      B_body_sha256=H("B"), outcome="CURRENT")
        self.assertEqual(tuple(values), wire.CHILD)
        return values

    def test_closed_child_outcomes_and_original_coordinates(self):
        value = self.child()
        for outcome in wire.OUTCOMES:
            value["outcome"] = outcome
            self.assertEqual(wire.child_state(CANON(value)), value)
        for field in wire.CHILD:
            invalid = dict(value)
            del invalid[field]
            with self.subTest(field=field), self.assertRaises(wire.InvalidWire):
                wire.child_state(CANON(invalid))

    def test_canonical_lexical_negatives(self):
        for raw in (b'{"version":1,"state":"UNAVAILABLE","state":"UNAVAILABLE"}',
                    b'{"version":1.0,"state":"UNAVAILABLE"}', b'{"version":1e0,"state":"UNAVAILABLE"}',
                    b'{"version":true,"state":"UNAVAILABLE"}', b'{"version":1,"state":"UNAVAILABLE"}\n',
                    b'{"version":1,"state":"UNAVAILABLE","extra":null}',
                    b'{"state":"UNAVAILABLE","version":1}', b'{"version":1,"state":"UNAVAILAB\\u004cE"}'):
            with self.subTest(raw=raw), self.assertRaises(wire.InvalidWire):
                wire.child_state(raw)

    def test_index_order_ownership_and_required_bound(self):
        child = self.child()
        index = {k: child[k] for k in ("version", "state", "pairing_epoch", "parent_enrollment_id", "parent_enrollment_generation", "A_body_sha256")}
        index["state"] = "CHILD_INDEX"
        index["children"] = [child]
        self.assertEqual(wire.child_index(CANON(index), 1), index)
        for bound in (0, None, True):
            with self.assertRaises(wire.InvalidWire):
                wire.child_index(CANON(index), bound)
        index["children"] = [child, child]
        with self.assertRaises(wire.InvalidWire):
            wire.child_index(CANON(index), 2)
        index["children"] = [dict(child, parent_enrollment_id=U())]
        with self.assertRaises(wire.InvalidWire):
            wire.child_index(CANON(index), 2)

    def test_receipt_is_unverified_data_not_native_capability(self):
        b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
        value = dict(version=1, state="CHILD_RECEIPT", B_body_b64url=b64(b"SYNTHETIC_UNVERIFIED_BODY"), B_signature_b64url=b64(bytes(64)))
        self.assertEqual(wire.original_child_receipt(CANON(value))["classification"], "UNVERIFIED_RECEIPT_DATA_ONLY")
        value["B_signature_b64url"] += "="
        with self.assertRaises(wire.InvalidWire):
            wire.original_child_receipt(CANON(value))
        with self.assertRaises(wire.InvalidWire):
            wire.original_child_receipt(b" " * 16385)

    def test_exact_role_routes_negative_only_no_legacy_fallback(self):
        raw = b'{"version":1,"state":"WAITING_AUTHORITY"}'
        for path in wire.ROLE_PATHS:
            self.assertEqual(wire.role_state(raw, path)["state"], "WAITING_AUTHORITY")
        for path in ("/api/djconnect/v1/surface_registration/state", wire.ROLE_PATHS[0] + "?role=widget_transport"):
            with self.assertRaises(wire.InvalidWire):
                wire.role_state(raw, path)


if __name__ == "__main__":
    unittest.main()
