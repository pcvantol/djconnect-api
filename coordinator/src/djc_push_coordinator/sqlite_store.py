"""One native SQLite transaction domain. Receipt bytes remain DATA, not admission."""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import re
from pathlib import Path
from collections.abc import Callable
from dataclasses import dataclass, asdict
from typing import TypeVar

T = TypeVar("T")
MAX = 9_007_199_254_740_991


def identifier(value):
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value) is None:
        raise Conflict("invalid identifier")


def digest(value):
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise Conflict("invalid digest")


def integer(value):
    if type(value) is not int or not 1 <= value <= MAX:
        raise Conflict("invalid integer")


class Conflict(Exception):
    pass


class UnknownCommit(Exception):
    """The connection is fenced; never repair by issuing a fresh operation."""


@dataclass(frozen=True)
class Job:
    job_id: str
    parent_id: str
    parent_generation: int
    pairing_epoch: str
    principal_epoch: int
    context_sha256: str
    key_scope_sha256: str
    deadline_ms: int

    def __post_init__(self):
        for v in (self.job_id, self.parent_id, self.pairing_epoch):
            identifier(v)
        for v in (self.parent_generation, self.principal_epoch, self.deadline_ms):
            integer(v)
        digest(self.context_sha256)
        digest(self.key_scope_sha256)


class Reservation:
    """Process-local once capability; no serializer or reconstruction API."""
    __slots__ = ()


class NativeSQLiteStore:
    def __init__(self, path: Path, restore_epoch: str):
        # Explicit existing file only. No schema creation or path fallback.
        self._db = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True,
                                   isolation_level=None, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._held: dict[Reservation, str] = {}
        self._closed = False
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA synchronous=FULL")
        self.settings = {
            "journal_mode": self._db.execute("PRAGMA journal_mode").fetchone()[0],
            "synchronous": self._db.execute("PRAGMA synchronous").fetchone()[0],
            "foreign_keys": self._db.execute("PRAGMA foreign_keys").fetchone()[0],
            "sqlite_version": sqlite3.sqlite_version,
        }
        try:
            row = self._db.execute("SELECT schema_version,restore_epoch FROM metadata WHERE singleton=1").fetchone()
            if (self.settings["journal_mode"] != "wal" or self.settings["synchronous"] != 2
                    or self.settings["foreign_keys"] != 1 or row is None
                    or tuple(row) != (1, restore_epoch)):
                raise Conflict("unqualified settings/schema/restore epoch")
        except BaseException:
            self._db.close()
            raise

    def close(self):
        with self._lock:
            if not self._closed:
                self._closed = True
                self._db.close()

    def _commit(self):
        self._db.execute("COMMIT")

    def _transaction(self, write: Callable[[sqlite3.Connection], T]) -> T:
        with self._lock:
            if self._closed:
                raise Conflict("store closed or commit unknown")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                result = write(self._db)
            except BaseException:
                try:
                    self._db.execute("ROLLBACK")
                except BaseException as error:
                    self._closed = True
                    self._db.close()
                    raise UnknownCommit("rollback settlement unavailable") from error
                raise
            try:
                self._commit()
            except BaseException as error:
                # Even an apparently rolled-back error is never a positive ACK.
                # Close/fence instead of retrying COMMIT, returning a fresh lease,
                # or claiming cancellation undid an actual commit.
                self._closed = True
                self._db.close()
                raise UnknownCommit("commit acknowledgement unavailable") from error
            return result

    def put_parent_data(self, parent_id: str, generation: int, pairing_epoch: str,
                        principal_epoch: int, role: str, body: bytes, expires_ms: int):
        """Called only inside source qualification. Does not verify Core signatures."""
        for v in (parent_id, pairing_epoch):
            identifier(v)
        for v in (generation, principal_epoch, expires_ms):
            integer(v)
        if type(body) is not bytes or not 1 <= len(body) <= 8192:
            raise Conflict("invalid original body")
        body_digest = hashlib.sha256(body).hexdigest()
        self._transaction(lambda db: db.execute(
            "INSERT INTO parents(parent_id,generation,pairing_epoch,principal_epoch,role,body_sha256,body,expires_ms) VALUES(?,?,?,?,?,?,?,?)",
            (parent_id, generation, pairing_epoch, principal_epoch, role, body_digest, body, expires_ms)))

    def bind_child_data(self, child_id: str, parent_id: str, generation: int,
                        revision: int, body: bytes, expires_ms: int, max_children: int | None = None):
        identifier(child_id)
        identifier(parent_id)
        for v in (generation, revision, expires_ms):
            integer(v)
        if type(body) is not bytes or not 1 <= len(body) <= 8192:
            raise Conflict("invalid original body")
        if max_children is not None:
            integer(max_children)
        def write(db):
            if max_children is not None and db.execute("SELECT count(*) FROM children").fetchone()[0] >= max_children:
                raise Conflict("finite child budget")
            p = db.execute("SELECT * FROM parents WHERE parent_id=?", (parent_id,)).fetchone()
            if p is None or p["retired"] or p["generation"] != generation or expires_ms > p["expires_ms"]:
                raise Conflict("child parent or lifetime mismatch")
            db.execute("INSERT INTO children(child_id,parent_id,parent_generation,revision,body_sha256,body,expires_ms) VALUES(?,?,?,?,?,?,?)",
                       (child_id, parent_id, generation, revision, hashlib.sha256(body).hexdigest(), body, expires_ms))
        self._transaction(write)

    @staticmethod
    def _parent(db, job: Job):
        p = db.execute("SELECT * FROM parents WHERE parent_id=?", (job.parent_id,)).fetchone()
        if (p is None or p["retired"] or p["generation"] != job.parent_generation
                or p["pairing_epoch"] != job.pairing_epoch or p["principal_epoch"] != job.principal_epoch
                or job.deadline_ms > p["expires_ms"]):
            raise Conflict("parent epoch/scope/lifetime mismatch")

    @staticmethod
    def _job(db, job: Job):
        row = db.execute("SELECT * FROM jobs WHERE job_id=?", (job.job_id,)).fetchone()
        if row is None or any(row[k] != v for k, v in asdict(job).items()):
            raise Conflict("immutable job binding mismatch")
        return row

    def create_job_data(self, job: Job, operation: str, nonce: str, max_jobs: int | None = None):
        identifier(operation)
        digest(nonce)
        if max_jobs is not None:
            integer(max_jobs)
        def write(db):
            if max_jobs is not None and db.execute("SELECT count(*) FROM jobs").fetchone()[0] >= max_jobs:
                raise Conflict("finite job budget")
            self._parent(db, job)
            db.execute("INSERT INTO jobs(job_id,parent_id,parent_generation,pairing_epoch,principal_epoch,context_sha256,key_scope_sha256,deadline_ms,phase) VALUES(?,?,?,?,?,?,?,?,?)",
                (job.job_id, job.parent_id, job.parent_generation, job.pairing_epoch,
                 job.principal_epoch, job.context_sha256, job.key_scope_sha256, job.deadline_ms, "RESERVED"))
            db.execute("INSERT INTO operations VALUES(?,?)", (operation, job.job_id))
            db.execute("INSERT INTO nonces VALUES(?,?)", (nonce, job.job_id))
        self._transaction(write)

    def reserve_stage(self, job: Job, stage: str, revision: int, claim: str,
                      operation: str, nonce: str, body_sha256: str, max_claims: int | None = None) -> Reservation:
        previous = {"prepare_key": "RESERVED", "verify_key": "KEY_PREPARED",
                    "prepare_target": "KEY_VERIFIED", "verify_target": "TARGET_PREPARED",
                    "submit": "TARGET_VERIFIED"}
        if stage not in previous:
            raise Conflict("unknown stage")
        integer(revision)
        identifier(claim)
        identifier(operation)
        digest(nonce)
        digest(body_sha256)
        if max_claims is not None:
            integer(max_claims)
        def write(db):
            if max_claims is not None and db.execute("SELECT count(*) FROM claims").fetchone()[0] >= max_claims:
                raise Conflict("finite reservation budget")
            self._parent(db, job)
            j = self._job(db, job)
            if (j is None or j["phase"] != previous[stage] or j["revision"] != revision
                    or j["context_sha256"] != job.context_sha256 or j["key_scope_sha256"] != job.key_scope_sha256
                    or j["parent_id"] != job.parent_id or j["pairing_epoch"] != job.pairing_epoch):
                raise Conflict("joint CAS lost")
            db.execute("INSERT INTO operations VALUES(?,?)", (operation, job.job_id))
            db.execute("INSERT INTO nonces VALUES(?,?)", (nonce, job.job_id))
            db.execute("INSERT INTO claims VALUES(?,?,?,?,?,?,?)",
                       (claim, job.job_id, stage, operation, body_sha256, revision, "RESERVED"))
        self._transaction(write)
        token = Reservation()
        with self._lock:
            self._held[token] = claim
        return token

    def complete_stage(self, job: Job, reservation: Reservation,
                       counter: tuple[str, int, int | None] | None = None):
        with self._lock:
            claim = self._held.pop(reservation, None)
        if claim is None:
            raise Conflict("spent or foreign reservation")
        # Consumed before validation, guards or submission; never restored.
        next_phase = {"prepare_key": "KEY_PREPARED", "verify_key": "KEY_VERIFIED",
                      "prepare_target": "TARGET_PREPARED", "verify_target": "TARGET_VERIFIED",
                      "submit": "SUBMIT_SPENT"}
        def write(db):
            self._parent(db, job)
            j = self._job(db, job)
            c = db.execute("SELECT * FROM claims WHERE claim_id=?", (claim,)).fetchone()
            if c is None or c["job_id"] != job.job_id or c["outcome"] != "RESERVED":
                raise Conflict("claim unavailable")
            needs_counter = c["stage"] in ("verify_key", "verify_target")
            if needs_counter != (counter is not None):
                raise Conflict("counter required only at verification")
            if counter is not None:
                key, value, expected = counter
                digest(key)
                if expected is not None:
                    integer(expected)
                if c["stage"] == "verify_target" and key != j["key_ref_sha256"]:
                    raise Conflict("target must use original verified key")
                if type(value) is not int or not 0 <= value <= 4294967295:
                    raise Conflict("invalid counter")
                k = db.execute("SELECT * FROM key_counters WHERE key_ref_sha256=?", (key,)).fetchone()
                if k is None:
                    if c["stage"] != "verify_key" or value != 0 or expected is not None:
                        raise Conflict("no counter reset or target bootstrap")
                    db.execute("INSERT INTO key_counters VALUES(?,?,?,1)", (key, job.key_scope_sha256, value))
                else:
                    if (k["key_scope_sha256"] != job.key_scope_sha256 or k["revision"] != expected
                            or value <= k["counter"] or k["revision"] >= MAX):
                        raise Conflict("global key counter CAS lost")
                    db.execute("UPDATE key_counters SET counter=?,revision=revision+1 WHERE key_ref_sha256=?",
                               (value, key))
                if c["stage"] == "verify_key":
                    db.execute("UPDATE jobs SET key_ref_sha256=? WHERE job_id=?", (key, job.job_id))
            changed = db.execute("UPDATE jobs SET phase=?,revision=revision+1 WHERE job_id=? AND revision=? AND revision<? AND phase<>'RETIRED'",
                                 (next_phase[c["stage"]], job.job_id, c["expected_revision"], MAX)).rowcount
            if changed != 1:
                raise Conflict("joint CAS lost")  # Rolls counter back inside same transaction.
            outcome = "SUBMIT_SPENT" if c["stage"] == "submit" else "COMMITTED"
            db.execute("UPDATE claims SET outcome=? WHERE claim_id=?", (outcome, claim))
        self._transaction(write)

    def retire_parent(self, parent_id: str):
        def write(db):
            db.execute("UPDATE parents SET retired=1 WHERE parent_id=?", (parent_id,))
            db.execute("UPDATE children SET retired=1 WHERE parent_id=?", (parent_id,))
            db.execute("UPDATE jobs SET phase='RETIRED' WHERE parent_id=?", (parent_id,))
            db.execute("UPDATE claims SET outcome='RETIRED' WHERE job_id IN (SELECT job_id FROM jobs WHERE parent_id=?) AND outcome='RESERVED'", (parent_id,))
        self._transaction(write)

    def inspect_data(self, table: str):
        if table not in {"parents", "children", "jobs", "operations", "nonces", "claims", "key_counters"}:
            raise Conflict("unknown table")
        with self._lock:
            if self._closed:
                raise Conflict("closed store")
            return [dict(row) for row in self._db.execute("SELECT * FROM " + table)]
