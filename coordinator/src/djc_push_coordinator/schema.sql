-- Disposable native SQLite qualification schema, never an automatic migration.
CREATE TABLE metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 schema_version INTEGER NOT NULL CHECK(schema_version=1), restore_epoch TEXT NOT NULL) STRICT;
CREATE TABLE parents (
 parent_id TEXT PRIMARY KEY, generation INTEGER NOT NULL CHECK(generation>0),
 pairing_epoch TEXT NOT NULL, principal_epoch INTEGER NOT NULL CHECK(principal_epoch>0),
 role TEXT NOT NULL CHECK(role IN ('widget_transport','status_activity_transport')),
 body_sha256 TEXT NOT NULL, body BLOB NOT NULL, expires_ms INTEGER NOT NULL CHECK(expires_ms>0),
 retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1))) STRICT;
CREATE TABLE children (
 child_id TEXT PRIMARY KEY, parent_id TEXT NOT NULL REFERENCES parents(parent_id),
 parent_generation INTEGER NOT NULL CHECK(parent_generation>0), revision INTEGER NOT NULL CHECK(revision>0),
 body_sha256 TEXT NOT NULL, body BLOB NOT NULL, expires_ms INTEGER NOT NULL CHECK(expires_ms>0),
 retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1))) STRICT;
CREATE TABLE jobs (
 job_id TEXT PRIMARY KEY, parent_id TEXT NOT NULL REFERENCES parents(parent_id),
 parent_generation INTEGER NOT NULL, pairing_epoch TEXT NOT NULL, principal_epoch INTEGER NOT NULL,
 context_sha256 TEXT NOT NULL, key_scope_sha256 TEXT NOT NULL,
 key_ref_sha256 TEXT,
 deadline_ms INTEGER NOT NULL CHECK(deadline_ms>0),
 phase TEXT NOT NULL CHECK(phase IN ('RESERVED','KEY_PREPARED','KEY_VERIFIED','TARGET_PREPARED','TARGET_VERIFIED','SUBMIT_SPENT','RETIRED')),
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0)) STRICT;
-- Shared namespaces across stages/jobs/roles/principal epochs, not per-job replay caches.
CREATE TABLE operations (operation_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(job_id)) STRICT;
CREATE TABLE nonces (nonce_sha256 TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(job_id)) STRICT;
CREATE TABLE claims (
 claim_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(job_id), stage TEXT NOT NULL,
 operation_id TEXT NOT NULL UNIQUE REFERENCES operations(operation_id), body_sha256 TEXT NOT NULL,
 expected_revision INTEGER NOT NULL CHECK(expected_revision>0),
 outcome TEXT NOT NULL CHECK(outcome IN ('RESERVED','COMMITTED','SUBMIT_SPENT','RETIRED')),
 UNIQUE(job_id,stage)) STRICT;
CREATE TABLE key_counters (
 key_ref_sha256 TEXT PRIMARY KEY, key_scope_sha256 TEXT NOT NULL,
 counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295),
 revision INTEGER NOT NULL CHECK(revision>0)) STRICT;
