-- Disposable qualification schema, NOT a production migration or runtime bootstrap.
-- These records and phase words are DATA, never owner/native/clock admission.
CREATE TABLE native_proof_data_jobs (
 job_id TEXT PRIMARY KEY,
 classification TEXT NOT NULL DEFAULT 'DATA_ONLY_NOT_ADMISSION'
  CHECK(classification='DATA_ONLY_NOT_ADMISSION'),
 bootstrap_binding_sha256 TEXT NOT NULL UNIQUE,
 context_sha256 TEXT NOT NULL,
 data_epoch_sha256 TEXT NOT NULL,
 key_scope_sha256 TEXT NOT NULL,
 key_operation_id TEXT NOT NULL,
 target_operation_id TEXT NOT NULL CHECK(target_operation_id<>key_operation_id),
 key_nonce_sha256 TEXT NOT NULL,
 target_nonce_sha256 TEXT NOT NULL CHECK(target_nonce_sha256<>key_nonce_sha256),
 bootstrap_deadline_unix_ms INTEGER NOT NULL CHECK(bootstrap_deadline_unix_ms BETWEEN 1 AND 9007199254740991),
 original_grant_expires_at_unix_ms INTEGER NOT NULL CHECK(original_grant_expires_at_unix_ms BETWEEN 1 AND 9007199254740991),
 phase TEXT NOT NULL CHECK(phase IN ('APPROVED_AVAILABLE','KEY_PREPARED','KEY_VERIFYING','KEY_VERIFIED',
  'TARGET_PREPARED','TARGET_VERIFYING','TARGET_VERIFIED','REJECTED_RETIRED','WITHDRAWN_RETIRED','EXPIRED_RETIRED','UNCERTAIN_RETIRED')),
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 active_claim TEXT,
 last_commit_claim TEXT,
 key_mode TEXT CHECK(key_mode IN ('new_key_attestation','existing_key_assertion')),
 key_ref_sha256 TEXT,
 key_transcript_sha256 TEXT,
 target_transcript_sha256 TEXT,
 native_token_sha256 TEXT
) STRICT;

-- Separate global namespaces also reject a key operation/nonce reused as another job's target.
CREATE TABLE native_proof_data_operations (
 operation_id TEXT PRIMARY KEY,
 job_id TEXT NOT NULL REFERENCES native_proof_data_jobs(job_id),
 original_phase TEXT NOT NULL CHECK(original_phase IN ('key','target')),
 UNIQUE(job_id,original_phase)
) STRICT;
CREATE TABLE native_proof_data_nonces (
 nonce_sha256 TEXT PRIMARY KEY,
 job_id TEXT NOT NULL REFERENCES native_proof_data_jobs(job_id),
 original_phase TEXT NOT NULL CHECK(original_phase IN ('key','target')),
 state TEXT NOT NULL CHECK(state IN ('available','spent')),
 spent_claim TEXT,
 UNIQUE(job_id,original_phase)
) STRICT;
CREATE TABLE native_proof_data_claims (
 job_id TEXT NOT NULL REFERENCES native_proof_data_jobs(job_id),
 stage TEXT NOT NULL CHECK(stage IN ('prepare_key','verify_key','prepare_target','verify_target')),
 claim_id TEXT NOT NULL UNIQUE,
 operation_id TEXT NOT NULL,
 body_sha256 TEXT NOT NULL,
 claimed_revision INTEGER NOT NULL CHECK(claimed_revision BETWEEN 1 AND 9007199254740991),
 outcome TEXT NOT NULL CHECK(outcome IN ('reserved','committed','retired')),
 PRIMARY KEY(job_id,stage)
) STRICT;
CREATE TABLE native_proof_data_key_counters (
 key_ref_sha256 TEXT PRIMARY KEY,
 key_scope_sha256 TEXT NOT NULL,
 counter INTEGER NOT NULL CHECK(counter BETWEEN 0 AND 4294967295),
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 last_claim TEXT NOT NULL
) STRICT;

-- A partial multi-row write must abort inside SQL, not be "rolled back" after an await.
-- Successful checks are inserted/deleted within the same definitive transaction.
CREATE TABLE native_proof_data_atomic_checks (
 claim_id TEXT PRIMARY KEY,
 valid INTEGER NOT NULL CHECK(valid=1)
) STRICT;
