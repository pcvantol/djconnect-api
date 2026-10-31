-- Source-only receiving tables. NOT a production migration or enrollment grant.
-- The actual install_tokens table and unchanged Source181 schema are prerequisites.
CREATE TABLE IF NOT EXISTS host_wake_operator_authorizations (
 authorization_id TEXT PRIMARY KEY,
 operation_id TEXT NOT NULL UNIQUE,
 request_hash TEXT NOT NULL,
 core_install_token_record_id TEXT NOT NULL REFERENCES install_tokens(id),
 ha_install_id TEXT NOT NULL,
 authorization_json TEXT NOT NULL,
 issued_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN('authorized','expired','withdrawn')),
 accepted_at INTEGER NOT NULL,
 original_request_expires_at INTEGER NOT NULL,
 CHECK(expires_at>issued_at)
);
CREATE TABLE IF NOT EXISTS host_wake_issuer_once (
 authorization_id TEXT NOT NULL REFERENCES host_wake_operator_authorizations(authorization_id),
 core_purpose_id TEXT NOT NULL,
 issuer_operation_id TEXT NOT NULL UNIQUE,
 claim_id TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 original_json TEXT NOT NULL,
 private_purpose_id TEXT NOT NULL UNIQUE,
 issued_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 accepted_at INTEGER NOT NULL,
 original_request_expires_at INTEGER NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN('reserved','issued','expired','unknown','withdrawn')),
 PRIMARY KEY(authorization_id,core_purpose_id)
);
CREATE TABLE IF NOT EXISTS host_wake_native_jobs (
 challenge_id TEXT PRIMARY KEY,
 private_job_id TEXT NOT NULL UNIQUE,
 authorization_id TEXT NOT NULL,
 core_purpose_id TEXT NOT NULL,
 operation_id TEXT NOT NULL,
 generation TEXT NOT NULL,
 revision INTEGER NOT NULL,
 request_hash TEXT NOT NULL,
 original_json TEXT NOT NULL,
 challenge_json TEXT NOT NULL,
 proof_kind TEXT NOT NULL CHECK(proof_kind IN('app_attest_attestation','app_attest_assertion')),
 verification_claim TEXT,
 captured_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN('reserved','verifying','verified','rejected','expired','unknown','withdrawn')),
 -- One original semantic registration has one noncejob, including UNKNOWN.
 UNIQUE(authorization_id,core_purpose_id,operation_id,generation,revision),
 FOREIGN KEY(authorization_id,core_purpose_id) REFERENCES host_wake_issuer_once(authorization_id,core_purpose_id)
);
-- No enrollment writer/factory is admitted by this schema. Only the eventual
-- verified enrollment/signing-policy composition may create these records.
CREATE TABLE IF NOT EXISTS host_wake_native_enrollments (
 native_key_ref TEXT PRIMARY KEY,
 native_key_id_b64 TEXT NOT NULL UNIQUE,
 public_key_spki_b64 TEXT NOT NULL,
 assertion_policy_json TEXT,
 counter_claim TEXT,
 host_bundle TEXT NOT NULL,
 install_id TEXT NOT NULL,
 platform TEXT NOT NULL CHECK(platform IN('ios','ipados')),
 environment TEXT NOT NULL CHECK(environment IN('sandbox','production')),
 identity_policy_sha256 TEXT NOT NULL,
 deployment_policy_sha256 TEXT NOT NULL,
 enrollment_receipt_sha256 TEXT NOT NULL,
 signed_environment_receipt_sha256 TEXT NOT NULL,
 issued_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 counter INTEGER NOT NULL CHECK(counter>=0),
 disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN(0,1))
);
CREATE TABLE IF NOT EXISTS host_wake_native_verifications (
 challenge_id TEXT PRIMARY KEY REFERENCES host_wake_native_jobs(challenge_id),
 private_job_id TEXT NOT NULL,
 native_key_ref TEXT NOT NULL REFERENCES host_wake_native_enrollments(native_key_ref),
 verified_counter INTEGER NOT NULL CHECK(verified_counter>0),
 verified_at INTEGER NOT NULL,
 commit_claim TEXT,
 original_json TEXT NOT NULL,
 consumed_at INTEGER,
 register_operation_id TEXT,
 register_claim_id TEXT,
 CHECK((consumed_at IS NULL AND register_operation_id IS NULL AND register_claim_id IS NULL) OR (consumed_at IS NOT NULL AND register_operation_id IS NOT NULL AND register_claim_id IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS host_wake_receiving_intents (
 authorization_id TEXT NOT NULL,
 core_purpose_id TEXT NOT NULL,
 issuer_operation_id TEXT NOT NULL,
 route TEXT NOT NULL,
 claim_id TEXT NOT NULL,
 request_hash TEXT,
 captured_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 outcome TEXT NOT NULL CHECK(outcome IN('reserved','completed','expired','unknown','withdrawn')),
 PRIMARY KEY(authorization_id,core_purpose_id,issuer_operation_id,route),
 FOREIGN KEY(authorization_id) REFERENCES host_wake_operator_authorizations(authorization_id)
);
