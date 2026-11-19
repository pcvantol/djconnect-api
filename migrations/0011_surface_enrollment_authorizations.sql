-- Hash-only, single-use enrollment authority, never a push/provider credential.
CREATE TABLE IF NOT EXISTS surface_enrollment_operator_operations (
 operation_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL,
 authorization_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('authorize','revoke')),
 claim_id TEXT NOT NULL, outcome TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS surface_enrollment_authorizations (
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
 authorize_operation_id TEXT NOT NULL UNIQUE,
 nonce_hash TEXT NOT NULL UNIQUE, action_key TEXT NOT NULL UNIQUE,
 consent_digest TEXT NOT NULL, request_hash TEXT NOT NULL,
 key_thumbprint TEXT NOT NULL, scope_digest TEXT NOT NULL,
 delegation_id TEXT NOT NULL UNIQUE, enrollment_operation_id TEXT NOT NULL UNIQUE,
 expires_at INTEGER NOT NULL, grant_expires_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('available','consumed','revoked')),
 claim_id TEXT NOT NULL, outcome TEXT NOT NULL,
 created_at INTEGER NOT NULL, consumed_at INTEGER, revoked_at INTEGER
);
