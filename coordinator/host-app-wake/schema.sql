-- Separate source-only schema. Not an automatic production migration.
-- Original purpose history is retained; no eviction or credential recovery.
CREATE TABLE IF NOT EXISTS host_app_wake_purposes (
 purpose_id TEXT PRIMARY KEY,
 scope_json TEXT NOT NULL,
 credential_hash TEXT NOT NULL UNIQUE,
 issued_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 max_operations INTEGER NOT NULL,
 max_wakes INTEGER NOT NULL,
 host_bundle TEXT NOT NULL,
 install_id TEXT NOT NULL,
 environment TEXT NOT NULL,
 withdrawn INTEGER NOT NULL DEFAULT 0 CHECK(withdrawn IN(0,1)),
 generation TEXT,
 revision INTEGER NOT NULL DEFAULT 0,
 ciphertext TEXT,
 nonce TEXT,
 claim_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS host_app_wake_operations (
 purpose_id TEXT NOT NULL REFERENCES host_app_wake_purposes(purpose_id),
 operation_id TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('register','wake')),
 claim_id TEXT NOT NULL,
 generation TEXT NOT NULL,
 revision INTEGER NOT NULL,
 accepted_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 outcome TEXT NOT NULL,
 provider_status INTEGER,
 PRIMARY KEY(purpose_id,operation_id)
);
CREATE INDEX IF NOT EXISTS host_app_wake_rate ON host_app_wake_operations(accepted_at,kind);
