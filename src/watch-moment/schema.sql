-- Standalone qualification schema only. Not a numbered/live migration.
-- Store digests and outcomes, never payload text, device tokens or credentials.
CREATE TABLE watch_moment_operations (
 operation_key TEXT PRIMARY KEY,
 publication_key TEXT NOT NULL UNIQUE,
 scope_hash TEXT NOT NULL,
 recipient_hash TEXT NOT NULL,
 request_hash TEXT NOT NULL,
 registration_hash TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('reserved','dispatching','provider_accepted','provider_rejected','retryable','unknown','cancelled','expired')),
 created_at_ms INTEGER NOT NULL,
 expires_at_ms INTEGER NOT NULL,
 lease_id TEXT NOT NULL,
 attempts INTEGER NOT NULL CHECK(attempts BETWEEN 1 AND 3),
 next_attempt_ms INTEGER NOT NULL,
 provider_status INTEGER,
 CHECK(expires_at_ms > created_at_ms)
);
CREATE INDEX watch_moment_scope ON watch_moment_operations(scope_hash);
CREATE INDEX watch_moment_burst ON watch_moment_operations(recipient_hash, created_at_ms);
