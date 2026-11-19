CREATE TABLE IF NOT EXISTS bootstrap_proofs_v2 (
	id TEXT PRIMARY KEY,
	proof_hash TEXT NOT NULL UNIQUE,
	ha_install_id TEXT NOT NULL,
	client_type TEXT NOT NULL CHECK (client_type IN ('ios', 'macos', 'watchos')),
	device_id TEXT NOT NULL,
	pairing_session_id TEXT,
	expires_at TEXT NOT NULL,
	used_at TEXT,
	created_at TEXT NOT NULL
);

INSERT OR IGNORE INTO bootstrap_proofs_v2 (
	id, proof_hash, ha_install_id, client_type, device_id, pairing_session_id,
	expires_at, used_at, created_at
)
SELECT
	id, proof_hash, ha_install_id, client_type, device_id, pairing_session_id,
	expires_at, used_at, created_at
FROM bootstrap_proofs
WHERE client_type IN ('ios', 'macos', 'watchos');

DROP TABLE bootstrap_proofs;
ALTER TABLE bootstrap_proofs_v2 RENAME TO bootstrap_proofs;

CREATE INDEX IF NOT EXISTS idx_bootstrap_proofs_hash
	ON bootstrap_proofs (proof_hash);

CREATE INDEX IF NOT EXISTS idx_bootstrap_proofs_context
	ON bootstrap_proofs (ha_install_id, client_type, device_id, used_at, expires_at);

CREATE TABLE IF NOT EXISTS relay_events_v2 (
	id TEXT PRIMARY KEY,
	ha_install_id TEXT NOT NULL,
	event_type TEXT NOT NULL CHECK (event_type IN ('ask_dj_response', 'ask_dj_confirm')),
	client_type TEXT CHECK (client_type IS NULL OR client_type IN ('ios', 'macos', 'watchos')),
	target_count INTEGER NOT NULL,
	success_count INTEGER NOT NULL,
	error_count INTEGER NOT NULL,
	created_at TEXT NOT NULL
);

INSERT OR IGNORE INTO relay_events_v2 (
	id, ha_install_id, event_type, client_type, target_count, success_count,
	error_count, created_at
)
SELECT
	id, ha_install_id, event_type, client_type, target_count, success_count,
	error_count, created_at
FROM relay_events
WHERE event_type IN ('ask_dj_response', 'ask_dj_confirm');

DROP TABLE relay_events;
ALTER TABLE relay_events_v2 RENAME TO relay_events;

CREATE INDEX IF NOT EXISTS idx_relay_events_install_created
	ON relay_events (ha_install_id, created_at);
