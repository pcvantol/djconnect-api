CREATE TABLE IF NOT EXISTS bootstrap_proofs (
	id TEXT PRIMARY KEY,
	proof_hash TEXT NOT NULL UNIQUE,
	ha_install_id TEXT NOT NULL,
	integration TEXT,
	integration_version TEXT,
	client_type TEXT NOT NULL CHECK (client_type IN ('ios', 'macos', 'watchos', 'raspberry_pi', 'esp32', 'conversation_agent')),
	device_id TEXT NOT NULL,
	pairing_session_id TEXT,
	expires_at TEXT NOT NULL,
	used_at TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_bootstrap_proofs_hash
	ON bootstrap_proofs (proof_hash);

CREATE INDEX IF NOT EXISTS idx_bootstrap_proofs_context
	ON bootstrap_proofs (ha_install_id, client_type, device_id, used_at, expires_at);

CREATE TABLE IF NOT EXISTS bootstrap_rate_limits (
	key TEXT PRIMARY KEY,
	window_start INTEGER NOT NULL,
	count INTEGER NOT NULL,
	updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
