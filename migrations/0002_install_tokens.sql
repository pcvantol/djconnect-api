CREATE TABLE IF NOT EXISTS install_tokens (
	id TEXT PRIMARY KEY,
	ha_install_id TEXT NOT NULL,
	ha_user_hash TEXT,
	token_hash TEXT NOT NULL UNIQUE,
	token_prefix TEXT NOT NULL,
	label TEXT,
	disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	updated_at TEXT NOT NULL DEFAULT (datetime('now')),
	last_used_at TEXT,
	rotated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_install_tokens_install_active
	ON install_tokens (ha_install_id, disabled);

CREATE INDEX IF NOT EXISTS idx_install_tokens_hash
	ON install_tokens (token_hash);
