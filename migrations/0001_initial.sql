CREATE TABLE IF NOT EXISTS registrations (
	id TEXT PRIMARY KEY,
	ha_install_id TEXT NOT NULL,
	ha_user_hash TEXT,
	device_id TEXT NOT NULL,
	client_type TEXT NOT NULL CHECK (client_type IN ('ios', 'macos', 'watchos')),
	apns_token_hash TEXT NOT NULL,
	apns_token TEXT NOT NULL,
	apns_environment TEXT NOT NULL CHECK (apns_environment IN ('sandbox', 'production')),
	topic TEXT NOT NULL,
	app_bundle_id TEXT,
	app_version TEXT,
	locale TEXT,
	categories_json TEXT NOT NULL DEFAULT '[]',
	disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
	invalid INTEGER NOT NULL DEFAULT 0 CHECK (invalid IN (0, 1)),
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	updated_at TEXT NOT NULL DEFAULT (datetime('now')),
	last_success_at TEXT,
	last_error_code TEXT,
	UNIQUE (ha_install_id, device_id, client_type, apns_token_hash)
);

CREATE INDEX IF NOT EXISTS idx_registrations_lookup
	ON registrations (ha_install_id, ha_user_hash, client_type, disabled, invalid);

CREATE INDEX IF NOT EXISTS idx_registrations_token_hash
	ON registrations (apns_token_hash);

CREATE TABLE IF NOT EXISTS relay_events (
	id TEXT PRIMARY KEY,
	ha_install_id TEXT NOT NULL,
	event_type TEXT NOT NULL CHECK (event_type IN ('ask_dj_response', 'ask_dj_confirm', 'playback_change')),
	client_type TEXT CHECK (client_type IS NULL OR client_type IN ('ios', 'macos', 'watchos')),
	target_count INTEGER NOT NULL DEFAULT 0,
	success_count INTEGER NOT NULL DEFAULT 0,
	error_count INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_relay_events_install_created
	ON relay_events (ha_install_id, created_at);
