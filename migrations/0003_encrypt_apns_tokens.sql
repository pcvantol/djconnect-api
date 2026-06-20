CREATE TABLE registrations_encrypted (
	id TEXT PRIMARY KEY,
	ha_install_id TEXT NOT NULL,
	ha_user_hash TEXT,
	device_id TEXT NOT NULL,
	client_type TEXT NOT NULL CHECK (client_type IN ('ios', 'macos', 'watchos')),
	apns_token_hash TEXT NOT NULL,
	apns_token TEXT,
	apns_token_ciphertext TEXT,
	apns_token_nonce TEXT,
	apns_token_key_version TEXT,
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

INSERT INTO registrations_encrypted (
	id, ha_install_id, ha_user_hash, device_id, client_type, apns_token_hash,
	apns_token, apns_environment, topic, app_bundle_id, app_version, locale,
	categories_json, disabled, invalid, created_at, updated_at, last_success_at,
	last_error_code
)
SELECT
	id, ha_install_id, ha_user_hash, device_id, client_type, apns_token_hash,
	apns_token, apns_environment, topic, app_bundle_id, app_version, locale,
	categories_json, disabled, invalid, created_at, updated_at, last_success_at,
	last_error_code
FROM registrations;

DROP TABLE registrations;

ALTER TABLE registrations_encrypted RENAME TO registrations;

CREATE INDEX IF NOT EXISTS idx_registrations_lookup
	ON registrations (ha_install_id, ha_user_hash, client_type, disabled, invalid);

CREATE INDEX IF NOT EXISTS idx_registrations_token_hash
	ON registrations (apns_token_hash);
