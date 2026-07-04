CREATE TABLE IF NOT EXISTS api_diagnostics (
	id TEXT PRIMARY KEY,
	method TEXT NOT NULL,
	route TEXT NOT NULL,
	status INTEGER NOT NULL,
	error_code TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_api_diagnostics_created
	ON api_diagnostics (created_at);

CREATE INDEX IF NOT EXISTS idx_api_diagnostics_route_status_created
	ON api_diagnostics (route, status, created_at);

CREATE TABLE IF NOT EXISTS push_delivery_failures (
	id TEXT PRIMARY KEY,
	relay_event_id TEXT NOT NULL,
	client_type TEXT CHECK (client_type IS NULL OR client_type IN ('ios', 'macos', 'watchos')),
	apns_status INTEGER NOT NULL,
	apns_reason TEXT NOT NULL,
	count INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	FOREIGN KEY (relay_event_id) REFERENCES relay_events(id)
);

CREATE INDEX IF NOT EXISTS idx_push_delivery_failures_created
	ON push_delivery_failures (created_at);

CREATE INDEX IF NOT EXISTS idx_push_delivery_failures_reason_created
	ON push_delivery_failures (apns_reason, created_at);
