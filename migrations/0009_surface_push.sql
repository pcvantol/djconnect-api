-- Source candidate only. This migration provisions no capability, token or admission.
CREATE TABLE surface_push_capabilities (
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
 install_id TEXT NOT NULL, device_binding TEXT NOT NULL, owner_binding TEXT NOT NULL,
 parent_bundle TEXT NOT NULL, extension_bundle TEXT NOT NULL, widget_kind TEXT NOT NULL,
 attributes_type TEXT NOT NULL, activity_profile TEXT NOT NULL,
 external_content_allowed INTEGER NOT NULL DEFAULT 0 CHECK(external_content_allowed IN (0,1)),
 platform TEXT NOT NULL CHECK(platform IN ('ios','ipados','maccatalyst','macos','watchos','visionos')),
 environment TEXT NOT NULL CHECK(environment IN ('sandbox','production')),
 role TEXT NOT NULL CHECK(role IN ('widget','live_activity_update','live_activity_start')),
 expires_at INTEGER NOT NULL, revoked_at INTEGER,
 max_operations INTEGER NOT NULL CHECK(max_operations BETWEEN 1 AND 10000),
 max_events INTEGER NOT NULL CHECK(max_events BETWEEN 1 AND 1000)
);
CREATE TABLE surface_push_targets (
 id TEXT PRIMARY KEY, capability_id TEXT NOT NULL,
 registration_id TEXT NOT NULL, generation TEXT NOT NULL, revision INTEGER NOT NULL,
 binding_id TEXT NOT NULL, device_binding TEXT NOT NULL, owner_binding TEXT NOT NULL,
 expires_at INTEGER NOT NULL, target_json TEXT,
 state TEXT NOT NULL CHECK(state IN ('active','revoked')),
 ciphertext TEXT, nonce TEXT, last_claim TEXT NOT NULL,
 FOREIGN KEY(capability_id) REFERENCES surface_push_capabilities(id)
);
CREATE TABLE surface_push_operations (
 capability_id TEXT NOT NULL, operation_id TEXT NOT NULL,
 request_hash TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('register','revoke','event')),
 target_id TEXT NOT NULL, claim_id TEXT NOT NULL,
 outcome TEXT NOT NULL, accepted_at INTEGER NOT NULL,
 registration_id TEXT NOT NULL, generation TEXT NOT NULL, revision INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, provider_status INTEGER,
 PRIMARY KEY(capability_id,operation_id),
 FOREIGN KEY(capability_id) REFERENCES surface_push_capabilities(id)
);
CREATE INDEX surface_push_operations_budget ON surface_push_operations(capability_id,kind,outcome);
-- No automatic deletion: unseen-register tombstones must survive operation-ledger pruning.
