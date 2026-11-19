-- Source-only purpose enrolment. Creates no key, approval, delegation or capability.
CREATE TABLE surface_push_delegations (
 id TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision=1),
 enrol_operation_id TEXT NOT NULL UNIQUE, approval_reference TEXT NOT NULL,
 install_id TEXT NOT NULL, device_binding TEXT NOT NULL, owner_binding TEXT NOT NULL,
 grant_binding TEXT NOT NULL, source_binding TEXT NOT NULL, binding_id TEXT NOT NULL,
 public_key_json TEXT NOT NULL, key_thumbprint TEXT NOT NULL,
 policy_json TEXT NOT NULL, scope_digest TEXT NOT NULL,
 expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE TABLE surface_push_operator_operations (
 operation_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, delegation_id TEXT NOT NULL,
 kind TEXT NOT NULL, claim_id TEXT NOT NULL, outcome TEXT NOT NULL
);
CREATE TABLE surface_push_issuer_operations (
 delegation_id TEXT NOT NULL, operation_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('challenge','issue','withdraw')),
 request_hash TEXT NOT NULL, claim_id TEXT NOT NULL, outcome TEXT NOT NULL,
 challenge_id TEXT, nonce_hash TEXT, scope_digest TEXT NOT NULL,
 expires_at INTEGER NOT NULL, capability_id TEXT, accepted_at INTEGER NOT NULL,
 PRIMARY KEY(delegation_id,operation_id,kind),
 FOREIGN KEY(delegation_id) REFERENCES surface_push_delegations(id)
);
ALTER TABLE surface_push_capabilities ADD COLUMN delegation_id TEXT REFERENCES surface_push_delegations(id);
ALTER TABLE surface_push_capabilities ADD COLUMN delegation_revision INTEGER;
ALTER TABLE surface_push_capabilities ADD COLUMN binding_id TEXT;
ALTER TABLE surface_push_capabilities ADD COLUMN grant_binding TEXT;
ALTER TABLE surface_push_capabilities ADD COLUMN source_binding TEXT;
ALTER TABLE surface_push_capabilities ADD COLUMN scope_digest TEXT;
-- Old unbound fixture capabilities are NOT upgraded into purpose grants.
CREATE VIEW surface_push_live_capabilities AS
 SELECT c.* FROM surface_push_capabilities c JOIN surface_push_delegations d ON
 c.delegation_id=d.id AND c.delegation_revision=d.revision AND d.revoked_at IS NULL AND
 c.revoked_at IS NULL AND c.expires_at<=d.expires_at AND
 c.install_id=d.install_id AND c.device_binding=d.device_binding AND c.owner_binding=d.owner_binding AND
 c.binding_id=d.binding_id AND c.grant_binding=d.grant_binding AND c.source_binding=d.source_binding AND c.scope_digest=d.scope_digest AND
 c.role=json_extract(d.policy_json,'$.token_role') AND c.platform=json_extract(d.policy_json,'$.platform') AND
 c.environment=json_extract(d.policy_json,'$.apns_environment') AND
 c.parent_bundle=json_extract(d.policy_json,'$.target.app_bundle_id') AND
 c.extension_bundle=COALESCE(json_extract(d.policy_json,'$.target.extension_bundle_id'),'') AND
 c.widget_kind=COALESCE(json_extract(d.policy_json,'$.target.widget_kind'),'') AND
 c.attributes_type=COALESCE(json_extract(d.policy_json,'$.target.attributes_type'),'') AND
 c.activity_profile=COALESCE(json_extract(d.policy_json,'$.activity_profile'),'') AND
 c.external_content_allowed=json_extract(d.policy_json,'$.external_content_allowed') AND
 c.max_operations<=json_extract(d.policy_json,'$.max_operations') AND
 c.max_events<=json_extract(d.policy_json,'$.max_events');
