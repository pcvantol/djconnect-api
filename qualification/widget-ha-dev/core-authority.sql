-- Isolated HA-dev only. Write access belongs to the trusted authority publisher.
CREATE TABLE widget_core_machines (
    access_client_id TEXT PRIMARY KEY NOT NULL,
    scope_id TEXT UNIQUE NOT NULL,
    ha_install_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
);

CREATE TABLE widget_core_pair_authority (
    scope_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    pairing_generation TEXT NOT NULL,
    pair_binding TEXT NOT NULL,
    owner_binding TEXT NOT NULL,
    device_binding TEXT NOT NULL,
    core_key_thumbprint TEXT NOT NULL,
    retirement_request_expires_at_ms INTEGER NOT NULL,
    consent_revision INTEGER NOT NULL CHECK (consent_revision > 0),
    current INTEGER NOT NULL CHECK (current IN (0, 1)),
    PRIMARY KEY (scope_id, credential_id, operation_id)
);

CREATE TABLE widget_core_consent_withdrawals (
    scope_id TEXT NOT NULL,
    pair_binding TEXT NOT NULL,
    through_revision INTEGER NOT NULL CHECK (through_revision > 0),
    PRIMARY KEY (scope_id, pair_binding)
);
