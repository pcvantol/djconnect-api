CREATE TABLE widget_first_key_retirements (
    pair_binding TEXT NOT NULL PRIMARY KEY
);

CREATE TABLE widget_first_key_decisions (
    credential_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    PRIMARY KEY (credential_id, decision_id)
);

CREATE INDEX widget_first_key_decision_expiry ON widget_first_key_decisions(expires_at_ms);

CREATE TABLE widget_first_key (
    credential_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    installation_id TEXT NOT NULL UNIQUE,
    policy_id TEXT NOT NULL,
    pair_binding TEXT NOT NULL,
    original_request TEXT NOT NULL,
    challenge TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    key_spki TEXT,
    transcript_sha256 TEXT,
    receipt TEXT,
    retired INTEGER NOT NULL DEFAULT 0 CHECK (retired IN (0, 1)),
    status_nonce TEXT,
    status_nonce_id TEXT,
    status_expires_at_ms INTEGER,
    PRIMARY KEY (credential_id, operation_id)
);
CREATE UNIQUE INDEX widget_first_key_one_per_pair
    ON widget_first_key(pair_binding) WHERE receipt IS NOT NULL;
