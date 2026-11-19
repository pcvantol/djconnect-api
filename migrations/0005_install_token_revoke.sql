ALTER TABLE install_tokens ADD COLUMN revoked_at TEXT;
ALTER TABLE install_tokens ADD COLUMN revoke_reason TEXT;
