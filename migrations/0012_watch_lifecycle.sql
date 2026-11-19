-- Additive Watch lifecycle storage. This migration installs no authority or initial data.
CREATE TABLE watch_lifecycle_issuer (
  installation TEXT PRIMARY KEY,
  epoch INTEGER NOT NULL,
  key_fingerprint TEXT NOT NULL,
  scope TEXT NOT NULL,
  active INTEGER NOT NULL CHECK (active IN (0, 1)),
  public_spki_hex TEXT
);
CREATE TABLE watch_lifecycle_preference (
  installation TEXT NOT NULL,
  receiver TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  incarnation TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  sealed INTEGER NOT NULL DEFAULT 0 CHECK (sealed IN (0, 1)),
  retired INTEGER NOT NULL DEFAULT 0 CHECK (retired IN (0, 1)),
  lifecycle_revision INTEGER NOT NULL DEFAULT 0,
  lifecycle_operation TEXT,
  lifecycle_hash TEXT,
  operation TEXT,
  body_hash TEXT,
  PRIMARY KEY (installation, receiver)
);
CREATE TABLE watch_lifecycle_intent (
  installation TEXT NOT NULL,
  receiver TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  incarnation TEXT NOT NULL,
  operation TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  PRIMARY KEY (installation, receiver, epoch, incarnation, operation)
);
CREATE TRIGGER watch_lifecycle_record_intent
AFTER UPDATE OF revision ON watch_lifecycle_preference
WHEN NEW.sealed = 0 AND NEW.revision = OLD.revision + 1 AND NEW.incarnation = OLD.incarnation AND NEW.epoch = OLD.epoch
BEGIN
  INSERT INTO watch_lifecycle_intent VALUES (
    NEW.installation, NEW.receiver, NEW.epoch, NEW.incarnation, NEW.operation, NEW.body_hash
  );
END;

CREATE TABLE watch_lifecycle_incarnation (
  installation TEXT NOT NULL,
  receiver TEXT NOT NULL,
  incarnation TEXT NOT NULL,
  PRIMARY KEY (installation, receiver, incarnation)
);
CREATE TRIGGER watch_lifecycle_initial_incarnation
AFTER INSERT ON watch_lifecycle_preference
BEGIN
  INSERT INTO watch_lifecycle_incarnation VALUES (NEW.installation, NEW.receiver, NEW.incarnation);
END;
CREATE TRIGGER watch_lifecycle_replacement_incarnation
AFTER UPDATE OF incarnation ON watch_lifecycle_preference
WHEN NEW.incarnation != OLD.incarnation
BEGIN
  INSERT INTO watch_lifecycle_incarnation VALUES (NEW.installation, NEW.receiver, NEW.incarnation);
END;

CREATE TABLE watch_lifecycle_receipt (
  installation TEXT NOT NULL,
  receiver TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  operation TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  incarnation TEXT NOT NULL,
  revision INTEGER NOT NULL,
  retired INTEGER NOT NULL,
  PRIMARY KEY (installation, receiver, epoch, operation)
);
CREATE TRIGGER watch_lifecycle_first_receipt
AFTER INSERT ON watch_lifecycle_preference
WHEN NEW.lifecycle_operation IS NOT NULL
BEGIN
  INSERT INTO watch_lifecycle_receipt VALUES (
    NEW.installation, NEW.receiver, NEW.epoch, NEW.lifecycle_operation,
    NEW.lifecycle_hash, NEW.incarnation, NEW.lifecycle_revision, NEW.retired
  );
END;
CREATE TRIGGER watch_lifecycle_next_receipt
AFTER UPDATE OF lifecycle_revision ON watch_lifecycle_preference
WHEN NEW.lifecycle_revision = OLD.lifecycle_revision + 1
BEGIN
  INSERT INTO watch_lifecycle_receipt VALUES (
    NEW.installation, NEW.receiver, NEW.epoch, NEW.lifecycle_operation,
    NEW.lifecycle_hash, NEW.incarnation, NEW.lifecycle_revision, NEW.retired
  );
END;

CREATE TABLE watch_lifecycle_enrollment (
  challenge_id TEXT PRIMARY KEY,
  audience TEXT NOT NULL,
  installation TEXT NOT NULL,
  operator_binding TEXT NOT NULL UNIQUE,
  restore_fence TEXT NOT NULL,
  nonce_hash TEXT NOT NULL UNIQUE,
  key_fingerprint TEXT NOT NULL,
  public_spki_hex TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  predecessor_epoch INTEGER,
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1))
);
CREATE TRIGGER watch_lifecycle_activate_issuer
AFTER UPDATE OF consumed ON watch_lifecycle_enrollment
WHEN OLD.consumed = 0 AND NEW.consumed = 1
BEGIN
  INSERT INTO watch_lifecycle_issuer(installation, epoch, key_fingerprint, scope, active, public_spki_hex)
  VALUES (NEW.installation, NEW.epoch, NEW.key_fingerprint, 'watch-lifecycle', 1, NEW.public_spki_hex)
  ON CONFLICT(installation) DO UPDATE SET epoch=excluded.epoch, key_fingerprint=excluded.key_fingerprint,
    scope=excluded.scope, active=excluded.active, public_spki_hex=excluded.public_spki_hex;
END;

CREATE TABLE watch_lifecycle_recovery (
  grant_id TEXT PRIMARY KEY,
  installation TEXT NOT NULL,
  receiver TEXT NOT NULL,
  predecessor_epoch INTEGER NOT NULL,
  predecessor TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  key_fingerprint TEXT NOT NULL,
  incarnation TEXT NOT NULL,
  operator_binding TEXT NOT NULL,
  restore_fence TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0, 1)),
  operation TEXT,
  body_hash TEXT
);
CREATE TRIGGER watch_lifecycle_recover_receiver
AFTER UPDATE OF consumed ON watch_lifecycle_recovery
WHEN OLD.consumed = 0 AND NEW.consumed = 1
BEGIN
  UPDATE watch_lifecycle_preference
    SET epoch=NEW.epoch, incarnation=NEW.incarnation, revision=0, enabled=0, sealed=0, retired=0,
        operation=NULL, body_hash=NULL, lifecycle_revision=lifecycle_revision+1,
        lifecycle_operation=NEW.operation, lifecycle_hash=NEW.body_hash
  WHERE installation=NEW.installation AND receiver=NEW.receiver
    AND epoch=NEW.predecessor_epoch AND incarnation=NEW.predecessor;
END;
