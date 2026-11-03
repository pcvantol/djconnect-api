-- Qualification schema only. This is not a production migration.
CREATE TABLE watch_lifecycle_issuer (
  installation TEXT PRIMARY KEY,
  epoch INTEGER NOT NULL,
  key_fingerprint TEXT NOT NULL,
  scope TEXT NOT NULL,
  active INTEGER NOT NULL CHECK (active IN (0, 1))
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
