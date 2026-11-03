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
