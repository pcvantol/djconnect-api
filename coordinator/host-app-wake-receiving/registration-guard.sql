-- One original verified proof is consumed in Source181's same register transaction.
CREATE TRIGGER IF NOT EXISTS host_wake_receiving_registration_guard
BEFORE UPDATE OF outcome ON host_app_wake_operations
WHEN NEW.outcome='registered' AND OLD.outcome='conflict'
BEGIN
 SELECT RAISE(ABORT,'host_wake_registration_eligibility')
 WHERE NEW.kind!='register' OR NEW.expires_at<=CAST(unixepoch('subsec')*1000 AS INTEGER)
 OR NOT EXISTS(SELECT 1 FROM host_wake_current_verified_targets e
  WHERE e.private_purpose_id=NEW.purpose_id AND e.semantic_operation_id=NEW.operation_id
  AND e.generation=NEW.generation AND e.revision=NEW.revision AND e.consumed_at IS NULL);
 UPDATE host_wake_native_verifications
 SET consumed_at=CAST(unixepoch('subsec')*1000 AS INTEGER),register_operation_id=NEW.operation_id,register_claim_id=NEW.claim_id
 WHERE challenge_id IN(SELECT e.challenge_id FROM host_wake_current_verified_targets e
  WHERE e.private_purpose_id=NEW.purpose_id AND e.semantic_operation_id=NEW.operation_id
  AND e.generation=NEW.generation AND e.revision=NEW.revision AND e.consumed_at IS NULL);
END;
