-- Source-only atomic dispatch boundary; no remote Core-state claim.
CREATE TRIGGER IF NOT EXISTS host_wake_receiving_dispatch_guard
BEFORE UPDATE OF outcome ON host_app_wake_operations
WHEN NEW.outcome='dispatch_started' AND OLD.outcome='reserved'
BEGIN
 SELECT RAISE(ABORT,'host_wake_dispatch_eligibility')
 WHERE NEW.kind!='wake' OR NEW.expires_at<=CAST(unixepoch('subsec')*1000 AS INTEGER)
 OR NOT EXISTS(SELECT 1 FROM host_wake_current_verified_targets e
  WHERE e.private_purpose_id=NEW.purpose_id AND e.generation=NEW.generation AND e.revision=NEW.revision
  AND e.consumed_at IS NOT NULL
  AND EXISTS(SELECT 1 FROM host_app_wake_operations r WHERE r.purpose_id=NEW.purpose_id
   AND r.operation_id=e.semantic_operation_id AND r.kind='register' AND r.outcome='registered' AND r.claim_id=e.register_claim_id));
END;
