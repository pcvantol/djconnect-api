-- Source-only, exact receiving owner at the actual Source181 INSERT boundary.
-- A delayed asynchronous issuer may not leave a live purpose after withdrawal.
CREATE TRIGGER IF NOT EXISTS host_wake_receiving_issuer_guard
BEFORE INSERT ON host_app_wake_purposes
BEGIN
 SELECT RAISE(ABORT,'host_wake_issuer_eligibility')
 WHERE NOT EXISTS(
  SELECT 1 FROM host_wake_issuer_once s
  JOIN host_wake_operator_authorizations a ON a.authorization_id=s.authorization_id
  JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id
  WHERE s.private_purpose_id=NEW.purpose_id AND s.outcome='reserved' AND a.outcome='authorized' AND i.disabled=0
  AND s.original_request_expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
  AND s.issued_at<=CAST(unixepoch('subsec')*1000 AS INTEGER) AND s.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
  AND a.issued_at<=CAST(unixepoch('subsec')*1000 AS INTEGER) AND a.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
  AND NEW.issued_at=s.issued_at AND NEW.expires_at=s.expires_at
  AND NEW.host_bundle=json_extract(s.original_json,'$.target.host_bundle_id')
  AND NEW.install_id=json_extract(s.original_json,'$.target.installation_id')
  AND NEW.environment=json_extract(s.original_json,'$.apns_environment')
  AND json_extract(NEW.scope_json,'$.owner_binding')=json_extract(s.original_json,'$.owner_binding')
  AND json_extract(NEW.scope_json,'$.device_binding')=json_extract(s.original_json,'$.device_binding')
  AND json_extract(NEW.scope_json,'$.source_binding')=json_extract(s.original_json,'$.source_binding')
  AND json_extract(NEW.scope_json,'$.platform')=json_extract(s.original_json,'$.platform')
  AND json_extract(NEW.scope_json,'$.display_expires_at_ms')=json_extract(s.original_json,'$.original_display_expires_at_ms')
  AND NEW.max_operations=json_extract(a.authorization_json,'$.max_operations')
  AND NEW.max_wakes=json_extract(a.authorization_json,'$.max_reserved_sends')
  AND NOT EXISTS(SELECT 1 FROM host_wake_child_withdrawals f WHERE f.authorization_id=s.authorization_id AND f.core_purpose_id=s.core_purpose_id)
 );
END;
