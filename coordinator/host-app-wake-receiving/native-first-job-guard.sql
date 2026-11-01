-- One initial attestation attempt per actual custodian policy/SDK key. A new
-- parent/transport UUID cannot repair a lost nonce or unknown enrollment.
CREATE TRIGGER IF NOT EXISTS host_wake_native_first_job_guard
BEFORE INSERT ON host_wake_native_jobs WHEN NEW.proof_kind='app_attest_attestation'
BEGIN
 SELECT RAISE(ABORT,'host_wake_native_policy_job_consumed') WHERE NOT EXISTS(
  SELECT 1 FROM host_wake_native_pending_policies p JOIN host_wake_operator_authorizations a ON a.authorization_id=p.authorization_id
  JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id
  WHERE p.authorization_id=NEW.authorization_id AND p.native_key_ref=json_extract(a.authorization_json,'$.native_key_ref')
  AND p.native_key_id_b64=json_extract(NEW.original_json,'$.native_key_id_b64') AND p.outcome='pending' AND p.attestation_job_id IS NULL
  AND p.issued_at<=CAST(unixepoch('subsec')*1000 AS INTEGER) AND p.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
  AND a.outcome='authorized' AND i.disabled=0 AND a.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
 );
 UPDATE host_wake_native_pending_policies SET attestation_job_id=NEW.private_job_id WHERE authorization_id=NEW.authorization_id
 AND native_key_id_b64=json_extract(NEW.original_json,'$.native_key_id_b64') AND outcome='pending' AND attestation_job_id IS NULL;
END;
