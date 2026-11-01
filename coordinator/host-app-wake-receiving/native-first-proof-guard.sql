-- Counter zero means initial attestation, not a first assertion. Any late or
-- mismatched positive proof aborts the complete policy/key/proof transaction.
CREATE TRIGGER IF NOT EXISTS host_wake_native_first_proof_guard
BEFORE INSERT ON host_wake_native_verifications WHEN NEW.verified_counter=0
BEGIN
 SELECT RAISE(ABORT,'host_wake_native_first_proof_context') WHERE NOT EXISTS(
  SELECT 1 FROM host_wake_native_jobs j JOIN host_wake_native_enrollments n ON n.native_key_ref=NEW.native_key_ref
  JOIN host_wake_native_pending_policies p ON p.native_key_ref=n.native_key_ref
  JOIN host_wake_operator_authorizations a ON a.authorization_id=j.authorization_id
  JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id
  JOIN host_wake_issuer_once s ON s.authorization_id=j.authorization_id AND s.core_purpose_id=j.core_purpose_id
  WHERE j.challenge_id=NEW.challenge_id AND j.private_job_id=NEW.private_job_id AND j.original_json=NEW.original_json
  AND j.proof_kind='app_attest_attestation' AND j.outcome='verifying' AND j.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
  AND NEW.verified_at>=j.captured_at AND NEW.verified_at<j.expires_at AND NEW.consumed_at IS NULL
  AND n.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
  AND n.common_status_checked_at<=NEW.verified_at AND NEW.verified_at<n.common_status_expires_at
  AND n.common_status_expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER) AND n.expires_at<=n.common_status_expires_at
  AND n.enrollment_job_id=j.private_job_id AND n.enrollment_claim=NEW.commit_claim AND n.counter=0 AND n.disabled=0
  AND p.outcome='enrolled' AND p.attestation_job_id=j.private_job_id AND p.enrollment_claim=NEW.commit_claim AND p.policy_json=n.native_policy_json
  AND p.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER) AND a.outcome='authorized' AND a.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
  AND i.disabled=0 AND s.native_proof_kind='app_attest_attestation' AND s.outcome='issued' AND s.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER) AND s.original_json=j.original_json
 );
END;
