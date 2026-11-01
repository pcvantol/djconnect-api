-- A new v2 key can be installed only inside its actual claimed first-attest
-- transaction. Legacy trusted fixture/import rows are not a first-enroller.
CREATE TRIGGER IF NOT EXISTS host_wake_native_key_insert_guard
BEFORE INSERT ON host_wake_native_enrollments WHEN NEW.native_policy_json IS NOT NULL
BEGIN
 SELECT RAISE(ABORT,'host_wake_native_enrollment_context') WHERE NOT EXISTS(
  SELECT 1 FROM host_wake_native_pending_policies p JOIN host_wake_native_jobs j ON j.private_job_id=p.attestation_job_id
  JOIN host_wake_operator_authorizations a ON a.authorization_id=p.authorization_id
  JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id
  JOIN host_wake_issuer_once s ON s.authorization_id=j.authorization_id AND s.core_purpose_id=j.core_purpose_id
  WHERE p.native_key_ref=NEW.native_key_ref AND p.policy_json=NEW.native_policy_json AND p.native_key_id_b64=NEW.native_key_id_b64
  AND p.outcome='enrolled' AND p.enrollment_claim=NEW.enrollment_claim AND p.attestation_job_id=NEW.enrollment_job_id
  AND j.proof_kind='app_attest_attestation' AND j.outcome='verifying' AND j.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
  AND p.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER) AND a.outcome='authorized' AND a.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
  AND i.disabled=0 AND s.native_proof_kind='app_attest_attestation' AND s.outcome='issued' AND s.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER) AND s.original_json=j.original_json
  AND typeof(NEW.common_status_checked_at)='integer' AND typeof(NEW.common_status_expires_at)='integer'
  AND NEW.common_status_checked_at>=0 AND NEW.common_status_checked_at<=NEW.issued_at
  AND NEW.common_status_expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER) AND NEW.expires_at<=NEW.common_status_expires_at
  AND NEW.counter=0 AND NEW.disabled=0 AND NEW.issued_at<=CAST(unixepoch('subsec')*1000 AS INTEGER)
  AND NEW.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER) AND NEW.expires_at<=p.expires_at
  AND NEW.host_bundle=json_extract(p.policy_json,'$.scope.target.host_bundle_id') AND NEW.install_id=json_extract(p.policy_json,'$.scope.target.installation_id')
  AND NEW.platform=json_extract(p.policy_json,'$.scope.platform') AND NEW.environment=json_extract(p.policy_json,'$.scope.apns_environment')
  AND NEW.identity_policy_sha256=json_extract(p.policy_json,'$.scope.identity_policy_sha256') AND NEW.deployment_policy_sha256=json_extract(p.policy_json,'$.scope.deployment_policy_sha256')
  AND NEW.signed_environment_receipt_sha256=json_extract(p.policy_json,'$.signed_environment_receipt_sha256')
  AND json_extract(NEW.assertion_policy_json,'$.profile')='host_wake_apple_assertion_properties_v2'
  AND json_extract(NEW.assertion_policy_json,'$.app_identifier')=json_extract(p.policy_json,'$.app_identifier')
  AND json_extract(NEW.assertion_policy_json,'$.bundle_version')=json_extract(p.policy_json,'$.bundle_version')
  AND ((json_extract(p.policy_json,'$.profile')='host_wake_apple_properties_attestation_v2'
    AND json_extract(NEW.assertion_policy_json,'$.launch_validation_category_b64')=json_extract(p.policy_json,'$.launch_validation_category_b64'))
   OR (json_extract(p.policy_json,'$.profile')='host_wake_apple_properties_attestation_v3'
    AND EXISTS(SELECT 1 FROM json_each(p.policy_json,'$.allowed_launch_validation_categories_b64') c
     WHERE c.value=json_extract(NEW.assertion_policy_json,'$.launch_validation_category_b64'))))
 );
END;
