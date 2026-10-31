-- Source-only local eligibility, not a native enrollment producer.
CREATE VIEW IF NOT EXISTS host_wake_current_verified_targets AS
SELECT s.private_purpose_id, j.challenge_id, j.operation_id AS semantic_operation_id, j.generation, j.revision, v.consumed_at, v.register_claim_id FROM host_wake_issuer_once s
  JOIN host_wake_operator_authorizations a ON a.authorization_id=s.authorization_id
  JOIN install_tokens i ON i.id=a.core_install_token_record_id AND i.ha_install_id=a.ha_install_id
  JOIN host_app_wake_purposes p ON p.purpose_id=s.private_purpose_id
  JOIN host_wake_native_jobs j ON j.authorization_id=s.authorization_id AND j.core_purpose_id=s.core_purpose_id
  JOIN host_wake_native_verifications v ON v.challenge_id=j.challenge_id
  JOIN host_wake_native_enrollments n ON n.native_key_ref=v.native_key_ref
  WHERE (
   1=1
   AND s.private_purpose_id=p.purpose_id
   AND s.outcome='issued'
   AND a.outcome='authorized'
   AND i.disabled=0
   AND a.issued_at<=CAST(unixepoch('subsec')*1000 AS INTEGER)
   AND a.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
   AND s.issued_at<=CAST(unixepoch('subsec')*1000 AS INTEGER)
  )
  AND (
   s.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
   AND p.withdrawn=0
   AND p.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
   AND p.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
   AND p.generation=j.generation
   AND p.revision=j.revision
   AND j.generation=p.generation
   AND j.revision=p.revision
  )
  AND (
   j.outcome='verified' AND v.private_job_id=j.private_job_id
   AND j.original_json=s.original_json
   AND v.original_json=j.original_json
   AND n.native_key_ref=json_extract(a.authorization_json,'$.native_key_ref')
   AND n.disabled=0
   AND n.counter>=v.verified_counter
   AND length(n.native_key_id_b64)=44
   AND substr(n.native_key_id_b64,44,1)='='
  )
  AND (
   substr(n.native_key_id_b64,1,43) NOT GLOB '*[^A-Za-z0-9+/]*'
   AND substr(n.native_key_id_b64,43,1) IN ('A','E','I','M','Q','U','Y','c','g','k','o','s','w','0','4','8')
   AND length(n.enrollment_receipt_sha256)=64
   AND n.enrollment_receipt_sha256 NOT GLOB '*[^a-f0-9]*'
   AND length(n.signed_environment_receipt_sha256)=64
   AND n.signed_environment_receipt_sha256 NOT GLOB '*[^a-f0-9]*'
   AND n.issued_at<=CAST(unixepoch('subsec')*1000 AS INTEGER)
   AND n.expires_at>CAST(unixepoch('subsec')*1000 AS INTEGER)
  )
  AND (
   n.host_bundle=p.host_bundle
   AND n.install_id=p.install_id
   AND n.environment=p.environment
   AND n.host_bundle=json_extract(j.original_json,'$.target.host_bundle_id')
   AND n.install_id=json_extract(j.original_json,'$.target.installation_id')
   AND n.platform=json_extract(j.original_json,'$.platform')
   AND n.environment=json_extract(j.original_json,'$.apns_environment')
   AND n.native_key_id_b64=json_extract(j.original_json,'$.native_key_id_b64')
  )
  AND (
   n.identity_policy_sha256=json_extract(j.original_json,'$.identity_policy_sha256')
   AND n.deployment_policy_sha256=json_extract(j.original_json,'$.deployment_policy_sha256')
   AND n.identity_policy_sha256=json_extract(a.authorization_json,'$.identity_policy_sha256')
   AND n.deployment_policy_sha256=json_extract(a.authorization_json,'$.deployment_policy_sha256')
   AND json_extract(p.scope_json,'$.owner_binding')=json_extract(j.original_json,'$.owner_binding')
   AND json_extract(p.scope_json,'$.device_binding')=json_extract(j.original_json,'$.device_binding')
   AND json_extract(p.scope_json,'$.source_binding')=json_extract(j.original_json,'$.source_binding')
  )
 AND (v.verified_at>=j.captured_at AND v.verified_at<j.expires_at)
 AND (j.operation_id=json_extract(j.original_json,'$.operation_id') AND j.generation=json_extract(j.original_json,'$.generation') AND j.revision=json_extract(j.original_json,'$.revision'));
