"""Independent synthetic protocol shapes. No vendor proof or enrollment fact."""
from pathlib import Path
import base64
import hashlib
import json
root = Path(__file__).parent
base = json.loads((root / 'private-server-reply-vectors.json').read_bytes())
resolve = json.loads((root / 'private-resolve-vectors.json').read_bytes())
canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
hash_value = lambda value: hashlib.sha256(canonical(value).encode()).hexdigest()
original = base['original']
original['native_key_id_b64'] = resolve['request']['scope']['native_key_id_b64']
for row in base['cases']:
    kind = row['route']
    request = row['request']
    reply = row['reply']
    if 'original' in request:
        request['original'] = original
    if 'original' in reply:
        reply['original'] = original
    if 'native_proof_kind' in reply:
        reply['native_proof_kind'] = 'app_attest_attestation'
    if 'native_proof' in request:
        request['native_proof'] = {'kind': 'app_attest_attestation', 'bytes_b64': base64.b64encode(b'MODELED DATA ONLY; NOT APPLE PROOF').decode()}
    if 'original_sha256' in reply:
        reply['original_sha256'] = hash_value(original)
    if kind == 'native/challenge':
        text = canonical({'original': original, 'challenge': reply['challenge']})
        reply['canonical_transcript_utf8'] = text
        reply['client_data_sha256'] = hashlib.sha256(('DJC-HOST-APP-WAKE-TARGET-REGISTER-V1\n' + text).encode()).hexdigest()
    digest = hash_value(['DJC-HOST-WAKE-API-REQUEST-V1', 'POST', '/v1/push/host-app-wake/' + kind, request])
    row['request_sha256'] = digest
    reply['request_sha256'] = digest
resolve['reply']['native_proof_kind'] = 'app_attest_attestation'
scope_keys = ['paired_subject_binding_sha256', 'owner_binding', 'device_binding', 'source_binding', 'selected_ha_origin_sha256', 'identity_policy_sha256', 'deployment_policy_sha256', 'target', 'platform', 'apns_environment']
policy = {'version': 'djc-host-app-wake-receiving/1', 'method': 'POST', 'route': '/v1/push/host-app-wake/operator/native-policy', 'action': 'native_policy', 'operation_id': 'fixture-first-policy-operation', 'authorization_id': base['cases'][0]['request']['authorization_id'], 'native_key_ref': 'fixture-private-custodian-reference', 'native_key_id_b64': original['native_key_id_b64'], 'profile': 'host_wake_apple_properties_attestation_v2', 'app_identifier': 'ABCDEFGHIJ.' + original['target']['host_bundle_id'], 'apns_team_id': 'ABCDEFGHIJ', 'app_attest_environment': 'development', 'bundle_version': '1.0', 'launch_validation_category_b64': base64.b64encode(bytes([3, 0, 0, 0])).decode(), 'signed_host_artifact_sha256': 'a' * 64, 'signed_environment_receipt_sha256': 'b' * 64, 'scope': {key: original[key] for key in scope_keys}, 'original_policy_issued_at_ms': original['original_wake_issued_at_ms'], 'original_policy_expires_at_ms': original['original_display_expires_at_ms']}
result = {'classification': 'SYNTHETIC_PROTOCOL_SHAPES_ONLY; POSITIVE_NATIVE_REPLIES_ARE_MODELED_DATA_NOT_OBSERVED_APPLE_PROOF_OR_ADMISSION', 'original': original, 'retained_proof_kind': 'app_attest_attestation', 'policy_request': policy, 'resolve': resolve, 'cases': base['cases'], 'invalid_proof_runtime_expectation': {'status': 403, 'body': {'version': 'djc-host-app-wake-receiving/1', 'success': False, 'error': 'host_wake_native_proof_rejected'}}, 'immutable_boundaries': {'key_reference': 'native_key_ref PRIVATE API custodian row; native_key_id_b64 actual public SDK32-byte identifier only', 'first_key_attempt': 'exactly one API-private first job per pending policy/SDK key; no new UUID/parent after UNKNOWN', 'issuer_kind': 'selected from actual state and persisted at original issuer reservation; never flip a prepared child kind after another child enrolls', 'transcript': 'unchanged R31 public fields and actual LF; no private IDs', 'clock_and_effects': 'NO genuine signed host, SDK key, native clock, device, provider or production qualification supplied'}}
(root / 'private-first-attestation-vectors.json').write_text(json.dumps(result, indent=2) + '\n')
