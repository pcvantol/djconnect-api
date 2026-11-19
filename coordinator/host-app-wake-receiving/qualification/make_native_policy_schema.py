"""Closed structural operator policy DATA; HMAC/runtime checks are separate."""
import base64
import json
import re
from pathlib import Path
root = Path(__file__).parent
obj = lambda p: {'type': 'object', 'additionalProperties': False, 'required': list(p), 'properties': p}
const = lambda v: {'const': v}
id_value = {'type': 'string', 'pattern': '^[A-Za-z0-9_-]{1,128}$'}
hash_value = {'type': 'string', 'pattern': '^[a-f0-9]{64}$'}
time = {'type': 'integer', 'minimum': 0, 'maximum': 9007199254740991}
version = const('djc-host-app-wake-receiving/1')
paths = ['/v1/push/host-app-wake/operator/native-policy', '/v1/push/host-app-wake/operator/native-policy/withdraw']
scope = {k: hash_value for k in ['paired_subject_binding_sha256', 'owner_binding', 'device_binding', 'source_binding', 'selected_ha_origin_sha256', 'identity_policy_sha256', 'deployment_policy_sha256']}
scope.update(target=obj({'host_bundle_id': {'type': 'string', 'maxLength': 200, 'pattern': '^[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+$'}, 'installation_id': id_value}), platform={'enum': ['ios', 'ipados']}, apns_environment={'enum': ['sandbox', 'production']})
policy = obj({'version': version, 'method': const('POST'), 'route': const(paths[0]), 'action': const('native_policy'), 'operation_id': id_value, 'authorization_id': id_value, 'native_key_ref': id_value, 'native_key_id_b64': {'type': 'string', 'pattern': '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$'}, 'profile': const('host_wake_apple_properties_attestation_v2'), 'app_identifier': {'type': 'string', 'pattern': '^[A-Z0-9]{10}\\.[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+$'}, 'apns_team_id': {'type': 'string', 'pattern': '^[A-Z0-9]{10}$'}, 'app_attest_environment': {'enum': ['development', 'production']}, 'bundle_version': {'type': 'string', 'pattern': '^[0-9]{1,20}(?:\\.[0-9]{1,20}){0,2}$'}, 'launch_validation_category_b64': {'enum': [base64.b64encode(bytes([v, 0, 0, 0])).decode() for v in (2, 3, 4, 5)]}, 'signed_host_artifact_sha256': hash_value, 'signed_environment_receipt_sha256': hash_value, 'scope': obj(scope), 'original_policy_issued_at_ms': time, 'original_policy_expires_at_ms': time})
import copy
policy_v3=copy.deepcopy(policy)
policy_v3['properties']['profile']=const('host_wake_apple_properties_attestation_v3')
category_enum=policy_v3['properties'].pop('launch_validation_category_b64')
policy_v3['required'].remove('launch_validation_category_b64')
policy_v3['required'].append('allowed_launch_validation_categories_b64')
policy_v3['properties']['allowed_launch_validation_categories_b64']={'type':'array','minItems':1,'maxItems':4,'uniqueItems':True,'items':category_enum}
# Exact canonical ordering is additionally checked by the runtime.
policy={'oneOf':[policy,policy_v3]}
withdraw = obj({'version': version, 'method': const('POST'), 'route': const(paths[1]), 'action': const('native_policy_withdraw'), 'operation_id': id_value, 'native_key_ref': id_value})
branches = []
for path, body in zip(paths, [policy, withdraw]):
    branches.append(obj({'method': const('POST'), 'path': const(path), 'direction': const('request'), 'body': body}))
    branches.append(obj({'method': const('POST'), 'path': const(path), 'direction': const('reply'), 'body': obj({'version': version, 'native_key_ref': id_value, 'outcome': {'enum': ['pending', 'enrolled', 'withdrawn', 'expired']} if path == paths[0] else const('withdrawn')})}))
    source = (root.parent / 'server-reply.ts').read_text().split('Object.freeze({', 1)[1].split('});', 1)[0]
    for status, codes in re.findall(r'(\d+):\[([^\]]*)\]', source):
        branches.append(obj({'method': const('POST'), 'path': const(path), 'direction': const('error'), 'status': const(int(status)), 'body': obj({'version': version, 'success': const(False), 'error': {'enum': re.findall(r"'([^']+)'", codes)}})}))
result = {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'urn:djconnect:host-wake-private-native-policy:3', 'description': 'Structural DATA only. Actual existing custodian HMAC over timestamp plus exact body, signed method/path/action/version and original request window are mandatory. Runtime additionally compares appIdentifier/team/target, active operator/native scope and original expiry bounds. No key or policy is created by parsing this schema. Fields are explicit; no QA application/build/environment or actual signed-artifact fact is supplied.', 'oneOf': branches}
(root / 'private-native-policy.schema.json').write_text(json.dumps(result, indent=2) + '\n')
