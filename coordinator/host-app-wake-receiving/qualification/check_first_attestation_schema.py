"""Standard schema checks for first-attestation synthetic protocol SHAPES only."""
from pathlib import Path
import copy
import hashlib
import json
from jsonschema import Draft202012Validator
root = Path(__file__).parent
vectors = json.loads((root / 'private-first-attestation-vectors.json').read_bytes())
private_schema = json.loads((root / 'private-receiving-ports.schema.json').read_bytes())
policy_schema = json.loads((root / 'private-native-policy.schema.json').read_bytes())
for schema in (private_schema, policy_schema):
    Draft202012Validator.check_schema(schema)
cases = []
for row in vectors['cases']:
    for direction in ('request', 'reply'):
        cases.append((private_schema, {'method': 'POST', 'path': '/v1/push/host-app-wake/' + row['route'], 'direction': direction, 'body': row[direction]}))
for direction in ('request', 'reply'):
    cases.append((private_schema, {'method': 'POST', 'path': vectors['resolve']['path'], 'direction': direction, 'body': vectors['resolve'][direction]}))
p = vectors['policy_request']
cases.append((policy_schema, {'method': 'POST', 'path': p['route'], 'direction': 'request', 'body': p}))
cases.append((policy_schema, {'method': 'POST', 'path': p['route'], 'direction': 'reply', 'body': {'version': p['version'], 'native_key_ref': p['native_key_ref'], 'outcome': 'pending'}}))
withdraw_path = p['route'] + '/withdraw'
cases.append((policy_schema, {'method': 'POST', 'path': withdraw_path, 'direction': 'request', 'body': {'version': p['version'], 'method': 'POST', 'route': withdraw_path, 'action': 'native_policy_withdraw', 'operation_id': 'fixture-policy-withdrawal', 'native_key_ref': p['native_key_ref']}}))
cases.append((policy_schema, {'method': 'POST', 'path': withdraw_path, 'direction': 'reply', 'body': {'version': p['version'], 'native_key_ref': p['native_key_ref'], 'outcome': 'withdrawn'}}))
for allowed in [['AgAAAA=='], ['AgAAAA==','AwAAAA=='], ['AgAAAA==','AwAAAA==','BAAAAA==','BQAAAA==']]:
    first=copy.deepcopy(p)
    del first['launch_validation_category_b64']
    first.update(profile='host_wake_apple_properties_attestation_v3',allowed_launch_validation_categories_b64=allowed)
    cases.append((policy_schema, {'method':'POST','path':p['route'],'direction':'request','body':first}))
passed = negatives = 0
for schema, value in cases:
    validator = Draft202012Validator(schema)
    validator.validate(value)
    passed += 1
    for change in ('unknown', 'path', 'method'):
        v = copy.deepcopy(value)
        if change == 'unknown':
            v['body']['unexpected'] = True
        elif change == 'path':
            v['path'] += '/unowned'
        else:
            v['method'] = 'GET'
        assert not validator.is_valid(v)
        negatives += 1
print(json.dumps({'scope': 'SYNTHETIC_PROTOCOL_SHAPES_NOT_ACTUAL_APPLE_TRUST_OR_POLICY_ADMISSION', 'positive_pass': passed, 'negative_pass': negatives, 'private_schema_sha256': hashlib.sha256((root / 'private-receiving-ports.schema.json').read_bytes()).hexdigest(), 'policy_schema_sha256': hashlib.sha256((root / 'private-native-policy.schema.json').read_bytes()).hexdigest()}, indent=2))
