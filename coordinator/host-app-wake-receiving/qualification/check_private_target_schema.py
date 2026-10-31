"""Actual standard schema validation for synthetic private target DATA only."""
import copy
import hashlib
import json
from pathlib import Path
from jsonschema import Draft202012Validator
root = Path(__file__).parent
raw = (root / 'private-target-ports.schema.json').read_bytes()
schema = json.loads(raw)
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)
vectors = json.loads((root / 'private-target-ports-vectors.json').read_bytes())
cases = []
for row in vectors['cases']:
    cases.append({'method': 'POST', 'path': row['path'], 'direction': 'request',
                  'headers': row['request_headers'], 'body': row['request']})
    cases.append({'method': 'POST', 'path': row['path'], 'direction': 'reply',
                  'status': row['status'], 'headers': row['reply_headers'], 'body': row['reply']})
for row in vectors['errors']:
    for route in ('register', 'wake', 'status', 'revoke'):
        cases.append({'method': 'POST', 'path': '/v1/push/host-app-wake/' + route,
                      'direction': 'error', 'status': row['status'], 'body': row['body']})
positive = negative = total_negative = 0
for case in cases:
    validator.validate(case)
    positive += 1
    for change in ('unknown_body', 'wrong_method', 'wrong_path'):
        value = copy.deepcopy(case)
        if change == 'unknown_body':
            value['body']['unexpected'] = True
        elif change == 'wrong_method':
            value['method'] = 'PUT'
        else:
            value['path'] += '/foreign'
        total_negative += 1
        negative += not validator.is_valid(value)
    if 'headers' in case:
        for change in ('missing_header', 'combined_header', 'unknown_header'):
            value = copy.deepcopy(case)
            key = next(iter(value['headers']))
            if change == 'missing_header':
                del value['headers'][key]
            elif change == 'combined_header':
                value['headers'][key] += ', duplicate'
            else:
                value['headers']['unexpected'] = 'value'
            total_negative += 1
            negative += not validator.is_valid(value)
result = {'schema_sha256': hashlib.sha256(raw).hexdigest(),
          'positive_pass': positive, 'positive_total': len(cases),
          'negative_pass': negative, 'negative_total': total_negative,
          'scope': 'Structural synthetic DATA, not runtime/native/provider acceptance'}
print(json.dumps(result, indent=2))
assert positive == len(cases) and negative == total_negative
