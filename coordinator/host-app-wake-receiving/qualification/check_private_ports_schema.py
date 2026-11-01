"""Validate private DATA vectors using the standard Draft 2020-12 engine.

Requires an existing jsonschema installation; does not install dependencies.
The HTTP payload is body-only. The method/path/direction wrapper is a validation
fixture and does not supply an original parent, role, native proof or permission.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
from jsonschema import Draft202012Validator

parser = argparse.ArgumentParser()
parser.add_argument('--source-directory', type=Path, default=Path(__file__).parent)
args = parser.parse_args()
root = args.source_directory
schema_bytes = (root / 'private-receiving-ports.schema.json').read_bytes()
schema = json.loads(schema_bytes)
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)
vectors = json.loads((root / 'private-server-reply-vectors.json').read_bytes())
resolve = json.loads((root / 'private-resolve-vectors.json').read_bytes())
cases = []
for row in vectors['cases']:
    for direction in ('request', 'reply'):
        cases.append({'method': 'POST', 'path': '/v1/push/host-app-wake/' + row['route'],
                      'direction': direction, 'body': row[direction]})
for direction in ('request', 'reply'):
    cases.append({'method': 'POST', 'path': resolve['path'],
                  'direction': direction, 'body': resolve[direction]})
results = []
for case in cases:
    result = {'path': case['path'], 'direction': case['direction']}
    try:
        result['positive_pass'] = validator.is_valid(case)
        negatives = []
        for change in ('body_extra', 'wrong_path', 'wrong_method'):
            altered = copy.deepcopy(case)
            if change == 'body_extra':
                altered['body']['unexpected'] = True
            elif change == 'wrong_path':
                altered['path'] += '/unowned'
            else:
                altered['method'] = 'GET'
            negatives.append(not validator.is_valid(altered))
        result['negative_passes'] = sum(negatives)
    except Exception as error:
        result['positive_pass'] = False
        result['negative_passes'] = 0
        result['exception'] = type(error).__name__
        result['message'] = str(error)[:200]
    results.append(result)
passed = sum(row['positive_pass'] for row in results)
negative = sum(row['negative_passes'] for row in results)
print(json.dumps({'schema_sha256': hashlib.sha256(schema_bytes).hexdigest(),
                  'positive_pass': passed, 'positive_total': len(cases),
                  'negative_pass': negative, 'negative_total': len(cases) * 3,
                  'results': results}, indent=2))
raise SystemExit(0 if passed == len(cases) and negative == len(cases) * 3 else 1)
