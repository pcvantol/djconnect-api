#!/usr/bin/env python3
"""Offline preparation consistency only. Never grants or performs deployment."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SUPPLYING_SHA = 'ff9ff5778f698fc206d7953b9f407752d7dde840'
PROOF = 'docs/rendezvous/workerd-create-recovery-source-proof-v1.json'
PROOF_HASH = '23404d85009af067941fe7b6621f66aa9beb623946feddfea5ae3bf63903a6db'
REFERENCES = ('wrangler.jsonc', '.github/workflows/deploy-api-worker.yml', PROOF)
BINDINGS = {
    'REQUEST_ADMISSION': 'RequestAdmission',
    'ADMISSION_STATE': 'AllocationBudget',
    'ALLOCATION_INDEX': 'AllocationIndex',
    'ENROLLMENT_COORDINATOR': 'EnrollmentCoordinator',
    'COMPOSED_TRANSACTIONS': 'BudgetedTransactionCoordinator',
}
GATES = ('joint_contract_freeze', 'independent_full_protocol_security',
         'public_entrypoint_and_all_gated_paths', 'trusted_cf_ip_provenance',
         'edge_waf_rejected_traffic_spend', 'account_plan_and_shared_usage',
         'namespace_and_migration_collision', 'provider_status_and_error_taxonomy',
         'genuine_supported_signed_ios', 'ha_external_route_and_display_admission',
         'physical_iphone_ha_tv', 'load_latency_cpu_sql_duration',
         'approved_spend_and_capacity', 'platform_logs_retention_backups_dpa',
         'secret_presence_and_rotation', 'cleanup_alerts_and_physical_retention',
         'immutable_product_artifact', 'protected_main_and_separate_finalization',
         'applicable_central_manifest', 'exact_deployment_authorization',
         'compatible_rollback_readback', 'authorized_live_smoke')
SUCCESS = 'PREPARATION_CONSISTENT_BLOCKED_NOT_AUTHORIZED'


def require(value):
    if not value:
        raise ValueError('invalid_preparation')


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    require(len(raw) <= 1024 * 1024)
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_json')))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(name):
    # Paths are pinned constants or come from the independently pinned proof.
    safe_path(name)
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0',
                       GIT_OPTIONAL_LOCKS='0', GIT_NO_REPLACE_OBJECTS='1')
    result = subprocess.run(['git', 'cat-file', 'blob', SUPPLYING_SHA + ':' + name],
                            cwd=ROOT, capture_output=True, timeout=10, check=True,
                            env=environment)
    require(len(result.stdout) <= 2 * 1024 * 1024)
    return result.stdout


def safe_path(name):
    require(isinstance(name, str) and name and '\\' not in name)
    parts = name.split('/')
    require(all(part not in ('', '.', '..') for part in parts))
    current = ROOT
    for part in parts:
        current = current / part
        require(not current.is_symlink())
    require(current.resolve().is_relative_to(ROOT))
    return current


def baseline():
    proof = blob(PROOF)
    require(digest(proof) == PROOF_HASH)
    recorded = decode(proof)['source_sha256']
    require(isinstance(recorded, dict) and len(recorded) == 65)
    sources = {}
    for name, expected in recorded.items():
        path = name if name.startswith(('docs/', 'src/')) else 'qualification/rendezvous/' + name
        require(digest(blob(path)) == expected)
        sources[path] = expected
    return sources, {name: digest(blob(name)) for name in REFERENCES}


def validate(plan):
    expected = {'schema_version', 'kind', 'status', 'supplying_source_sha',
                'profile', 'wire', 'worker', 'service_origin', 'browser_origin',
                'compatibility_date', 'activation_allowed', 'public_entrypoint',
                'central_manifest_id', 'artifact_id', 'artifact_sha256', 'approval',
                'account_id', 'account_plan', 'bindings', 'migration', 'secret_names',
                'gates', 'source_hashes', 'reference_hashes'}
    require(isinstance(plan, dict) and set(plan) == expected)
    constants = {'schema_version': 1, 'kind': 'rendezvous_deployment_preparation',
                 'status': 'NOT_AUTHORIZED', 'supplying_source_sha': SUPPLYING_SHA,
                 'profile': '0.4.0-draft', 'wire': 'djc-rendezvous/1',
                 'worker': 'djconnect-api', 'service_origin': 'https://api.djconnect.dev',
                 'browser_origin': 'https://vibecast.tv', 'compatibility_date': '2026-06-20'}
    for key, value in constants.items():
        require(type(plan[key]) is type(value) and plan[key] == value)
    require(plan['activation_allowed'] is False)
    for key in ('public_entrypoint', 'central_manifest_id', 'artifact_id',
                'artifact_sha256', 'approval', 'account_id', 'account_plan'):
        require(plan[key] is None)
    require(plan['bindings'] == BINDINGS)
    require(plan['migration'] == {'proposed_tag': 'djc-rendezvous-sqlite-v1',
                                 'status': 'PROPOSED_COLLISION_UNVERIFIED',
                                 'new_sqlite_classes': sorted(BINDINGS.values())})
    require(plan['secret_names'] == ['RENDEZVOUS_IP_HASH_KEY', 'RECEIPT_ACTIVE_KEY',
                                     'RECEIPT_PREVIOUS_KEY'])
    require(plan['gates'] == {name: 'OPEN' for name in GATES})
    sources, references = baseline()
    require(plan['source_hashes'] == sources and plan['reference_hashes'] == references)
    for path, expected_hash in {**sources, **references}.items():
        require(digest(safe_path(path).read_bytes()) == expected_hash)
    return {'status': SUCCESS, 'activation_allowed': False,
            'supplying_source_sha': SUPPLYING_SHA, 'open_gate_count': len(GATES)}


def main():
    # No execute/deploy/approve mode. This output cannot be a dispatch receipt.
    try:
        require(len(sys.argv) == 1)
        raw = safe_path('docs/rendezvous/deployment-preparation-v1.json').read_bytes()
        result = validate(decode(raw))
    except Exception:
        print(json.dumps({'status': 'PREPARATION_INVALID_NOT_AUTHORIZED',
                          'activation_allowed': False}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
