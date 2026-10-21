#!/usr/bin/env python3
"""Offline preparation consistency only. Never grants or performs deployment."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SUPPLYING_SHA = '896ccdc69447c231d04da3a6af4f27ea1f763697'

DELTA_PATH = 'docs/rendezvous/enrollment-point-digest-source-delta-v1.json'
DELTA_SHA256 = 'fd97e9a23a8da29cf2c915d233b23eb03897d2ada3b881e72464805a9277ebf2'
DELTA_PROOFS = (('docs/rendezvous/enrollment-point-digest-shared-observations-v1.json',
  '2bfee77c019a3a70f66de10887ccccc3f00e97e75d42e357bb30660059be8dac',
  'source_sha256',
  66,
  'LOCAL_SHARED_APP_KEY_API_NOT_NATIVE_EDGE_OR_RELEASE_GO'),
 ('docs/rendezvous/enrollment-point-digest-build-observations-v1.json',
  '2725d99610f66d9724038eeb772ffa24e94d5b1b94443da0eb6bbd4b914062cc',
  'source_hashes',
  85,
  'ACTUAL_PRODUCT_BUILD_PRIVATE_RPC_ONLY'),
 ('docs/rendezvous/enrollment-point-digest-composition-observations-v1.json',
  '0e2bc1a993bc7593203fc4be09c34a063524082cbac7631193717b16907d3d46',
  'source_sha256',
  19,
  'INTERNAL_PRODUCT_MODULE_WITH_REAL_PRIVATE_DO_NOT_ROOT_HTTP_OR_EDGE_PROVENANCE'))
DELTA_SOURCES = frozenset(('qualification/rendezvous/enrollment-key-state.check.mjs',
 'qualification/rendezvous/enrollment-evidence-candidate.mjs',
 'qualification/rendezvous/enrollment-evidence.check.mjs',
 'qualification/rendezvous/provider-unavailable.check.mjs'))
SOURCE_PROVENANCE = {'baseline_sha': '896ccdc69447c231d04da3a6af4f27ea1f763697',
 'delta_sha256': 'fd97e9a23a8da29cf2c915d233b23eb03897d2ada3b881e72464805a9277ebf2',
 'effective_source_map_sha256': '1f35b6e34d31e8a86c8306b1bcfa8983c45ba525e72b02e5d5a9682ed48898a9',
 'kind': 'BASELINE_PLUS_PINNED_DELTA'}

PROOFS = (('docs/rendezvous/assertion-crypto-shared-observations-v1.json',
  'd1b5d6bdc6a2009c31ba96ce2af1833c69b3794420fa6d0096103f2911701a4b',
  'source_sha256',
  66,
  'LOCAL_SHARED_APP_KEY_API_NOT_NATIVE_EDGE_OR_RELEASE_GO'),
 ('docs/rendezvous/sharp-0355-composition-observations-v1.json',
  'd0ef8018d7b494e27667ef9915c68a9849754b36d944f2cddf3ae910092ed531',
  'source_sha256',
  19,
  'INTERNAL_PRODUCT_MODULE_WITH_REAL_PRIVATE_DO_NOT_ROOT_HTTP_OR_EDGE_PROVENANCE'),
 ('docs/rendezvous/sharp-0355-build-observations-v1.json',
  'cd0c1df612e1218edc1483c9f04d6166d40680652ff463105f84446de99a5089',
  'source_hashes',
  85,
  'ACTUAL_PRODUCT_BUILD_PRIVATE_RPC_ONLY'))

REFERENCES = ('wrangler.jsonc', '.github/workflows/deploy-api-worker.yml',
              '.github/workflows/api-release-artifact.yml',
              'docs/rendezvous/implementation-contract-release-v1.json',
              'LICENSE', 'THIRD_PARTY_NOTICES.md',
              'docs/rendezvous/THIRD_PARTY_LICENSES_V1.md',
              *(proof[0] for proof in PROOFS))
PROPOSED_CONFIGURATION = {
    'COMPOSED_POLICY_ENABLED': 'djc-http-composition-qualification/1',
    'REQUEST_POLICY_ENABLED': 'djc-request-admission-qualification/2',
    'ALLOCATION_POLICY_ENABLED': 'djc-allocation-qualification/1',
    'INDEX_POLICY_ENABLED': 'djc-index-qualification/1',
    'ASSERTION_POLICY_ENABLED': 'ios-dev-qualification/1',
    'ASSERTION_POLICY_EXPIRES_AT': None,
    'ENROLLMENT_POLICY_REVISION': None,
    'RENDEZVOUS_EDGE_POLICY': 'djc-direct-edge-identity/1-candidate',
}
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


def merge_sources(shared, module, root):
    """Only immutable proof maps define inputs; never discover mutable Git state."""
    sources = {}
    excluded = set()
    for index, recorded in enumerate((shared, module, root)):
        require(isinstance(recorded, dict) and len(recorded) == (66, 19, 85)[index])
        for name, expected in recorded.items():
            require(isinstance(name, str) and isinstance(expected, str)
                    and len(expected) == 64 and all(c in '0123456789abcdef' for c in expected))
            path = (name if name.startswith(('docs/', 'src/'))
                    else 'qualification/rendezvous/' + name) if index == 0 else name
            if index == 2 and path.startswith('node_modules/'):
                require('\\' not in path and all(p not in ('', '.', '..') for p in path.split('/')))
                excluded.add(path)
                continue  # Installed package bytes are not immutable Git blobs.
            safe_path(path)
            require(path not in sources or sources[path] == expected)
            sources[path] = expected
    require(len(excluded) == 32 and len(sources) == 106)
    return sources


def immutable_baseline():
    maps = []
    for name, pin, field, count, scope in PROOFS:
        raw = blob(name)
        require(digest(raw) == pin)
        proof = decode(raw)
        require(proof['scope'] == scope and isinstance(proof[field], dict) and len(proof[field]) == count)
        maps.append(proof[field])
    sources = merge_sources(*maps)
    for path, expected in sources.items():
        require(digest(blob(path)) == expected)
    return sources, {name: digest(blob(name)) for name in REFERENCES}


def source_map_digest(sources):
    return digest(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode('utf-8'))


def pinned_working_proof(name, pin):
    path = safe_path(name)
    require(path.is_file())
    raw = path.read_bytes()
    require(digest(raw) == pin)
    return decode(raw)


def baseline():
    # Original protected history remains authoritative, even after squash deletes PR refs.
    original, references = immutable_baseline()
    delta = pinned_working_proof(DELTA_PATH, DELTA_SHA256)
    require(isinstance(delta, dict) and set(delta) == {'schema_version', 'scope',
        'baseline_source_sha', 'baseline_source_map_sha256',
        'effective_source_map_sha256', 'changes', 'proofs'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1
        and delta['scope'] == 'EXACT_SOURCE_DELTA_NOT_DEPLOYMENT_AUTHORIZATION'
        and delta['baseline_source_sha'] == SUPPLYING_SHA
        and delta['baseline_source_map_sha256'] == source_map_digest(original))
    changes = delta['changes']
    require(isinstance(changes, dict) and set(changes) == DELTA_SOURCES)
    effective = dict(original)
    for name, change in changes.items():
        safe_path(name)
        require(isinstance(change, dict) and set(change) == {'before', 'after'}
            and change['before'] == original[name] and change['after'] != change['before']
            and isinstance(change['after'], str) and len(change['after']) == 64
            and all(c in '0123456789abcdef' for c in change['after']))
        effective[name] = change['after']
    require(delta['effective_source_map_sha256'] == source_map_digest(effective)
        == SOURCE_PROVENANCE['effective_source_map_sha256'])
    require(delta['proofs'] == {key: {'path': record[0], 'sha256': record[1]}
        for key, record in zip(('shared', 'root', 'module'), DELTA_PROOFS)})
    fresh = []
    for name, pin, field, count, scope in DELTA_PROOFS:
        proof = pinned_working_proof(name, pin)
        require(proof['scope'] == scope and isinstance(proof[field], dict)
            and len(proof[field]) == count)
        fresh.append(proof[field])
        references[name] = pin
    old_root = decode(blob(PROOFS[2][0]))[PROOFS[2][2]]
    installed = lambda values: {key: value for key, value in values.items()
                              if key.startswith('node_modules/')}
    require(installed(fresh[1]) == installed(old_root))
    require(merge_sources(fresh[0], fresh[2], fresh[1]) == effective)
    references[DELTA_PATH] = DELTA_SHA256
    return effective, references


def validate(plan):
    expected = {'schema_version', 'kind', 'status', 'supplying_source_sha', 'source_provenance',
                'profile', 'wire', 'worker', 'service_origin', 'browser_origin',
                'compatibility_date', 'activation_allowed', 'public_entrypoint',
                'central_manifest_id', 'artifact_id', 'artifact_sha256', 'approval',
                'account_id', 'account_plan', 'bindings', 'migration', 'secret_names',
                'gates', 'source_hashes', 'reference_hashes', 'proposed_configuration'}
    require(isinstance(plan, dict) and set(plan) == expected)
    constants = {'schema_version': 1, 'kind': 'rendezvous_deployment_preparation',
                 'status': 'NOT_AUTHORIZED', 'supplying_source_sha': SUPPLYING_SHA,
                 'profile': '0.4.0-draft', 'wire': 'djc-rendezvous/1',
                 'worker': 'djconnect-api', 'service_origin': 'https://api.djconnect.dev',
                 'browser_origin': 'https://vibecast.tv', 'compatibility_date': '2026-06-20'}
    for key, value in constants.items():
        require(type(plan[key]) is type(value) and plan[key] == value)
    require(plan['source_provenance'] == SOURCE_PROVENANCE)
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
    require(plan['proposed_configuration'] == PROPOSED_CONFIGURATION)
    require(plan['gates'] == {name: 'OPEN' for name in GATES})
    sources, references = baseline()
    require(plan['source_hashes'] == sources and plan['reference_hashes'] == references)
    for path, expected_hash in {**sources, **references}.items():
        require(digest(safe_path(path).read_bytes()) == expected_hash)
    return {'status': SUCCESS, 'activation_allowed': False,
            'supplying_source_sha': SUPPLYING_SHA, 'source_provenance': SOURCE_PROVENANCE,
            'open_gate_count': len(GATES)}


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
