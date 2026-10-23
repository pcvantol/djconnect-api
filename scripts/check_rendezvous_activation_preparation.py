#!/usr/bin/env python3
"""Check the immutable, closed readiness package. Never authorizes an effect.

No network, credential discovery, deployment, key generation or approval mode.
Exit 0 means internally consistent preparation, including its explicit blockers.
"""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
RECORD = 'docs/rendezvous/controlled-activation-preparation-v1.json'
RECORD_SHA256 = '822d01e72a429697551084ef0d8b02a3b7e9c9f6eca2be1b698252e2adf0d3f0'
EXPECTED_VERSION = '6d6531ba-ea62-48c2-b132-8649cdcee627'
EXPECTED_SOURCE = 'c04864ce7c885e0de5fb365aa0139a64c7921b22'


def require(value):
    if not value:
        raise ValueError('invalid_closed_preparation')


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value)
        value[key] = item
    return value


def load(raw):
    require(len(raw) <= 128 * 1024)
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False))


def read(root, name):
    require(isinstance(name, str) and name and '\\' not in name)
    parts = name.split('/')
    require(all(p not in ('', '.', '..') for p in parts))
    path = root
    for part in parts:
        path = path / part
        require(not path.is_symlink())
    require(path.resolve().is_relative_to(root.resolve()) and path.is_file())
    require(path.stat().st_size <= 2 * 1024 * 1024)
    return path.read_bytes()


def assess(root=ROOT):
    root = Path(root)
    raw = read(root, RECORD)
    require(hashlib.sha256(raw).hexdigest() == RECORD_SHA256)
    record = load(raw)
    require(record['schema_version'] == 1 and record['activation_allowed'] is False
            and record['status'] == 'BLOCKED_NOT_AUTHORIZED'
            and record['deployed_api_source'] == EXPECTED_SOURCE
            and record['provider_version'] == EXPECTED_VERSION)
    for name, pin in record['source_hashes'].items():
        require(hashlib.sha256(read(root, name)).hexdigest() == pin)
    previous = load(read(root, 'docs/rendezvous/deployment-preparation-v1.json'))
    require(previous['activation_allowed'] is False
            and len(previous['gates']) == 22
            and set(previous['gates'].values()) == {'OPEN'})
    overlay = record['configuration_overlay']
    require(overlay['preserve_all_existing_bindings_and_routes'] is True)
    require(overlay['observability'] == {
        'redact_query_string': True, 'logs': {'invocation_logs': False}})
    expected_bindings = previous['bindings']
    proposed = overlay['durable_objects']['bindings']
    require(len(proposed) == 5 and {x['name']:x['class_name'] for x in proposed} == expected_bindings)
    require(overlay['migrations'] == [{'tag':'djc-rendezvous-sqlite-v1',
                                     'new_sqlite_classes':sorted(expected_bindings.values())}])
    require(set(overlay['required_secret_names']) == {'RENDEZVOUS_IP_HASH_KEY','RECEIPT_ACTIVE_KEY'}
            and overlay['optional_rotation_secret_names'] == ['RECEIPT_PREVIOUS_KEY'])
    require(set(overlay['native_policy'].values()) == {None})
    require(set(record['external_decisions'].values()) == {None})
    provider = record['provider_readback']
    live = provider['binding_names_and_types']
    require(len({x['name'] for x in live}) == len(live))
    require(not any(x['type'] == 'durable_object_namespace' for x in live))
    require(provider['namespaces']['complete'] is True
            and provider['namespaces']['namespaces'] == [])
    require(provider['subscriptions']['http'] == 403
            and provider['subscriptions']['success'] is False)
    require(all(x['http'] == 403 and x['success'] is False
                for x in provider['edge_rule_readback'].values()))
    require(provider['zone_plan_is_not_workers_plan'] is True)
    missing_bindings = sorted(set(expected_bindings) - {x['name'] for x in live})
    missing_secrets = sorted(set(overlay['required_secret_names']) - set(provider['secret_names']))
    settings = provider['worker_settings']
    require(settings['success'] is True and settings['http'] == 200)
    logs = settings['configuration']['observability']
    require(logs['redact_query_string'] is False and logs['logs']['invocation_logs'] is True)
    return {
        'status':'PREPARATION_CONSISTENT_BLOCKED_NOT_AUTHORIZED',
        'activation_allowed':False,
        'provider_observed_at':record['observed_at'],
        'deployed_api_source':EXPECTED_SOURCE,
        'existing_api_health':'PASS_CLOSED_WORKER_ONLY',
        'missing_durable_bindings':missing_bindings,
        'missing_required_secret_names':missing_secrets,
        'optional_previous_key':'NOT_REQUIRED_FOR_INITIAL_CONFIGURATION',
        'namespace_inventory':'ZERO_CURRENT_NAMESPACES_AT_OBSERVATION_NOT_MIGRATION_APPROVAL',
        'logging_changes_prepared_not_applied':overlay['observability'],
        'blockers':[
            'exact_signed_iOS_profile_and_original_positive_admission_unavailable',
            'five_private_bindings_and_reviewed_migration_not_provisioned',
            'two_required_operator_secrets_and_custody_rotation_not_provisioned',
            'query_redaction_invocation_log_retention_and_backup_policy_not_admitted',
            'Free_shared_quota_headroom_and_edge_controls_not_verified',
            'bounded_private_CPU_SQL_alarm_cleanup_and_provider_checks_not_yet_performed',
            'exact_activation_source_artifact_central_manifest_and_effect_approval_absent'],
        'unchanged_service_gates_open':22,
        'note':'Recorded metadata is dated evidence, not a live monitor or activation receipt.'}


def main():
    try:
        require(len(sys.argv) == 1)
        result = assess()
    except Exception:
        print(json.dumps({'status':'PREPARATION_INVALID_NOT_AUTHORIZED','activation_allowed':False}))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
