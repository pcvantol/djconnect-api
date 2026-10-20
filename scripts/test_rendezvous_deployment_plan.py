"""Negative admission tests for offline preparation; no runtime/deployment proof."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('plan_validator', Path(__file__).with_name('validate_rendezvous_deployment_plan.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads((v.ROOT / 'docs/rendezvous/deployment-preparation-v1.json').read_text())

    def rejects(self, plan):
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            v.validate(plan)

    def test_valid_is_always_blocked_not_authorized(self):
        out = v.validate(self.plan)
        self.assertEqual(out['status'], v.SUCCESS)
        self.assertIs(out['activation_allowed'], False)
        self.assertEqual(out['open_gate_count'], 22)

    def test_protected_supplier_survives_squash_and_branch_cleanup(self):
        # Model main checkout with no PR/intermediate history or object fallback.
        with tempfile.TemporaryDirectory() as name:
            checkout = Path(name)
            subprocess.run(['git', 'init', '--quiet', str(checkout)], check=True)
            subprocess.run(['git', 'fetch', '--quiet', '--no-tags', '--depth=1',
                            str(v.ROOT), v.SUPPLYING_SHA], cwd=checkout, check=True)
            subprocess.run(['git', 'checkout', '--quiet', '--detach', 'FETCH_HEAD'],
                           cwd=checkout, check=True)
            commits = subprocess.check_output(['git', 'rev-list', 'HEAD'],
                                              cwd=checkout, text=True).splitlines()
            self.assertEqual(commits, [v.SUPPLYING_SHA])
            missing = subprocess.run(['git', 'cat-file', '-e',
                                      '81df44c6dbc00f58bb3ca5772cd6836fd9f41c10'],
                                     cwd=checkout, capture_output=True)
            self.assertNotEqual(missing.returncode, 0)
            with patch.object(v, 'ROOT', checkout):
                out = v.validate(self.plan)
            self.assertFalse(out['activation_allowed'])
            self.assertEqual(out['open_gate_count'], 22)

    def test_git_cannot_lazy_fetch_or_prompt(self):
        with patch.object(v.subprocess, 'run') as run:
            run.return_value.stdout = b'{}'
            self.assertEqual(v.blob('wrangler.jsonc'), b'{}')
            env = run.call_args.kwargs['env']
            self.assertEqual(env['GIT_NO_LAZY_FETCH'], '1')
            self.assertEqual(env['GIT_TERMINAL_PROMPT'], '0')
            self.assertEqual(env['GIT_OPTIONAL_LOCKS'], '0')
            self.assertEqual(env['GIT_NO_REPLACE_OBJECTS'], '1')
            self.assertNotIn('GIT_DIR', env)

    def test_missing_local_blob_fails_closed(self):
        with self.assertRaises(subprocess.CalledProcessError):
            v.blob('docs/rendezvous/definitely-missing-preparation-blob.json')

    def test_no_self_authorization(self):
        for key, value in [('activation_allowed', True), ('status', 'APPROVED'),
                           ('approval', {'state': 'APPROVED'}), ('central_manifest_id', 'release-example'),
                           ('artifact_id', 123), ('artifact_sha256', 'a' * 64),
                           ('public_entrypoint', 'src/index.ts')]:
            with self.subTest(key=key):
                p = copy.deepcopy(self.plan)
                p[key] = value
                self.rejects(p)

    def test_no_gate_promotion_or_omission(self):
        for state in ('PASS', 'QUALIFIED', None):
            p = copy.deepcopy(self.plan)
            p['gates']['trusted_cf_ip_provenance'] = state
            self.rejects(p)
        del self.plan['gates']['joint_contract_freeze']
        self.rejects(self.plan)

    def test_foreign_source_cannot_define_own_truth(self):
        self.plan['supplying_source_sha'] = 'f' * 40
        self.plan['source_hashes'] = {}
        self.rejects(self.plan)

    def test_own_baseline_pin_cannot_be_replaced(self):
        with patch.object(v, 'blob', return_value=b'{"source_sha256":{}}'):
            self.rejects(self.plan)

    def test_source_hash_forgery(self):
        name = next(iter(self.plan['source_hashes']))
        self.plan['source_hashes'][name] = 'a' * 64
        self.rejects(self.plan)

    def test_reference_drift(self):
        self.plan['reference_hashes']['wrangler.jsonc'] = 'b' * 64
        self.rejects(self.plan)

    def proof_maps(self):
        return [v.decode(v.blob(name))[field] for name, _pin, field, _count, _scope in v.PROOFS]

    def test_all_three_immutable_proof_pins_enforced(self):
        original = v.blob
        for name, _pin, _field, _count, _scope in v.PROOFS:
            with self.subTest(proof=name), patch.object(v, 'blob', side_effect=lambda path: b'{}' if path == name else original(path)):
                self.rejects(self.plan)

    def test_cross_proof_hash_collision_rejected(self):
        maps = self.proof_maps()
        maps[1]['src/index.ts'] = 'f' * 64
        with self.assertRaises(ValueError):
            v.merge_sources(*maps)

    def test_exact_106_tracked_sources_and_32_explicit_dependency_inputs(self):
        maps = self.proof_maps()
        self.assertEqual(len(v.merge_sources(*maps)), 106)
        excluded = [path for path in maps[2] if path.startswith('node_modules/')]
        self.assertEqual(len(excluded), 32)
        value = maps[2].pop(excluded[0])
        maps[2]['untracked/dependency.js'] = value
        with self.assertRaises(ValueError):
            v.merge_sources(*maps)

    def test_excluded_dependency_path_cannot_escape(self):
        maps = self.proof_maps()
        name = next(path for path in maps[2] if path.startswith('node_modules/'))
        maps[2]['node_modules/../outside.js'] = maps[2].pop(name)
        with self.assertRaises(ValueError):
            v.merge_sources(*maps)

    def test_new_product_module_current_bytes_checked(self):
        original = Path.read_bytes
        def changed(path):
            return b'module drift' if path == v.ROOT / 'src/rendezvous/composition.ts' else original(path)
        with patch.object(Path, 'read_bytes', changed):
            self.rejects(self.plan)

    def test_proposed_configuration_cannot_select_deadline_or_revision(self):
        for name, value in [('ASSERTION_POLICY_EXPIRES_AT', 9999999999999),
                            ('ENROLLMENT_POLICY_REVISION', 'self-approved'),
                            ('REQUEST_POLICY_ENABLED', 'caller-selected'),
                            ('RECEIPT_ACTIVE_KEY', 'synthetic-test-value')]:
            with self.subTest(field=name):
                plan = copy.deepcopy(self.plan)
                plan['proposed_configuration'][name] = value
                self.rejects(plan)

    def test_current_checkout_drift(self):
        with patch.object(Path, 'read_bytes', return_value=b'changed working bytes'):
            self.rejects(self.plan)

    def test_software_and_legacy_bindings_rejected(self):
        for name in ('SOFTWARE_ENROLLMENT', 'RECEIPT_KEY_STORE', 'TRANSACTION_STATE'):
            p = copy.deepcopy(self.plan)
            p['bindings'][name] = 'SoftwareEnrollmentCoordinator'
            self.rejects(p)

    def test_missing_binding_and_wrong_class(self):
        p = copy.deepcopy(self.plan)
        del p['bindings']['REQUEST_ADMISSION']
        self.rejects(p)
        self.plan['bindings']['ENROLLMENT_COORDINATOR'] = 'AssertionKeyState'
        self.rejects(self.plan)

    def test_migration_cannot_claim_collision_checked(self):
        self.plan['migration']['status'] = 'QUALIFIED'
        self.rejects(self.plan)

    def test_unknown_fields_and_secret_values_rejected(self):
        self.plan['RECEIPT_ACTIVE_KEY'] = 'synthetic-test-value'
        self.rejects(self.plan)

    def test_unknown_nested_migration_field_rejected(self):
        self.plan['migration']['execute'] = True
        self.rejects(self.plan)

    def test_json_duplicate_and_nonfinite_rejected(self):
        for raw in (b'{"status":"NOT_AUTHORIZED","status":"APPROVED"}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(ValueError):
                v.decode(raw)

    def test_size_limit_rejected(self):
        with self.assertRaises(ValueError):
            v.decode(b' ' * (1024 * 1024 + 1))

    def test_lexical_path_escape_rejected(self):
        for name in ('/etc/passwd', '../outside', 'scripts/../outside', 'scripts//x', 'scripts\\x'):
            with self.assertRaises(ValueError):
                v.safe_path(name)

    def test_real_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            (Path(root) / 'alias').symlink_to(outside, target_is_directory=True)
            with patch.object(v, 'ROOT', Path(root)):
                with self.assertRaises(ValueError):
                    v.safe_path('alias/payload')

    def test_cli_cannot_request_execute(self):
        result = subprocess.run(['python3', str(v.ROOT / 'scripts/validate_rendezvous_deployment_plan.py'), '--execute'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {'status': 'PREPARATION_INVALID_NOT_AUTHORIZED', 'activation_allowed': False})
        self.assertEqual(result.stderr, '')

    def test_wrong_schema_type_not_coerced(self):
        self.plan['schema_version'] = True
        self.rejects(self.plan)


if __name__ == '__main__':
    unittest.main()
