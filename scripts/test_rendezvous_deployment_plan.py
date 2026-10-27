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
            canonical = v.ROOT
            # An old protected checkout alone must NOT validate the new source.
            with patch.object(v, 'ROOT', checkout):
                self.rejects(self.plan)
            # Install only fixed, verified delta inputs; no fetching PR objects.
            additions = (*v.DELTA_SOURCES, *v.DELTA_ADDITIONS, *v.REFERENCE_DELTA, v.DELTA_PATH,
                         *(record[0] for record in v.DELTA_PROOFS))
            for path in additions:
                raw = (canonical / path).read_bytes()
                expected = {**self.plan['source_hashes'],
                            **self.plan['reference_hashes']}[path]
                self.assertEqual(v.digest(raw), expected)
                destination = checkout / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
            with patch.object(v, 'ROOT', checkout):
                out = v.validate(self.plan)
            self.assertFalse(out['activation_allowed'])
            self.assertEqual(out['open_gate_count'], 22)

    def test_baseline_source_is_machine_distinguished_from_effective_source(self):
        self.assertEqual(self.plan['source_provenance'], v.SOURCE_PROVENANCE)
        self.assertEqual(v.validate(self.plan)['source_provenance'], v.SOURCE_PROVENANCE)
        for field, value in [('kind', 'CURRENT_MAIN'), ('baseline_sha', 'f' * 40),
                             ('delta_sha256', 'f' * 64),
                             ('effective_source_map_sha256', 'f' * 64)]:
            plan = copy.deepcopy(self.plan)
            plan['source_provenance'][field] = value
            self.rejects(plan)
        del self.plan['source_provenance']
        self.rejects(self.plan)

    def delta(self):
        return v.decode((v.ROOT / v.DELTA_PATH).read_bytes())

    def rejects_changed_proof(self, path, changed):
        original = v.pinned_working_proof
        with patch.object(v, 'pinned_working_proof', side_effect=lambda name, pin:
                          changed if name == path else original(name, pin)):
            self.rejects(self.plan)

    def test_delta_missing_extra_noop_and_foreign_source_rejected(self):
        for mutation in ('missing', 'extra', 'noop', 'before', 'after', 'map',
                         'baseline-map', 'baseline-sha', 'unknown-field', 'proof-path'):
            with self.subTest(mutation=mutation):
                delta = self.delta()
                name = next(iter(delta['changes']))
                if mutation == 'missing':
                    del delta['changes'][name]
                elif mutation == 'extra':
                    delta['changes']['src/foreign-source.ts'] = delta['changes'][name]
                elif mutation == 'noop':
                    delta['changes'][name]['after'] = delta['changes'][name]['before']
                elif mutation == 'before':
                    delta['changes'][name]['before'] = 'f' * 64
                elif mutation == 'after':
                    delta['changes'][name]['after'] = 'f' * 64
                elif mutation == 'map':
                    delta['effective_source_map_sha256'] = 'f' * 64
                elif mutation == 'baseline-map':
                    delta['baseline_source_map_sha256'] = 'f' * 64
                elif mutation == 'baseline-sha':
                    delta['baseline_source_sha'] = 'f' * 40
                elif mutation == 'unknown-field':
                    delta['changes'][name]['grant'] = True
                else:
                    delta['proofs']['shared']['path'] = 'src/index.ts'
                self.rejects_changed_proof(v.DELTA_PATH, delta)

    def test_each_new_proof_and_delta_raw_hash_is_mandatory(self):
        original = Path.read_bytes
        for name in (v.DELTA_PATH, *(record[0] for record in v.DELTA_PROOFS)):
            with self.subTest(name=name):
                def changed(path):
                    return b'{}' if path == v.ROOT / name else original(path)
                with patch.object(Path, 'read_bytes', changed):
                    self.rejects(self.plan)

    def test_new_complete_proofs_cannot_conflict_with_exact_effective_map(self):
        for name, _pin, field, _count, _scope in v.DELTA_PROOFS:
            proof = v.decode((v.ROOT / name).read_bytes())
            path = next(iter(proof[field]))
            proof[field][path] = 'f' * 64
            self.rejects_changed_proof(name, proof)

    def test_new_root_installed_dependency_set_and_hashes_stay_exact(self):
        name, _pin, field, _count, _scope = v.DELTA_PROOFS[1]
        for mutation in ('hash', 'path', 'escape'):
            with self.subTest(mutation=mutation):
                proof = v.decode((v.ROOT / name).read_bytes())
                key = next(key for key in proof[field] if key.startswith('node_modules/'))
                if mutation == 'hash':
                    proof[field][key] = 'f' * 64
                else:
                    new = 'node_modules/other.js' if mutation == 'path' else 'node_modules/../escape'
                    proof[field][new] = proof[field].pop(key)
                self.rejects_changed_proof(name, proof)

    def test_each_current_delta_source_byte_is_verified(self):
        original = Path.read_bytes
        for name in v.DELTA_SOURCES | v.DELTA_ADDITIONS:
            with self.subTest(name=name):
                def changed(path):
                    return b'changed source' if path == v.ROOT / name else original(path)
                with patch.object(Path, 'read_bytes', changed):
                    self.rejects(self.plan)

    def test_closed_issuer_additions_are_exact_and_cannot_overwrite_baseline(self):
        delta = self.delta()
        for name in v.DELTA_ADDITIONS:
            self.assertNotIn(name, v.immutable_baseline()[0])
            self.assertIsNone(delta['changes'][name]['before'])
            for mutation in ('before', 'missing', 'unknown'):
                changed = copy.deepcopy(delta)
                if mutation == 'before':
                    changed['changes'][name]['before'] = 'f' * 64
                elif mutation == 'missing':
                    del changed['changes'][name]
                else:
                    changed['changes'][name]['grant'] = True
                self.rejects_changed_proof(v.DELTA_PATH, changed)
        self.assertEqual(len(self.plan['source_hashes']), 119)
        for name in v.DELTA_SOURCES:
            changed = copy.deepcopy(delta)
            changed['changes'][name]['before'] = None
            self.rejects_changed_proof(v.DELTA_PATH, changed)

    def test_new_graph_cannot_be_used_as_historical_baseline(self):
        maps = [v.decode((v.ROOT / name).read_bytes())[field]
                for name, _pin, field, _count, _scope in v.DELTA_PROOFS]
        with self.assertRaises(ValueError):
            v.merge_sources(maps[0], maps[2], maps[1])
        self.assertEqual(len(v.merge_sources(maps[0], maps[2], maps[1],
                                       with_closed_issuer=True)), 119)

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

    def test_runtime_patch_cannot_change_an_unlisted_installed_input(self):
        path, pin, field, _, _ = v.DELTA_PROOFS[1]
        proof = v.pinned_working_proof(path, pin)
        name = next(name for name in proof[field]
                    if name.startswith('node_modules/')
                    and name not in v.INSTALLED_DEPENDENCY_DELTA)
        proof[field][name] = 'f' * 64
        self.rejects_changed_proof(path, proof)

    def test_runtime_patch_cannot_forge_the_original_installed_hash(self):
        changed = copy.deepcopy(v.INSTALLED_DEPENDENCY_DELTA)
        name = next(iter(changed))
        changed[name]['before'] = 'f' * 64
        with patch.object(v, 'INSTALLED_DEPENDENCY_DELTA', changed):
            self.rejects(self.plan)

    def test_major_graph_cannot_add_a_dependency_outside_reviewed_paths(self):
        changed = copy.deepcopy(v.INSTALLED_DEPENDENCY_DELTA)
        changed['node_modules/unreviewed/index.js'] = {'before': None, 'after': 'f' * 64}
        with patch.object(v, 'INSTALLED_DEPENDENCY_DELTA', changed):
            self.rejects(self.plan)

    def test_removed_major_graph_input_cannot_reappear_in_current_proof(self):
        path, pin, field, _, _ = v.DELTA_PROOFS[1]
        proof = v.pinned_working_proof(path, pin)
        name, change = next((name, change) for name, change in v.INSTALLED_DEPENDENCY_DELTA.items()
                            if change['after'] is None)
        proof[field][name] = change['before']
        self.rejects_changed_proof(path, proof)

    def test_added_major_graph_input_cannot_claim_an_original_hash(self):
        changed = copy.deepcopy(v.INSTALLED_DEPENDENCY_DELTA)
        name = next(name for name, change in changed.items() if change['before'] is None)
        changed[name]['before'] = 'f' * 64
        with patch.object(v, 'INSTALLED_DEPENDENCY_DELTA', changed):
            self.rejects(self.plan)

    def test_major_graph_input_cannot_be_removed_without_original_match(self):
        changed = copy.deepcopy(v.INSTALLED_DEPENDENCY_DELTA)
        name = next(name for name, change in changed.items() if change['after'] is None)
        changed[name]['before'] = 'f' * 64
        with patch.object(v, 'INSTALLED_DEPENDENCY_DELTA', changed):
            self.rejects(self.plan)

    def test_version_label_delta_cannot_replace_an_authority_reference(self):
        for mutation in ('unlisted', 'forged-original'):
            changed = copy.deepcopy(v.REFERENCE_DELTA)
            if mutation == 'unlisted':
                changed['wrangler.jsonc'] = {'before': self.plan['reference_hashes']['wrangler.jsonc'], 'after': 'f' * 64}
            else:
                changed['THIRD_PARTY_NOTICES.md']['before'] = 'f' * 64
            with patch.object(v, 'REFERENCE_DELTA', changed):
                self.rejects(self.plan)


if __name__ == '__main__':
    unittest.main()
