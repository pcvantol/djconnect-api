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
                         v.WORKFLOW_DELTA_SOURCE, v.WORKFLOW_DELTA_PATH,
                         *(record[0] for record in v.DELTA_PROOFS),
                         *v.CLOSED_RECEIVING_MAP_CHANGES, v.CLOSED_RECEIVING_DELTA_PATH,
                         v.CLOSED_RECEIVING_PRODUCT_PATH, *v.RETENTION_SOURCES,
                         v.RETENTION_DELTA_PATH, *v.CATEGORY_SOURCES, v.CATEGORY_DELTA_PATH, *v.MOUNT_SOURCES, v.MOUNT_DELTA_PATH,
                         *v.DEPENDENCY_SOURCES, *v.DEPENDENCY_ADDITIONS,
                         *v.DEPENDENCY_REFERENCE_CHANGES, *v.DEPENDENCY_REFERENCE_ADDITIONS,
                         v.DEPENDENCY_DELTA_PATH, *v.WATCH_SOURCES,
                         *v.WATCH_REFERENCES, v.WATCH_DELTA_PATH, *v.RECEIPT_SOURCES,
                         *v.RECEIPT_REFERENCES, v.RECEIPT_DELTA_PATH, v.RELEASE_RETENTION_DELTA_PATH,
                         v.CLOSED_PRODUCTION_BINDINGS_DELTA_PATH,
                         *v.TOOLCHAIN_REFRESH_SOURCES, *v.TOOLCHAIN_REFRESH_REFERENCES,
                         *v.TOOLCHAIN_REFRESH_ADDITIONS, v.TOOLCHAIN_REFRESH_DELTA_PATH,
                         *v.API_MAINTENANCE_SOURCES, v.API_MAINTENANCE_DELTA_PATH,
                         *v.STABLE_RELEASE_SOURCES, v.STABLE_RELEASE_DELTA_PATH,
                         *v.STABLE_RELEASE_REFERENCES, *v.PUSH_ERASURE_SOURCES,
                         *v.PUSH_ERASURE_REFERENCES, *v.PUSH_ERASURE_ADDITIONS,
                         v.PUSH_ERASURE_DELTA_PATH)
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

    def test_qualification_workflow_delta_cannot_expand_or_forge_history(self):
        original = v.pinned_working_proof(v.WORKFLOW_DELTA_PATH, v.WORKFLOW_DELTA_SHA256)
        for mutation in ('extra-source', 'wrong-original', 'no-change', 'wrong-new', 'wrong-scope', 'empty'):
            changed = copy.deepcopy(original)
            item = changed['changes'][v.WORKFLOW_DELTA_SOURCE]
            if mutation == 'extra-source':
                changed['changes']['src/index.ts'] = dict(item)
            elif mutation == 'wrong-original':
                item['before'] = 'f' * 64
            elif mutation == 'no-change':
                item['after'] = item['before']
            elif mutation == 'wrong-new':
                item['after'] = 'f' * 64
            elif mutation == 'wrong-scope':
                changed['scope'] = 'ACTIVATION'
            else:
                changed['changes'] = {}
            with self.subTest(mutation=mutation):
                self.rejects_changed_proof(v.WORKFLOW_DELTA_PATH, changed)

    def test_watch_topic_delta_preserves_history_and_closed_activation(self):
        before, _ = v.baseline_before_watch_topic()
        after, _ = v.baseline_before_watch_registration_receipt()
        self.assertEqual(len(before), len(after))
        self.assertEqual({k for k in before if before[k] != after[k]}, {'wrangler.jsonc', 'rendezvous-build-inputs.json'})
        proof = v.pinned_working_proof(v.WATCH_DELTA_PATH, v.WATCH_DELTA_SHA256)
        self.assertFalse(proof['public_activation_allowed'])
        self.assertFalse(proof['production_effect_authorized'])
        self.assertEqual(proof['reference_changes']['wrangler.jsonc'], proof['source_changes']['wrangler.jsonc'])

    def test_watch_topic_delta_rejects_forgery_and_scope_expansion(self):
        original = v.pinned_working_proof(v.WATCH_DELTA_PATH, v.WATCH_DELTA_SHA256)
        for mutation in ('scope', 'base_source', 'baseline_source_map_sha256',
                         'effective_source_map_sha256', 'public_activation_allowed',
                         'production_effect_authorized', 'extra-source', 'extra-reference',
                         'missing-source', 'before', 'after', 'reference-before', 'reference-after'):
            proof = copy.deepcopy(original)
            if mutation in ('public_activation_allowed', 'production_effect_authorized'):
                proof[mutation] = True
            elif mutation == 'scope': proof['scope'] = 'ACTIVATION'
            elif mutation == 'base_source': proof['base_source'] = 'f' * 40
            elif mutation.endswith('source_map_sha256'): proof[mutation] = 'f' * 64
            elif mutation == 'extra-source': proof['source_changes']['src/index.ts'] = {'before': 'a'*64, 'after': 'b'*64}
            elif mutation == 'extra-reference': proof['reference_changes']['unreviewed.json'] = {'before': 'a'*64, 'after': 'b'*64}
            elif mutation == 'missing-source': proof['source_changes'] = {}
            elif mutation in ('before', 'after'): proof['source_changes']['wrangler.jsonc'][mutation] = 'f'*64
            else: proof['reference_changes']['wrangler.jsonc'][mutation.split('-')[1]] = 'f'*64
            with self.subTest(mutation=mutation):
                self.rejects_changed_proof(v.WATCH_DELTA_PATH, proof)

    def test_dependency_refresh_is_closed_and_retains_installed_history(self):
        proof = v.pinned_working_proof(v.DEPENDENCY_DELTA_PATH, v.DEPENDENCY_DELTA_SHA256)
        self.assertEqual(len(proof['source_changes']), 6)
        self.assertEqual(len(proof['source_additions']), 1)
        self.assertEqual(len(proof['installed_changes']), 1)
        self.assertFalse(proof['public_activation_allowed'])
        self.assertFalse(proof['production_effect_authorized'])
        self.assertEqual(len(v.baseline_before_dependency_refresh()[0]), 144)
        self.assertEqual(len(v.baseline()[0]), 145)

    def test_dependency_refresh_rejects_scope_history_and_source_forgery(self):
        original = v.pinned_working_proof(v.DEPENDENCY_DELTA_PATH, v.DEPENDENCY_DELTA_SHA256)
        for mutation in ('base', 'baseline', 'effective', 'extra-source', 'before', 'after',
                         'installed-extra', 'installed-before', 'installed-after',
                         'reference-extra', 'reference-before', 'addition-extra',
                         'activation', 'effect', 'scope'):
            proof = copy.deepcopy(original)
            if mutation == 'base': proof['base_source'] = 'f' * 40
            elif mutation == 'baseline': proof['baseline_source_map_sha256'] = 'f' * 64
            elif mutation == 'effective': proof['effective_source_map_sha256'] = 'f' * 64
            elif mutation == 'extra-source': proof['source_changes']['src/index.ts'] = {'before': 'a'*64, 'after': 'b'*64}
            elif mutation in ('before', 'after'): proof['source_changes']['package-lock.json'][mutation] = 'f' * 64
            elif mutation == 'installed-extra': proof['installed_changes']['node_modules/asn1js/build/index.js'] = {'before': 'a'*64, 'after': 'b'*64}
            elif mutation.startswith('installed-'): proof['installed_changes']['node_modules/pkijs/build/index.js'][mutation.split('-')[1]] = 'f' * 64
            elif mutation == 'reference-extra': proof['reference_changes']['API_CONTRACT.md'] = {'before': 'a'*64, 'after': 'b'*64}
            elif mutation == 'reference-before': proof['reference_changes']['THIRD_PARTY_NOTICES.md']['before'] = 'f' * 64
            elif mutation == 'addition-extra': proof['reference_additions']['unreviewed.json'] = 'f' * 64
            elif mutation == 'activation': proof['public_activation_allowed'] = True
            elif mutation == 'effect': proof['production_effect_authorized'] = True
            else: proof['scope'] = 'ACTIVATION'
            with self.subTest(mutation=mutation):
                self.rejects_changed_proof(v.DEPENDENCY_DELTA_PATH, proof)

    def test_mount_delta_is_four_exact_paths_not_effect_authority(self):
        proof = v.pinned_working_proof(v.MOUNT_DELTA_PATH, v.MOUNT_DELTA_SHA256)
        self.assertEqual(len(proof['changes']), 4)
        self.assertTrue(proof['private_http_mount_selected'])
        self.assertFalse(proof['production_effect_authorized'])

    def test_mount_delta_cannot_grant_production_effect(self):
        proof = v.pinned_working_proof(v.MOUNT_DELTA_PATH, v.MOUNT_DELTA_SHA256)
        proof['production_effect_authorized'] = True
        self.rejects_changed_proof(v.MOUNT_DELTA_PATH, proof)

    def test_mount_delta_cannot_add_unreviewed_source(self):
        proof = v.pinned_working_proof(v.MOUNT_DELTA_PATH, v.MOUNT_DELTA_SHA256)
        proof['changes']['unreviewed.ts'] = {'before': None, 'after':'f'*64}
        self.rejects_changed_proof(v.MOUNT_DELTA_PATH, proof)

    def test_mount_delta_cannot_rewrite_prior_category_map(self):
        proof = v.pinned_working_proof(v.MOUNT_DELTA_PATH, v.MOUNT_DELTA_SHA256)
        proof['baseline_source_map_sha256'] = 'f'*64
        self.rejects_changed_proof(v.MOUNT_DELTA_PATH, proof)

    def test_category_delta_preserves_prior_ci_and_runtime_maps(self):
        self.assertEqual(len(v.baseline_before_native_category()[0]), 144)
        proof = v.pinned_working_proof(v.CATEGORY_DELTA_PATH, v.CATEGORY_DELTA_SHA256)
        self.assertEqual(len(proof['changes']), 5)
        self.assertFalse(proof['public_activation_allowed'])

    def test_category_delta_cannot_authorize_activation(self):
        proof = v.pinned_working_proof(v.CATEGORY_DELTA_PATH, v.CATEGORY_DELTA_SHA256)
        proof['public_activation_allowed'] = True
        self.rejects_changed_proof(v.CATEGORY_DELTA_PATH, proof)

    def test_category_delta_cannot_rewrite_the_prior_source(self):
        proof = v.pinned_working_proof(v.CATEGORY_DELTA_PATH, v.CATEGORY_DELTA_SHA256)
        proof['baseline_source_map_sha256'] = 'f' * 64
        self.rejects_changed_proof(v.CATEGORY_DELTA_PATH, proof)

    def test_category_delta_cannot_add_unlisted_runtime(self):
        proof = v.pinned_working_proof(v.CATEGORY_DELTA_PATH, v.CATEGORY_DELTA_SHA256)
        proof['changes']['unreviewed.ts'] = {'before': None, 'after': 'f' * 64}
        self.rejects_changed_proof(v.CATEGORY_DELTA_PATH, proof)

    def test_retention_delta_cannot_authorize_activation(self):
        value = v.pinned_working_proof(v.RETENTION_DELTA_PATH, v.RETENTION_DELTA_SHA256)
        value['public_activation_allowed'] = True
        self.rejects_changed_proof(v.RETENTION_DELTA_PATH, value)

    def test_retention_delta_cannot_replace_a_historical_source(self):
        value = v.pinned_working_proof(v.RETENTION_DELTA_PATH, v.RETENTION_DELTA_SHA256)
        value['changes']['.github/workflows/ci-cd.yml']['before'] = 'f' * 64
        self.rejects_changed_proof(v.RETENTION_DELTA_PATH, value)

    def test_retention_delta_is_exact_not_an_extra_source_allowlist(self):
        value = v.pinned_working_proof(v.RETENTION_DELTA_PATH, v.RETENTION_DELTA_SHA256)
        value['changes']['src/index.ts'] = {'before': 'a' * 64, 'after': 'b' * 64}
        self.rejects_changed_proof(v.RETENTION_DELTA_PATH, value)

    def test_retention_delta_cannot_omit_its_cleanup_implementation(self):
        value = v.pinned_working_proof(v.RETENTION_DELTA_PATH, v.RETENTION_DELTA_SHA256)
        del value['changes']['scripts/cleanup_workflow_runs.py']
        self.rejects_changed_proof(v.RETENTION_DELTA_PATH, value)

    def test_qualification_workflow_metadata_is_not_an_activation_or_runtime_override(self):
        sources, refs = v.baseline_before_receiving_root()
        maps = [v.decode((v.ROOT / name).read_bytes())[field]
                for name, _pin, field, _count, _scope in v.DELTA_PROOFS]
        historical = v.merge_sources(maps[0], maps[2], maps[1], with_closed_issuer=True)
        changed = {name for name, pin in historical.items()
                   if not name.startswith('node_modules/') and sources[name] != pin}
        self.assertEqual(changed, {v.WORKFLOW_DELTA_SOURCE})
        self.assertEqual(refs[v.WORKFLOW_DELTA_PATH], v.WORKFLOW_DELTA_SHA256)
        result = v.validate(self.plan)
        self.assertEqual(set(result['qualification_workflow_delta']), {v.WORKFLOW_DELTA_SOURCE})
        self.assertEqual(result['open_gate_count'], 22)
        self.assertFalse(result['activation_allowed'])

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
        for name in (v.DELTA_PATH, *(record[0] for record in v.DELTA_PROOFS),
                         *v.CLOSED_RECEIVING_MAP_CHANGES, v.CLOSED_RECEIVING_DELTA_PATH,
                         v.CLOSED_RECEIVING_PRODUCT_PATH, v.CLOSED_PRODUCTION_BINDINGS_DELTA_PATH):
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
        for name in v.DELTA_SOURCES | v.DELTA_ADDITIONS | v.CLOSED_PRODUCTION_BINDINGS_SOURCES:
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
        self.assertEqual(len(v.baseline_before_receiving_root()[0]), 119)
        self.assertEqual(len(v.baseline_before_ci_retention()[0]), 142)
        self.assertEqual(len(v.baseline_before_dependency_refresh()[0]), 144)
        self.assertEqual(len(self.plan['source_hashes']), 145)
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

    def test_prior_qualified_plan_does_not_cover_the_new_root(self):
        previous = copy.deepcopy(self.plan)
        previous['source_hashes'], previous['reference_hashes'] = v.baseline_before_receiving_root()
        for key in list(previous['source_provenance']):
            if key.startswith('closed_receiving_root_'):
                del previous['source_provenance'][key]
        self.rejects(previous)

    def test_closed_root_proof_cannot_grant_activation(self):
        proof = v.pinned_working_proof(v.CLOSED_RECEIVING_DELTA_PATH, v.CLOSED_RECEIVING_DELTA_SHA256)
        proof['public_activation_allowed'] = True
        self.rejects_changed_proof(v.CLOSED_RECEIVING_DELTA_PATH, proof)

    def test_closed_root_delta_cannot_expand_the_source_map(self):
        proof = v.pinned_working_proof(v.CLOSED_RECEIVING_DELTA_PATH, v.CLOSED_RECEIVING_DELTA_SHA256)
        proof['changes']['src/unreviewed.ts'] = {'before': None, 'after': 'f' * 64}
        self.rejects_changed_proof(v.CLOSED_RECEIVING_DELTA_PATH, proof)

    def test_closed_root_requires_all_observed_public_denials(self):
        proof = v.pinned_working_proof(v.CLOSED_RECEIVING_PRODUCT_PATH, v.CLOSED_RECEIVING_PRODUCT_SHA256)
        proof['closed_receiving_prefix_checks'] = 63
        self.rejects_changed_proof(v.CLOSED_RECEIVING_PRODUCT_PATH, proof)

    def test_closed_root_cannot_change_an_installed_dependency(self):
        proof = v.pinned_working_proof(v.CLOSED_RECEIVING_PRODUCT_PATH, v.CLOSED_RECEIVING_PRODUCT_SHA256)
        name = next(k for k in proof['source_hashes'] if k.startswith('node_modules/'))
        proof['source_hashes'][name] = 'f' * 64
        self.rejects_changed_proof(v.CLOSED_RECEIVING_PRODUCT_PATH, proof)


if __name__ == '__main__':
    unittest.main()
