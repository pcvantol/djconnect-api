"""Read-only negative controls for the closed operational preparation package."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('preparation', HERE/'check_rendezvous_activation_preparation.py')
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class ClosedPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        record = check.load(check.read(check.ROOT, check.RECORD))
        for name in (check.RECORD, *record['source_hashes']):
            dest = self.root/name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(check.ROOT/name, dest)

    def test_actual_closed_record_never_grants_activation(self):
        result = check.assess(self.root)
        self.assertFalse(result['activation_allowed'])
        self.assertEqual(result['missing_required_secret_names'], ['RECEIPT_ACTIVE_KEY','RENDEZVOUS_IP_HASH_KEY'])
        self.assertEqual(len(result['missing_durable_bindings']), 5)
        self.assertEqual(result['unchanged_service_gates_open'], 22)
        self.assertTrue(result['blockers'])

    def test_forged_activation_metadata_is_rejected(self):
        path = self.root/check.RECORD
        value = check.load(path.read_bytes())
        value['activation_allowed'] = True
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            check.assess(self.root)

    def test_forged_successful_billing_or_edge_readback_is_rejected(self):
        path = self.root/check.RECORD
        value = check.load(path.read_bytes())
        value['provider_readback']['subscriptions']['http'] = 200
        value['provider_readback']['subscriptions']['success'] = True
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            check.assess(self.root)

    def test_changed_compiled_public_guard_is_rejected(self):
        path = self.root/'src/rendezvous/dispatch.ts'
        raw = path.read_text()
        self.assertIn('PRODUCT_RENDEZVOUS_ENABLED = false', raw)
        path.write_text(raw.replace('PRODUCT_RENDEZVOUS_ENABLED = false', 'PRODUCT_RENDEZVOUS_ENABLED = true'))
        with self.assertRaises(ValueError):
            check.assess(self.root)

    def test_changed_quota_or_native_profile_source_is_rejected(self):
        for name in ('qualification/rendezvous/request-admission.ts',
                     'qualification/rendezvous/app-attest-core-candidate.mjs'):
            with self.subTest(name=name):
                path = self.root/name
                original = path.read_bytes()
                path.write_bytes(original+b'\n//changed')
                with self.assertRaises(ValueError):
                    check.assess(self.root)
                path.write_bytes(original)

    def test_secret_reference_cannot_follow_a_source_symlink(self):
        path = self.root/'wrangler.jsonc'
        path.unlink()
        path.symlink_to(check.ROOT/'wrangler.jsonc')
        with self.assertRaises(ValueError):
            check.assess(self.root)

    def test_closed_json_rejects_duplicate_keys_and_nonfinite_values(self):
        for raw in (b'{"activation_allowed":false,"activation_allowed":true}', b'{"cpu":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                check.load(raw)

    def test_input_bounds_and_path_escape_are_rejected(self):
        with self.assertRaises(ValueError):
            check.load(b' '*(128*1024+1))
        for name in ('/etc/passwd','../outside','src/../wrangler.jsonc','src\\outside'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check.read(self.root, name)


if __name__ == '__main__':
    unittest.main()
