import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.check_production_d1_migrations import verify


class ProductionD1MigrationTests(unittest.TestCase):
    first = "0001_initial.sql"
    second = "0002_erasure.sql"

    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.directory = Path(scratch.name)
        (self.directory / self.first).write_text("CREATE TABLE example (id INTEGER);")
        sql = b"DELETE FROM example;"
        (self.directory / self.second).write_bytes(sql)
        self.boundary = {
            "preflight_pending": [self.second],
            "pending_sha256": {self.second: hashlib.sha256(sql).hexdigest()},
        }

    def verify(self, *applied, boundary=None, after_apply=False):
        return verify(
            self.boundary if boundary is None else boundary,
            self.directory,
            [{"success": True, "results": [{"name": name} for name in applied]}],
            after_apply=after_apply,
        )

    def test_exact_migration_and_post_apply(self):
        self.assertEqual(self.verify(self.first), [self.second])
        self.assertEqual(self.verify(self.first, self.second, after_apply=True), [])

    def test_no_pending_with_existing_manifest(self):
        self.assertEqual(
            self.verify(self.first, self.second, boundary={"preflight_pending": []}), []
        )

    def test_unapproved_pending_migration(self):
        with self.assertRaisesRegex(ValueError, "release state"):
            self.verify(self.first, boundary={"preflight_pending": []})
        (self.directory / "0003_unreviewed.sql").touch()
        with self.assertRaisesRegex(ValueError, "release suffix"):
            self.verify(self.first)

    def test_missing_or_altered_migration_hash(self):
        with self.assertRaisesRegex(ValueError, "allowlist"):
            self.verify(self.first, boundary={"preflight_pending": [self.second]})
        (self.directory / self.second).write_bytes(b"DELETE FROM another_table;")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.verify(self.first)

    def test_partial_unexpected_or_unverified_ledger(self):
        for applied, after_apply in [
            ([], False),
            ([self.first, self.second], False),
            ([self.first, "0002_unknown.sql"], False),
            ([self.first], True),
            ([self.second, self.first], True),
        ]:
            with self.subTest(applied=applied, after_apply=after_apply):
                with self.assertRaisesRegex(ValueError, "release state"):
                    self.verify(*applied, after_apply=after_apply)
        with self.assertRaisesRegex(ValueError, "successful result"):
            verify(self.boundary, self.directory, [{"success": False}])

    def test_rejects_nested_migrations(self):
        (self.directory / "nested").mkdir()
        with self.assertRaisesRegex(ValueError, "Unexpected entry"):
            self.verify(self.first)
