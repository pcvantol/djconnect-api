"""Active-head retention, incomplete inventories and late provider changes."""
import copy
from contextlib import redirect_stdout
import io
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('retention', Path(__file__).with_name('cleanup_workflow_runs.py'))
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)
ORIGINAL, PREMERGE, OPEN, ARCHIVE_A, ARCHIVE_B, OLD = [c * 40 for c in 'abcdef']
ROOT = 'repos/fixture/api'


def run(number, head, minute, workflow=20, status='completed'):
    return {'id': number, 'head_sha': head, 'status': status, 'workflow_id': workflow,
            'created_at': '2026-11-01T09:' + minute + ':00Z'}


class Provider:
    def __init__(self):
        # Old branch dates are later than the actual source-main date: this is
        # the provider ordering that caused the real main-evidence deletion.
        self.runs = {
            10: [run(101, ARCHIVE_A, '47', 10), run(102, ARCHIVE_B, '46', 10),
                 run(100, ORIGINAL, '22', 10), run(105, OLD, '00', 10)],
            20: [run(204, ARCHIVE_A, '48'), run(205, ARCHIVE_B, '47'),
                 run(200, ORIGINAL, '22'), run(201, OPEN, '10'),
                 run(202, PREMERGE, '05'), run(203, OLD, '00')],
        }
        self.main_reads = 0
        self.open_reads = 0
        self.calls = []
        self.deleted = []
        self.fail_workflow = None
        self.change_main = False
        self.change_main_at = 2
        self.new_open_head = None
        self.actual_status = {}
        self.changed_run = None
        self.fail_fresh = False

    def get(self, endpoint, paginated=False):
        self.calls.append(endpoint)
        if endpoint == ROOT + '/git/ref/heads/main':
            self.main_reads += 1
            return {'object': {'sha': '0' * 40 if self.change_main and self.main_reads >= self.change_main_at else ORIGINAL}}
        if endpoint == ROOT + '/pulls?state=open&per_page=100':
            self.open_reads += 1
            if self.fail_fresh and self.open_reads > 1:
                raise retention.SafetyStop('pagination_failed')
            values = [[{'head': {'sha': OPEN}}]]
            if self.new_open_head and self.open_reads > 1:
                values.append([{'head': {'sha': self.new_open_head}}])
            return values
        if endpoint == ROOT + '/commits/' + ORIGINAL + '/pulls?per_page=100':
            return [[{'merged_at': '2026-11-01T09:22:00Z', 'base': {'ref': 'main'},
                      'merge_commit_sha': ORIGINAL, 'head': {'sha': PREMERGE}}]]
        if endpoint == ROOT + '/actions/workflows?per_page=100':
            return [{'workflows': [{'id': 10}]}, {'workflows': [{'id': 20}]}]
        if endpoint.startswith(ROOT + '/actions/workflows/'):
            workflow = int(endpoint.split('/workflows/')[1].split('/')[0])
            if workflow == self.fail_workflow:
                raise retention.SafetyStop('pagination_failed')
            return [{'workflow_runs': copy.deepcopy(self.runs[workflow])}]
        if endpoint.startswith(ROOT + '/actions/runs/'):
            number = int(endpoint.rsplit('/', 1)[1])
            if number == 1:
                return run(1, ORIGINAL, '22', 10, 'in_progress')
            value = copy.deepcopy(next(r for group in self.runs.values() for r in group if r['id'] == number))
            value['status'] = self.actual_status.get(number, value['status'])
            if number == self.changed_run:
                value['head_sha'] = '1' * 40
            return value
        raise AssertionError(endpoint)

    def delete(self, endpoint):
        # Prove that every workflow inventory completed before any mutation.
        assert any('/workflows/20/runs?' in path for path in self.calls)
        self.deleted.append(int(endpoint.rsplit('/', 1)[1]))


class RetentionTests(unittest.TestCase):
    def invoke(self, api, execute=True):
        with redirect_stdout(io.StringIO()):
            return retention.cleanup(api, 'fixture/api', ORIGINAL, 1, keep=2, execute=execute)

    def test_later_created_old_branches_cannot_delete_main_across_workflows(self):
        api = Provider()
        # Legacy chronological keep2 selected 200 even though it is own main.
        self.assertIn(200, [r['id'] for r in sorted(api.runs[20], key=lambda r: r['created_at'], reverse=True)[2:]])
        result = self.invoke(api)
        self.assertEqual(api.deleted, [102, 105, 203])
        self.assertNotIn(100, result['deleted'])
        self.assertNotIn(200, result['deleted'])

    def test_open_and_specific_premerge_heads_remain_protected(self):
        api = Provider()
        self.invoke(api)
        self.assertNotIn(201, api.deleted)
        self.assertNotIn(202, api.deleted)

    def test_late_pagination_failure_stops_before_any_delete(self):
        api = Provider()
        api.fail_workflow = 20
        with self.assertRaises(retention.SafetyStop):
            self.invoke(api)
        self.assertEqual(api.deleted, [])

    def test_moved_main_stops_before_any_delete(self):
        api = Provider()
        api.change_main = True
        with self.assertRaisesRegex(retention.SafetyStop, 'main_changed'):
            self.invoke(api)
        self.assertEqual(api.deleted, [])

    def test_new_open_pr_on_second_page_is_protected_at_delete_boundary(self):
        api = Provider()
        api.new_open_head = OLD
        self.invoke(api)
        self.assertEqual(api.deleted, [102])

    def test_queued_running_and_unknown_status_are_not_deleted(self):
        for status in ['queued', 'in_progress']:
            with self.subTest(status=status):
                api = Provider()
                api.actual_status[102] = status
                self.invoke(api)
                self.assertNotIn(102, api.deleted)

    def test_cleanup_from_old_main_preserves_current_main_premerge_evidence(self):
        class NewMainProvider(Provider):
            def get(self, endpoint, paginated=False):
                if endpoint == ROOT + '/git/ref/heads/main':
                    self.calls.append(endpoint)
                    return {'object': {'sha': '9' * 40}}
                if endpoint == ROOT + '/commits/' + '9' * 40 + '/pulls?per_page=100':
                    self.calls.append(endpoint)
                    return [[{'merged_at': '2026-11-01T09:30:00Z', 'base': {'ref': 'main'},
                              'merge_commit_sha': '9' * 40, 'head': {'sha': OLD}}]]
                return super().get(endpoint, paginated)
        api = NewMainProvider()
        self.invoke(api)
        self.assertNotIn(105, api.deleted)
        self.assertNotIn(203, api.deleted)
        self.assertTrue(any('/commits/' + '9' * 40 + '/pulls?' in path for path in api.calls))

    def test_current_main_source_relation_lookup_failure_stops_before_delete(self):
        class UnavailableMainProvider(Provider):
            def get(self, endpoint, paginated=False):
                if endpoint == ROOT + '/git/ref/heads/main':
                    self.calls.append(endpoint)
                    return {'object': {'sha': '9' * 40}}
                if endpoint == ROOT + '/commits/' + '9' * 40 + '/pulls?per_page=100':
                    raise retention.SafetyStop('current_main_relation_unavailable')
                return super().get(endpoint, paginated)
        api = UnavailableMainProvider()
        with self.assertRaisesRegex(retention.SafetyStop, 'current_main_relation_unavailable'):
            self.invoke(api)
        self.assertEqual(api.deleted, [])

    def test_missing_current_main_origin_is_not_empty_protection(self):
        class MissingOriginProvider(Provider):
            def get(self, endpoint, paginated=False):
                if endpoint == ROOT + '/commits/' + ORIGINAL + '/pulls?per_page=100':
                    return [[]]
                return super().get(endpoint, paginated)
        api = MissingOriginProvider()
        with self.assertRaisesRegex(retention.SafetyStop, 'current_main_origin_unknown'):
            self.invoke(api)
        self.assertEqual(api.deleted, [])

    def test_unknown_fresh_status_stops_the_invocation(self):
        api = Provider()
        api.actual_status[102] = 'future_unknown_status'
        with self.assertRaisesRegex(retention.SafetyStop, 'unknown_status'):
            self.invoke(api)
        self.assertEqual(api.deleted, [])

    def test_main_moved_after_run_readback_stops_before_delete(self):
        api = Provider()
        api.change_main = True
        api.change_main_at = 3
        with self.assertRaisesRegex(retention.SafetyStop, 'main_changed'):
            self.invoke(api)
        self.assertEqual(api.deleted, [])

    def test_changed_run_source_stops_before_delete(self):
        api = Provider()
        api.changed_run = 102
        with self.assertRaisesRegex(retention.SafetyStop, 'run_changed'):
            self.invoke(api)
        self.assertEqual(api.deleted, [])

    def test_fresh_protection_failure_is_not_treated_as_empty(self):
        api = Provider()
        api.fail_fresh = True
        with self.assertRaises(retention.SafetyStop):
            self.invoke(api)
        self.assertEqual(api.deleted, [])

    def test_default_dry_run_has_no_mutation(self):
        api = Provider()
        result = self.invoke(api, execute=False)
        self.assertEqual(result['planned'], [102, 105, 203])
        self.assertEqual(api.deleted, [])

    def test_invalid_repository_and_sha_never_reach_provider(self):
        for repository, original in [('fixture/api;echo', ORIGINAL), ('fixture/api', 'not-a-sha')]:
            api = Provider()
            with self.assertRaises(retention.SafetyStop):
                retention.cleanup(api, repository, original, 1)
            self.assertEqual(api.calls, [])


if __name__ == '__main__':
    unittest.main()
