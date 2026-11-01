#!/usr/bin/env python3
"""Bounded retention of completed CI runs; active source heads stay protected.

Dry-run by default. Inventory failures stop before deletion. Rechecks narrow a
race window; GitHub does not provide an atomic run/ref compare-and-delete here.
"""
import argparse
from datetime import datetime
import json
import os
import re
import subprocess


class SafetyStop(ValueError):
    pass


def require(value, reason):
    if not value:
        raise SafetyStop(reason)


def source_sha(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}', value), 'invalid_sha')
    return value


def run_id(value):
    require(type(value) is int and value > 0, 'invalid_run_id')
    return value


def page_items(pages, key=None):
    require(isinstance(pages, list), 'invalid_pages')
    result = []
    for page in pages:
        items = page.get(key) if key and isinstance(page, dict) else page
        require(isinstance(items, list), 'invalid_page')
        result.extend(items)
    return result


class GitHub:
    def get(self, endpoint, paginated=False):
        args = ['gh', 'api', endpoint]
        if paginated:
            args.extend(['--paginate', '--slurp'])
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
        require(result.returncode == 0, 'inventory_unavailable')
        try:
            return json.loads(result.stdout)
        except (ValueError, TypeError) as error:
            raise SafetyStop('invalid_inventory_json') from error

    def delete(self, endpoint):
        result = subprocess.run(['gh', 'api', '--method', 'DELETE', endpoint],
                                capture_output=True, text=True, timeout=60)
        require(result.returncode == 0, 'delete_failed')


def protected_heads(api, repository, original, expected_main=None):
    root = 'repos/' + repository
    main = source_sha(api.get(root + '/git/ref/heads/main')['object']['sha'])
    require(expected_main is None or main == expected_main, 'main_changed_stop_cleanup')
    protected = {original, main}
    for pr in page_items(api.get(root + '/pulls?state=open&per_page=100', True)):
        protected.add(source_sha(pr['head']['sha']))
    # Preserve the specific pre-merge evidence relationship as well.
    for revision in dict.fromkeys((original, main)):
        related = set()
        for pr in page_items(api.get(root + '/commits/' + revision + '/pulls?per_page=100', True)):
            if (pr.get('merged_at') and pr['base']['ref'] == 'main'
                    and pr.get('merge_commit_sha') == revision):
                related.add(source_sha(pr['head']['sha']))
        if revision == main:
            require(bool(related), 'current_main_origin_unknown_stop_cleanup')
        protected.update(related)
    return main, protected


def validate_run(value):
    require(isinstance(value, dict), 'invalid_run')
    run_id(value['id'])
    source_sha(value['head_sha'])
    require(value['status'] in ('completed', 'queued', 'in_progress', 'waiting', 'pending', 'requested'), 'unknown_status_stop_cleanup')
    timestamp = datetime.fromisoformat(value['created_at'].replace('Z', '+00:00'))
    require(timestamp.tzinfo is not None, 'missing_timestamp_zone')
    return timestamp


def cleanup(api, repository, original, current_run, keep=2, execute=False, maximum=100):
    require(isinstance(repository, str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            and all(part not in ('.', '..') for part in repository.split('/')), 'invalid_repository')
    source_sha(original)
    run_id(current_run)
    require(type(keep) is int and 1 <= keep <= 100, 'invalid_keep')
    require(type(maximum) is int and 1 <= maximum <= 100, 'invalid_budget')
    root = 'repos/' + repository
    current = api.get(root + '/actions/runs/' + str(current_run))
    require(current['head_sha'] == original, 'current_run_source_mismatch')
    current_workflow = run_id(current['workflow_id'])
    initial_main, initial_protected = protected_heads(api, repository, original)
    workflows = page_items(api.get(root + '/actions/workflows?per_page=100', True), 'workflows')
    candidates = []
    # Complete every paginated inventory before the first possible DELETE.
    for workflow in workflows:
        workflow_id = run_id(workflow['id'])
        runs = page_items(api.get(root + '/actions/workflows/' + str(workflow_id)
                                 + '/runs?status=completed&per_page=100', True), 'workflow_runs')
        ordered = sorted(runs, key=validate_run, reverse=True)
        limit = keep - 1 if workflow_id == current_workflow else keep
        for value in ordered[limit:]:
            if (value['status'] == 'completed' and value['id'] != current_run
                    and value['head_sha'] not in initial_protected):
                candidates.append(value)
    report = {'scope': 'COMPLETED_RUN_RETENTION_WITH_ACTIVE_SOURCE_PROTECTION',
              'original_sha': original, 'main_sha': initial_main, 'execute': execute,
              'planned': [], 'deleted': [], 'skipped': []}
    for indexed in candidates[:maximum]:
        main, fresh_protected = protected_heads(api, repository, original, initial_main)
        require(main == initial_main, 'main_changed_stop_cleanup')
        actual = api.get(root + '/actions/runs/' + str(indexed['id']))
        validate_run(actual)
        require(actual['id'] == indexed['id'] and actual['head_sha'] == indexed['head_sha'], 'run_changed_stop_cleanup')
        if actual['status'] != 'completed' or actual['head_sha'] in initial_protected | fresh_protected:
            report['skipped'].append(actual['id'])
            continue
        # Ref movement during the other lookups also stops this invocation.
        final_main = source_sha(api.get(root + '/git/ref/heads/main')['object']['sha'])
        require(final_main == initial_main, 'main_changed_stop_cleanup')
        report['planned'].append(actual['id'])
        if execute:
            print(json.dumps({'scope': 'CI_RETENTION_DELETE_ATTEMPT', 'run_id': actual['id'],
                              'head_sha': actual['head_sha']}), flush=True)
            api.delete(root + '/actions/runs/' + str(actual['id']))
            print(json.dumps({'scope': 'CI_RETENTION_DELETED', 'run_id': actual['id']}), flush=True)
            report['deleted'].append(actual['id'])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default=os.environ.get('REPOSITORY'))
    parser.add_argument('--original-sha', default=os.environ.get('GITHUB_SHA'))
    parser.add_argument('--current-run-id', type=int, default=os.environ.get('CURRENT_RUN_ID'))
    parser.add_argument('--keep', type=int, default=2)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(cleanup(GitHub(), args.repository, args.original_sha,
                                 args.current_run_id, args.keep, args.execute), sort_keys=True))
    except (SafetyStop, KeyError, TypeError, ValueError, OSError, subprocess.TimeoutExpired):
        print(json.dumps({'scope': 'CI_RETENTION_STOPPED', 'result': 'STOPPED_NOT_AUTHORIZED_TO_CONTINUE'}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
