#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./cleanup_old_releases.sh [--keep N] [--keep-workflow-runs N] [--skip-workflow-runs] [--execute]

Examples:
  ./cleanup_old_releases.sh
  ./cleanup_old_releases.sh --keep 1
  ./cleanup_old_releases.sh --keep 2 --execute
  ./cleanup_old_releases.sh --keep 1 --keep-workflow-runs 10 --execute

By default this is a dry-run. It keeps the newest semantic-version tags/releases
and the newest GitHub Actions workflow runs. It deletes older matching vX.Y.Z
GitHub releases, remote tags, local tags and workflow runs only when --execute
is passed.
EOF
}

KEEP=1
KEEP_WORKFLOW_RUNS=1
CLEAN_WORKFLOW_RUNS=true
EXECUTE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
        echo "--keep requires a positive number." >&2
        exit 64
      fi
      KEEP="$2"
      shift 2
      ;;
    --keep-workflow-runs)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -lt 1 ]]; then
        echo "--keep-workflow-runs requires a positive number." >&2
        exit 64
      fi
      KEEP_WORKFLOW_RUNS="$2"
      shift 2
      ;;
    --skip-workflow-runs)
      CLEAN_WORKFLOW_RUNS=false
      shift
      ;;
    --execute)
      EXECUTE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 64
      ;;
  esac
done

if [[ ! -d ".git" || ! -f "wrangler.jsonc" || ! -f "package.json" ]]; then
  echo "Run this script from the djconnect-api repository root." >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI 'gh' is required." >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "GitHub CLI is not authenticated. Run 'gh auth login' first." >&2
  exit 1
fi

run() {
  echo "+ $*"
  if [[ "$EXECUTE" == true ]]; then
    "$@"
  fi
}

cleanup_workflow_runs() {
  if [[ "$CLEAN_WORKFLOW_RUNS" != true ]]; then
    echo
    echo "Skipping GitHub Actions workflow run cleanup."
    return
  fi

  local runs_json
  local run_count
  local delete_count

  runs_json="$(gh run list --status completed --limit 1000 --json databaseId,createdAt,workflowName,headBranch,status,conclusion)"
  run_count="$(printf '%s' "$runs_json" | node -e 'const fs=require("fs"); const runs=JSON.parse(fs.readFileSync(0,"utf8") || "[]"); console.log(runs.length);')"

  echo
  echo "Newest GitHub Actions workflow runs to keep: $KEEP_WORKFLOW_RUNS"

  if [[ "$run_count" -eq 0 ]]; then
    echo "No GitHub Actions workflow runs found."
    return
  fi

  printf '%s' "$runs_json" | node -e '
    const fs = require("fs");
    const keep = Number(process.argv[1]);
    const runs = JSON.parse(fs.readFileSync(0, "utf8") || "[]");
    for (const run of runs.slice(0, keep)) {
      console.log(`  ${run.databaseId} ${run.createdAt} ${run.workflowName} ${run.headBranch} ${run.conclusion || run.status}`);
    }
  ' "$KEEP_WORKFLOW_RUNS"

  if [[ "$run_count" -le "$KEEP_WORKFLOW_RUNS" ]]; then
    echo "No old GitHub Actions workflow runs to delete."
    return
  fi

  delete_count=$((run_count - KEEP_WORKFLOW_RUNS))
  echo
  if [[ "$EXECUTE" == true ]]; then
    echo "Deleting $delete_count old GitHub Actions workflow runs:"
  else
    echo "Dry-run. Would delete $delete_count old GitHub Actions workflow runs:"
  fi

  printf '%s' "$runs_json" | node -e '
    const fs = require("fs");
    const keep = Number(process.argv[1]);
    const runs = JSON.parse(fs.readFileSync(0, "utf8") || "[]");
    for (const run of runs.slice(keep)) {
      console.log(`${run.databaseId}\t${run.createdAt}\t${run.workflowName}\t${run.headBranch}\t${run.conclusion || run.status}`);
    }
  ' "$KEEP_WORKFLOW_RUNS" | while IFS=$'\t' read -r run_id created_at workflow_name head_branch result; do
    echo "  $run_id $created_at $workflow_name $head_branch $result"
    run gh run delete "$run_id"
  done
}

mapfile -t TAGS < <(
  git ls-remote --tags --refs origin 'v*' \
    | awk '{print $2}' \
    | sed 's#refs/tags/##' \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
    | sort -V -r
)

if [[ "${#TAGS[@]}" -eq 0 ]]; then
  echo "No semantic version tags found on origin."
else
  echo "Newest tags/releases to keep:"
  printf '  %s\n' "${TAGS[@]:0:KEEP}"

  if [[ "${#TAGS[@]}" -le "$KEEP" ]]; then
    echo "No old releases/tags to delete."
  else
    DELETE_TAGS=("${TAGS[@]:KEEP}")

    echo
    if [[ "$EXECUTE" == true ]]; then
      echo "Deleting old releases/tags:"
    else
      echo "Dry-run. Would delete old releases/tags:"
    fi
    printf '  %s\n' "${DELETE_TAGS[@]}"
    echo

    for tag in "${DELETE_TAGS[@]}"; do
      if gh release view "$tag" >/dev/null 2>&1; then
        run gh release delete "$tag" --yes
      else
        echo "+ skip missing GitHub release $tag"
      fi
      run git push --delete origin "$tag"
      if git rev-parse "$tag" >/dev/null 2>&1; then
        run git tag -d "$tag"
      else
        echo "+ skip missing local tag $tag"
      fi
    done
  fi
fi

cleanup_workflow_runs

if [[ "$EXECUTE" == false ]]; then
  echo
  echo "Dry-run complete. Re-run with --execute to delete the old releases/tags and workflow runs."
fi
