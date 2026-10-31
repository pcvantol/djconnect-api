#!/usr/bin/env bash
set -euo pipefail

# A GitHub commit can still resolve through the API after it leaves main, while
# Actions can reject reusable workflows pinned to that orphaned history.
# Capture discovery in the parent shell. Process-substitution failures do not
# propagate through set -e and must not silently skip every verification.
# git is already required by Actions checkout; ripgrep is not a runner contract.
if ! workflow_refs="$(git grep --no-index -h -o -E 'pcvantol/djconnect/\.github/workflows/[^ @]+@[0-9a-f]{40}' -- .github/workflows | sort -u)"; then
  echo "Cannot enumerate pinned canonical reusable workflows" >&2
  exit 1
fi
if [[ -z "${workflow_refs}" ]]; then
  echo "No pinned canonical reusable workflows found" >&2
  exit 1
fi

while IFS= read -r workflow_ref; do
  workflow_path="${workflow_ref#pcvantol/djconnect/}"
  workflow_path="${workflow_path%@*}"
  commit_sha="${workflow_ref##*@}"
  status="$(gh api "repos/pcvantol/djconnect/compare/${commit_sha}...main" --jq .status)"
  if [[ "${status}" != ahead && "${status}" != identical ]]; then
    echo "Reusable workflow is not on canonical main: ${workflow_ref} (${status})" >&2
    exit 1
  fi
  gh api "repos/pcvantol/djconnect/contents/${workflow_path}?ref=${commit_sha}" --jq .path >/dev/null
  echo "Verified ${workflow_ref}"
done <<< "${workflow_refs}"
