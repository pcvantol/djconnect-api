#!/usr/bin/env bash
set -euo pipefail

# A GitHub commit can still resolve through the API after it leaves main, while
# Actions can reject reusable workflows pinned to that orphaned history.
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
done < <(rg --no-filename -o 'pcvantol/djconnect/\.github/workflows/[^ @]+@[0-9a-f]{40}' .github/workflows | sort -u)
