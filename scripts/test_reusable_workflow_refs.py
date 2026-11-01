"""Exercise the actual Bash guard in sparse-PATH fixtures; no real GitHub calls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--scratch", type=Path, required=True)
parser.add_argument("--report", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
scratch = args.scratch.resolve(strict=True)
if scratch == root or root in scratch.parents:
    raise SystemExit("External scratch required")
source = root / "scripts/check_reusable_workflow_refs.sh"
reference = "pcvantol/djconnect/.github/workflows/example.yml@" + "1" * 40
mock = """#!/bin/bash
printf '%s\\n' "$*" >> "$CASE_LOG"
case "$2" in
  */compare/*)
    [[ "$GH_MODE" != compare_failure ]] || exit 42
    printf '%s\\n' "$COMPARE_STATUS" ;;
  *)
    [[ "$GH_MODE" != contents_failure ]] || exit 44
    printf '%s\\n' '.github/workflows/example.yml' ;;
esac
"""
cases = [
    "valid_without_rg", "dedup_without_rg", "canonical_behind_refused",
    "canonical_compare_failure", "referenced_workflow_missing",
    "enumeration_git_failure", "enumeration_sort_failure",
    "no_matching_refs", "missing_git", "missing_gh",
]


def run(case):
    with tempfile.TemporaryDirectory(prefix="workflow-ref-", dir=scratch) as temp:
        fixture = Path(temp)
        binaries = fixture / "bin"
        binaries.mkdir()
        workflows = fixture / ".github/workflows"
        workflows.mkdir(parents=True)
        content = "uses: " + reference + "\n"
        (workflows / "a.yml").write_text(
            content if case != "no_matching_refs" else "name: no canonical pins\n"
        )
        if case == "dedup_without_rg":
            (workflows / "b.yml").write_text(content)
        for name in ["git", "sort"]:
            if case == "missing_git" and name == "git":
                continue
            target = shutil.which(name)
            if not target:
                raise RuntimeError("Test host requires " + name)
            os.symlink(os.path.realpath(target), binaries / name)
        for name, mode in [("git", "enumeration_git_failure"),
                           ("sort", "enumeration_sort_failure")]:
            if case == mode:
                (binaries / name).unlink()
                (binaries / name).write_text("#!/bin/bash\nexit 23\n")
                (binaries / name).chmod(0o755)
        if case != "missing_gh":
            (binaries / "gh").write_text(mock)
            (binaries / "gh").chmod(0o755)
        # Neither real gh nor rg is reachable. git is used only for local grep.
        environment = {
            **os.environ,
            "PATH": str(binaries),
            "CASE_LOG": str(fixture / "calls"),
            "GH_MODE": "compare_failure" if case == "canonical_compare_failure"
            else "contents_failure" if case == "referenced_workflow_missing"
            else "normal",
            "COMPARE_STATUS": "behind" if case == "canonical_behind_refused"
            else "ahead",
        }
        result = subprocess.run(
            ["/bin/bash", str(source)], cwd=fixture, env=environment,
            text=True, capture_output=True, timeout=10,
        )
        calls = (fixture / "calls").read_text().splitlines() if (
            fixture / "calls"
        ).exists() else []
        if case in ["valid_without_rg", "dedup_without_rg"]:
            expected = [
                "api repos/pcvantol/djconnect/compare/" + "1" * 40 + "...main --jq .status",
                "api repos/pcvantol/djconnect/contents/.github/workflows/example.yml?ref="
                + "1" * 40 + " --jq .path",
            ]
            passed = result.returncode == 0 and calls == expected
        else:
            passed = result.returncode != 0
        return {"case": case, "passed": passed, "exit": result.returncode,
                "mock_GH_calls": len(calls), "stderr": result.stderr.strip()}


results = [run(case) for case in cases]
report = {"script_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
          "passed": sum(item["passed"] for item in results),
          "failed": sum(not item["passed"] for item in results),
          "real_GH_or_network_calls": False, "cases": results}
if args.report:
    destination = args.report.resolve()
    if destination == root or root in destination.parents:
        raise SystemExit("External report required")
    with destination.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
print(json.dumps(report, indent=2))
raise SystemExit(0 if report["failed"] == 0 else 1)
