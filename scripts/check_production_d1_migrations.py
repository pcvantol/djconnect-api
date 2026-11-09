"""Verify the production D1 migration ledger against an approved release."""

import argparse
import hashlib
import json
import re
from pathlib import Path


def verify(boundary, migrations_dir, readback, *, after_apply=False):
    approved = boundary["preflight_pending"]
    hashes = boundary.get("pending_sha256", {})
    if (
        not isinstance(approved, list)
        or any(not isinstance(name, str) for name in approved)
        or len(set(approved)) != len(approved)
        or not isinstance(hashes, dict)
        or set(hashes) != set(approved)
    ):
        raise ValueError("Invalid manifest migration allowlist")

    files = sorted(migrations_dir.iterdir())
    if not files or any(
        not file.is_file()
        or file.is_symlink()
        or not re.fullmatch(r"[0-9]{4}_[a-z0-9_]+\.sql", file.name)
        for file in files
    ):
        raise ValueError("Unexpected entry in the release migrations directory")
    names = [file.name for file in files]
    if len({name[:4] for name in names}) != len(names):
        raise ValueError("Duplicate release migration number")
    if approved and names[-len(approved):] != approved:
        raise ValueError("Approved migrations are not the exact release suffix")
    for name in approved:
        if hashlib.sha256((migrations_dir / name).read_bytes()).hexdigest() != hashes[name]:
            raise ValueError(f"Approved migration checksum mismatch: {name}")

    if not isinstance(readback, list) or len(readback) != 1 or readback[0]["success"] is not True:
        raise ValueError("D1 migration ledger query did not return one successful result")
    rows = readback[0]["results"]
    if not isinstance(rows, list):
        raise ValueError("Invalid D1 migration ledger")
    expected_pending = [] if after_apply else approved
    expected_applied = names[:len(names) - len(expected_pending)]
    if [row["name"] for row in rows] != expected_applied:
        raise ValueError("Live D1 migration ledger does not match the approved release state")
    return expected_pending


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("migrations", type=Path)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--after-apply", action="store_true")
    args = parser.parse_args()
    try:
        pending = verify(
            json.loads(args.manifest.read_text())["migration_boundary"],
            args.migrations,
            json.loads(args.ledger.read_text()),
            after_apply=args.after_apply,
        )
    except (KeyError, TypeError, ValueError, OSError) as error:
        parser.exit(1, f"Production D1 migration check failed: {error}\n")
    for name in pending:
        print(name)


if __name__ == "__main__":
    main()
