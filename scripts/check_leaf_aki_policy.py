#!/usr/bin/env python3
"""Private real-fixture OpenSSL policy regression. No runtime or network access."""
import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

from cryptography import x509


def main():
    probe, anchors, qualification = map(lambda item: Path(item).resolve(), sys.argv[1:4])
    root = anchors / "attestation-root.pem"
    results = []

    def run(name, intermediate, leaf, mode, expected, epoch=None, anchor=root):
        command = [str(probe), str(anchor), str(intermediate), str(leaf), mode]
        if epoch is not None:
            command.append(str(epoch))
        response = subprocess.run(command, capture_output=True, check=False)
        value = json.loads(response.stdout)
        assert set(value) == {"verified", "allowed_missing_leaf_aki", "error_code", "error_depth"}
        assert type(value["verified"]) is bool and type(value["allowed_missing_leaf_aki"]) is bool
        assert type(value["error_code"]) is int and type(value["error_depth"]) is int
        assert value["verified"] is expected and response.returncode == (0 if expected else 1)
        results.append({"name": name, **value})
        return value

    for slot in ["active", "replacement"]:
        directory = qualification / slot
        leaf_file, intermediate_file = directory / "leaf.pem", directory / "intermediate.pem"
        leaf = x509.load_pem_x509_certificate(leaf_file.read_bytes())
        result = run(slot + ":strict-baseline", intermediate_file, leaf_file, "strict", False)
        assert result["error_code"] == 85 and not result["allowed_missing_leaf_aki"]
        result = run(slot + ":narrow-leaf-aki", intermediate_file, leaf_file, "leaf-aki", True)
        assert result["allowed_missing_leaf_aki"] and result["error_code"] == 0
        result = run(slot + ":damaged-signature", intermediate_file, directory / "damaged-leaf.pem", "leaf-aki", False)
        # Critical regression: the exception has already been used, then crypto still fails.
        assert result["allowed_missing_leaf_aki"] and result["error_code"] == 7
        run(slot + ":wrong-root", intermediate_file, leaf_file, "leaf-aki", False,
            anchor=qualification / "receipt-root.pem")
        run(slot + ":reversed", leaf_file, intermediate_file, "leaf-aki", False)
        run(slot + ":wrong-intermediate", root, leaf_file, "leaf-aki", False)
        run(slot + ":not-yet-valid", intermediate_file, leaf_file, "leaf-aki", False,
            epoch=int((leaf.not_valid_before_utc - timedelta(seconds=1)).timestamp()))
        run(slot + ":expired", intermediate_file, leaf_file, "leaf-aki", False,
            epoch=int((leaf.not_valid_after_utc + timedelta(seconds=1)).timestamp()))
    print(json.dumps({"scope": "NARROW_OFFLINE_APPLE_LEAF_AKI_POLICY_NOT_FULL_VERIFIER",
                      "count": len(results), "cases": results}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Leaf-AKI qualification FAILED; raw diagnostics suppressed.", file=sys.stderr)
        raise SystemExit(1)
