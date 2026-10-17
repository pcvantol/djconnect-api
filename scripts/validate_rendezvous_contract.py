#!/usr/bin/env python3
"""Validate design schema fixtures; does not validate crypto, DO or native runtime."""

import base64
import json
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError as error:
    raise SystemExit("Install jsonschema==4.25.1 in an isolated validation environment.") from error


def main():
    root = Path(__file__).resolve().parents[1] / "docs" / "rendezvous"
    schema = json.loads((root / "wire-request-schemas-v1.json").read_text())
    fixtures = json.loads((root / "wire-schema-cases-v1.json").read_text())
    if fixtures["kind"] != "synthetic_schema_cases_only":
        raise SystemExit("Fixture scope must remain structural, not crypto qualification.")
    Draft202012Validator.check_schema(schema)
    for case in fixtures["cases"]:
        selected = schema if case["schema"] == "$root" else {
            **schema, "$ref": "#/$defs/" + case["schema"]
        }
        if Draft202012Validator(selected).is_valid(case["value"]) != case["valid"]:
            raise SystemExit("Schema case failed: " + case["name"])
    examples = [fixtures["client_data_byte_example"],
                *fixtures.get("management_client_data_byte_examples", [])]
    for example in examples:
        encoded = example["base64url"]
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if raw.decode("utf-8") != example["utf8"] or json.loads(raw) != example["parsed"]:
            raise SystemExit("clientData byte example mismatch")
    print(f"PASS: {len(fixtures['cases'])} schema cases and {len(examples)} clientData byte examples")
    print("NOT_RUN: App Attest, JWE interoperability, DO/runtime, native and live chain")


if __name__ == "__main__":
    main()
