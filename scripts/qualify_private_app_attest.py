#!/usr/bin/env python3
"""Offline genuine-fixture research; NOT a deployable or complete server verifier.

Requires isolated cryptography==50.0.2 and asn1crypto==1.5.1, OpenSSL CLI,
private decoder output and independently retrieved public Apple roots.
Only fixed labels/booleans/counters/public-root digests are emitted.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import cryptography
import asn1crypto
from datetime import datetime, timezone
from pathlib import Path

from asn1crypto import core
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends.openssl.backend import backend


class Nonce(core.Sequence):
    _fields = [("nonce", core.OctetString, {"explicit": 1})]


class Attribute(core.Sequence):
    _fields = [("type", core.Integer), ("version", core.Integer), ("value", core.OctetString)]


class Attributes(core.SetOf):
    _child_spec = Attribute


def main():
    source, anchors, work = map(Path, sys.argv[1:4])
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    assert work.stat().st_mode & 0o077 == 0
    fixture = json.loads(source.read_text())
    assert set(fixture["slots"]) == {"active", "replacement"}
    assert cryptography.__version__ == "50.0.2" and asn1crypto.__version__ == "1.5.1"
    b64 = lambda text: base64.b64decode(text, validate=True)
    checks = []

    def check(name, function, rejected=False):
        try:
            function()
        except (AssertionError, ValueError, InvalidSignature):
            if not rejected:
                raise RuntimeError(name) from None
        else:
            if rejected:
                raise RuntimeError(name) from None
        checks.append({"name": name, "result": "rejected" if rejected else "pass"})

    def equal(a, b):
        assert a == b

    def save(path, value):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)

    root = x509.load_pem_x509_certificate((anchors / "attestation-root.pem").read_bytes())
    receipt_root = x509.load_der_x509_certificate((anchors / "receipt-root.cer").read_bytes())
    save(work / "receipt-root.pem", receipt_root.public_bytes(Encoding.PEM))
    anchor_fingerprints = {
        "attestation": root.fingerprint(hashes.SHA256()).hex(),
        "receipt": receipt_root.fingerprint(hashes.SHA256()).hex(),
    }
    assert anchor_fingerprints == {
        "attestation": "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932",
        "receipt": "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
    }

    def path_result(leaf, intermediate, strict=False, at=None, trusted=None):
        command = ["openssl", "verify", "-purpose", "any", "-no-CApath", "-no-CAstore",
                   "-CAfile", str(trusted or anchors / "attestation-root.pem"),
                   "-untrusted", str(intermediate)]
        if strict:
            command.append("-x509_strict")
        if at is not None:
            command.extend(["-attime", str(int(at.timestamp()))])
        command.append(str(leaf))
        return subprocess.run(command, capture_output=True, check=False)

    expected_app_hash = hashlib.sha256(b"ZEML4LPXH4.dev.djconnect.ios").digest()

    def counter_after(new, old):
        assert type(old) is int and 0 <= old <= 0xffffffff
        assert type(new) is int and 0 < new <= 0xffffffff and new > old

    def nonce_value(encoded):
        value = Nonce.load(encoded, strict=True)
        assert len(value) == 1
        assert value.dump(force=True) == encoded
        result = value["nonce"].native
        assert len(result) == 32
        return result

    def signature_valid(public, auth, signature, client):
        nonce = hashlib.sha256(auth + hashlib.sha256(client).digest()).digest()
        public.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))

    stale_receipts = 0
    for slot, value in fixture["slots"].items():
        directory = work / slot
        directory.mkdir(mode=0o700, exist_ok=True)
        certs = [x509.load_der_x509_certificate(b64(item)) for item in value["certificates"]]
        leaf, intermediate = certs
        leaf_path, intermediate_path = directory / "leaf.pem", directory / "intermediate.pem"
        save(leaf_path, leaf.public_bytes(Encoding.PEM))
        save(intermediate_path, intermediate.public_bytes(Encoding.PEM))
        public = leaf.public_key()
        save(directory / "public-key.pem", public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        assert isinstance(public, ec.EllipticCurvePublicKey) and public.curve.name == "secp256r1"
        check(slot + ":standard-openssl-path", lambda: equal(path_result(leaf_path, intermediate_path).returncode, 0))
        strict = path_result(leaf_path, intermediate_path, strict=True)
        check(slot + ":strict-rfc-mode-rejects-missing-leaf-aki", lambda: (
            equal(strict.returncode, 2),
            equal(b"Missing Authority Key Identifier" in strict.stderr, True)))
        check(slot + ":wrong-trust-anchor", lambda: equal(
            path_result(leaf_path, intermediate_path, trusted=work / "receipt-root.pem").returncode, 0), True)
        check(slot + ":reversed-certificate-order-leaf-policy", lambda: equal(
            intermediate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, False), True)
        from datetime import timedelta
        check(slot + ":before-certificate-validity", lambda: equal(path_result(
            leaf_path, intermediate_path, at=leaf.not_valid_before_utc - timedelta(seconds=1)).returncode, 0), True)
        check(slot + ":after-certificate-validity", lambda: equal(path_result(
            leaf_path, intermediate_path, at=leaf.not_valid_after_utc + timedelta(seconds=1)).returncode, 0), True)
        damaged = bytearray(leaf.public_bytes(Encoding.DER)); damaged[-1] ^= 1
        damaged_path = directory / "damaged-leaf.pem"
        save(damaged_path, x509.load_der_x509_certificate(bytes(damaged)).public_bytes(Encoding.PEM))
        check(slot + ":damaged-leaf-signature", lambda: equal(path_result(damaged_path, intermediate_path).returncode, 0), True)
        # These assertions constrain the measured Apple certificate, not all PKI paths.
        check(slot + ":leaf-not-ca", lambda: equal(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, False))
        check(slot + ":intermediate-is-ca", lambda: equal(intermediate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, True))
        check(slot + ":intermediate-key-cert-sign", lambda: equal(intermediate.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign, True))
        auth, client, credential = b64(value["auth"]), b64(value["input"]), b64(value["credential"])
        nonce_extension = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.2.840.113635.100.8.2")).value.value
        computed_nonce = hashlib.sha256(auth + hashlib.sha256(client).digest()).digest()
        check(slot + ":strict-der-nonce-binding", lambda: equal(nonce_value(nonce_extension), computed_nonce))
        check(slot + ":changed-attestation-challenge", lambda: equal(nonce_value(nonce_extension),
            hashlib.sha256(auth + hashlib.sha256(client + b"changed").digest()).digest()), True)
        check(slot + ":nonce-trailing-data", lambda: nonce_value(nonce_extension + b"\0"), True)
        synthetic_nonce = Nonce({"nonce": bytes(32)}).dump()
        duplicate_nonce = bytes([0x30, 2 * (len(synthetic_nonce) - 2)]) + synthetic_nonce[2:] * 2
        check(slot + ":nonce-duplicate-field", lambda: nonce_value(duplicate_nonce), True)
        check(slot + ":nonce-wrong-length", lambda: nonce_value(Nonce({"nonce": bytes(31)}).dump()), True)
        point = public.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        check(slot + ":credential-leaf-key-binding", lambda: equal(hashlib.sha256(point).digest(), credential))
        check(slot + ":cose-leaf-binding", lambda: equal(point, b"\x04" + b64(value["cose_x"]) + b64(value["cose_y"])))
        check(slot + ":app-id-binding", lambda: equal(auth[:32], expected_app_hash))
        check(slot + ":wrong-app-id", lambda: equal(auth[:32], hashlib.sha256(b"other.invalid.app").digest()), True)
        check(slot + ":development-marker", lambda: equal(auth[37:53], b"appattestdevelop"))
        check(slot + ":production-policy-rejects-development", lambda: equal(auth[37:53], b"appattest" + b"\0" * 7), True)

        receipt = b64(value["receipt"])
        receipt_path = directory / "receipt.cms"
        save(receipt_path, receipt)
        command = ["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", str(receipt_path),
                   "-CAfile", str(work / "receipt-root.pem"), "-no-CApath", "-no-CAstore", "-purpose", "any",
                   "-x509_strict", "-out", str(directory / "receipt-content.bin")]
        save(directory / "receipt-content.bin", b"")
        check(slot + ":receipt-cms-signature-strict-path", lambda: equal(
            subprocess.run(command, capture_output=True, check=False).returncode, 0))
        # Parse the payload that OpenSSL actually authenticated, not an unverified extraction.
        payload = (directory / "receipt-content.bin").read_bytes()
        attributes = Attributes.load(payload, strict=True)
        fields = {}
        for attribute in attributes:
            key = attribute["type"].native
            assert key not in fields and attribute["version"].native == 1
            fields[key] = attribute["value"].native
        check(slot + ":receipt-app-id", lambda: equal(fields[2], b"ZEML4LPXH4.dev.djconnect.ios"))
        check(slot + ":receipt-attested-cert-binding", lambda: equal(fields[3], leaf.public_bytes(Encoding.DER)))
        check(slot + ":receipt-initial-type", lambda: equal(fields[6], b"ATTEST"))
        check(slot + ":receipt-wrong-app", lambda: equal(fields[2], b"other.invalid.app"), True)
        other = "replacement" if slot == "active" else "active"
        check(slot + ":receipt-wrong-key", lambda: equal(fields[3], b64(fixture["slots"][other]["certificates"][0])), True)
        created = datetime.fromisoformat(fields[12].decode("ascii").replace("Z", "+00:00"))

        def receipt_fresh(now):
            assert created.tzinfo is not None
            age = (now - created).total_seconds()
            assert 0 <= age <= 300

        check(slot + ":receipt-at-capture-time-model", lambda: receipt_fresh(created + timedelta(seconds=1)))
        check(slot + ":receipt-stale-model", lambda: receipt_fresh(created + timedelta(seconds=301)), True)
        check(slot + ":receipt-future-model", lambda: receipt_fresh(created - timedelta(seconds=1)), True)
        if (datetime.now(timezone.utc) - created).total_seconds() > 300:
            check(slot + ":receipt-now-stale-live-enrollment-denied", lambda: receipt_fresh(datetime.now(timezone.utc)), True)
            stale_receipts += 1
        tampered = bytearray(receipt); tampered[-32] ^= 1
        save(directory / "tampered-receipt.cms", bytes(tampered))
        changed_command = command.copy(); changed_command[changed_command.index("-in") + 1] = str(directory / "tampered-receipt.cms")
        check(slot + ":tampered-receipt", lambda: equal(subprocess.run(
            changed_command, capture_output=True, check=False).returncode, 0), True)

        for item in value["assertions"]:
            data, signature, client_data = map(b64, [item["auth"], item["signature"], item["input"]])
            prefix = slot + ":assertion" + str(item["counter"])
            check(prefix + ":real-signature", lambda: signature_valid(public, data, signature, client_data))
            save(directory / "assertion-signature.der", signature)
            save(directory / "assertion-nonce.bin", hashlib.sha256(data + hashlib.sha256(client_data).digest()).digest())
            check(prefix + ":openssl-cli-signature-adapter", lambda: equal(subprocess.run([
                "openssl", "dgst", "-sha256", "-verify", str(directory / "public-key.pem"),
                "-signature", str(directory / "assertion-signature.der"), str(directory / "assertion-nonce.bin")],
                capture_output=True, check=False).returncode, 0))
            check(prefix + ":changed-client-data", lambda: signature_valid(public, data, signature, client_data + b"changed"), True)
            changed = bytearray(signature); changed[-1] ^= 1
            check(prefix + ":changed-signature", lambda: signature_valid(public, data, bytes(changed), client_data), True)
            changed_data = bytearray(data); changed_data[36] ^= 1
            check(prefix + ":changed-signed-counter", lambda: signature_valid(public, bytes(changed_data), signature, client_data), True)
            check(prefix + ":rp-app-id", lambda: equal(data[:32], expected_app_hash))
            check(prefix + ":monotone-counter", lambda: counter_after(item["counter"], item["counter"] - 1))
            check(prefix + ":replay-equal-counter", lambda: counter_after(item["counter"], item["counter"]), True)

    boundary_public = x509.load_der_x509_certificate(b64(fixture["slots"]["active"]["certificates"][0])).public_key()
    wrong_public = x509.load_der_x509_certificate(b64(fixture["slots"]["replacement"]["certificates"][0])).public_key()
    boundary = fixture["input_boundary"]["accepted_raw_hash_31"]
    boundary_auth, boundary_signature = b64(boundary["auth"]), b64(boundary["signature"])
    # Characterize actual SDK behavior, never use this raw-hash entry point for admission.
    check("sdk31:real-signature-over-31-byte-hash", lambda: boundary_public.verify(
        boundary_signature, hashlib.sha256(boundary_auth + bytes(31)).digest(), ec.ECDSA(hashes.SHA256())))
    check("sdk31:server-hashes-saved-data-rejects-raw-hash", lambda: signature_valid(
        boundary_public, boundary_auth, boundary_signature, bytes(31)), True)
    check("sdk31:counter5-not-reset", lambda: equal(boundary_auth[33:37], (5).to_bytes(4, "big")))
    next_assertion = fixture["input_boundary"]["next_normal_assertion"]
    next_auth, next_signature, next_input = map(b64, [next_assertion["auth"], next_assertion["signature"], next_assertion["input"]])
    check("sdk31:next-normal-signature-valid", lambda: signature_valid(boundary_public, next_auth, next_signature, next_input))
    check("sdk31:next-counter6", lambda: equal(next_auth[33:37], (6).to_bytes(4, "big")))
    check("sdk31:wrong-attested-key", lambda: signature_valid(wrong_public, next_auth, next_signature, next_input), True)

    for name, new, old in [("missing", 1, None), ("nan", 1, float("nan")), ("zero", 0, 0),
                            ("reordered", 1, 2), ("overflow", 0x100000000, 0xffffffff)]:
        check("counter-model:" + name, lambda new=new, old=old: counter_after(new, old), True)
    check("counter-model:upper-half", lambda: counter_after(0x80000000, 0x7fffffff))
    check("counter-model:maximum", lambda: counter_after(0xffffffff, 0xfffffffe))
    print(json.dumps({"scope": "OFFLINE_GENUINE_FIXTURE_QUALIFICATION_NOT_RUNTIME_GO",
                      "attestations": 2, "real_assertions": 10, "checks": checks,
                      "decoder_negative_checks": fixture["decoder_checks"],
                      "public_root_sha256": anchor_fingerprints,
                      "python": sys.version.split()[0], "cryptography": cryptography.__version__,
                      "asn1crypto": asn1crypto.__version__, "crypto_backend": backend.openssl_version_text(),
                      "openssl_cli": subprocess.run(["openssl", "version"], capture_output=True, check=True).stdout.decode().strip(),
                      "archived_receipts_now_stale": stale_receipts,
                      "strict_attestation_path": "REJECTED_MISSING_LEAF_AKI_NO_SILENT_EXCEPTION",
                      "native_input_boundary_test": "FAILED_ASSUMPTION_SDK_REQUIRES_32_BYTES_NOT_RELABELED_PASS",
                      "not_run": ["full adversarial PKI corpus", "revocation availability", "production enrollment",
                                  "workerd/DO races/crashes", "server recovery/revoke", "HA/TV E2E"]}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never dump exception paths, certificate subjects, keys, receipts or proofs.
        print("Private qualification FAILED; raw diagnostics suppressed.", file=sys.stderr)
        raise SystemExit(1)
