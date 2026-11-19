#!/usr/bin/env python3
"""Generate public synthetic signed certificates, never export private keys.

Qualification only: fake roots are trusted solely by the synthetic test entrypoint.
Uses cryptography50.0.2/asn1crypto1.5.1 in the isolated qualification environment.
"""
import base64
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from asn1crypto import core, x509 as asn_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID, ObjectIdentifier


class Nonce(core.Sequence):
    _fields = [("nonce", core.OctetString, {"explicit": 1})]


def main():
    now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
    root_key, inter_key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    names = [x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic QA " + role)])
             for role in ["Root", "Intermediate", "Leaf"]]
    nonce_oid = ObjectIdentifier("1.2.840.113635.100.8.2")
    eku_oid = ObjectIdentifier("1.2.840.113635.100.4.24")

    def cert(role, variant):
        index = ["root", "intermediate", "leaf"].index(role)
        key = [root_key, inter_key, leaf_key][index]
        signer = root_key if index < 2 else inter_key
        if role == "leaf" and variant == "leaf-rsa": key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if role == "leaf" and variant == "leaf-p384": key = ec.generate_private_key(ec.SECP384R1())
        ca = role != "leaf"
        if variant == role + "-not-ca": ca = False
        if role == "leaf" and variant == "leaf-is-ca": ca = True
        before, after = now - timedelta(days=2), now + timedelta(days=2)
        if variant == role + "-future": before = now + timedelta(seconds=1)
        if variant == role + "-expired": after = now - timedelta(seconds=1)
        issuer = names[0 if index < 2 else 1]
        if role == "leaf" and variant == "wrong-issuer-name": issuer = names[0]
        builder = x509.CertificateBuilder().subject_name(names[index]).issuer_name(issuer).public_key(key.public_key())
        builder = builder.serial_number(x509.random_serial_number()).not_valid_before(before).not_valid_after(after)
        path_length = 1 if role == "root" else 0 if role == "intermediate" else None
        if variant == "root-pathlen-zero" and role == "root": path_length = 0
        if not ca: path_length = None
        if variant != role + "-missing-bc":
            builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length),
                critical=variant != role + "-noncritical-bc")
        if variant != role + "-missing-ku":
            sign = role != "leaf" and variant != role + "-no-cert-sign"
            digital = role == "leaf" and variant != "leaf-no-digital-signature"
            builder = builder.add_extension(x509.KeyUsage(digital_signature=digital, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=sign,
                crl_sign=sign, encipher_only=False, decipher_only=False), critical=True)
        if variant != role + "-missing-ski":
            builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        if variant != role + "-missing-aki":
            identifier = x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key())
            if variant == role + "-wrong-aki": identifier = x509.AuthorityKeyIdentifier(bytes(20), None, None)
            builder = builder.add_extension(identifier, critical=False)
        if role == "leaf":
            eku = [eku_oid]
            if variant == "leaf-wrong-eku": eku = [ObjectIdentifier("1.3.6.1.5.5.7.3.1")]
            if variant == "leaf-extra-eku": eku.append(ObjectIdentifier("1.3.6.1.5.5.7.3.1"))
            if variant != "leaf-missing-eku": builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
            if variant != "leaf-missing-nonce":
                builder = builder.add_extension(x509.UnrecognizedExtension(nonce_oid, Nonce({"nonce": bytes(32)}).dump()),
                    critical=variant == "leaf-critical-nonce")
        if variant == role + "-unknown-critical" or variant == role + "-unknown-noncritical":
            builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4.5.6"), b"\x05\x00"),
                critical=variant.endswith("-critical"))
        algorithm = hashes.SHA512() if role == "leaf" and variant == "leaf-unsupported-sha512" else hashes.SHA256() if role == "leaf" else hashes.SHA384()
        return builder.sign(signer, algorithm).public_bytes(Encoding.DER)

    variants = [
        "valid", "leaf-missing-aki", "intermediate-missing-aki", "leaf-wrong-aki", "intermediate-wrong-aki",
        "root-missing-ski", "intermediate-missing-ski", "leaf-is-ca", "intermediate-not-ca", "root-not-ca",
        "leaf-missing-bc", "leaf-noncritical-bc", "leaf-missing-ku", "leaf-no-digital-signature",
        "intermediate-no-cert-sign", "root-no-cert-sign", "leaf-wrong-eku", "leaf-extra-eku", "leaf-missing-eku",
        "leaf-missing-nonce", "leaf-critical-nonce", "leaf-rsa", "leaf-p384", "leaf-unsupported-sha512",
        "leaf-unknown-critical", "intermediate-unknown-critical", "root-unknown-critical", "leaf-unknown-noncritical",
        "root-pathlen-zero", "wrong-issuer-name", "leaf-future", "leaf-expired", "intermediate-future",
        "intermediate-expired", "root-future", "root-expired",
    ]
    cases = []
    for variant in variants:
        root, intermediate, leaf = (cert(role, variant) for role in ["root", "intermediate", "leaf"])
        cases.append({"name": variant, "expected": variant in ["valid", "leaf-missing-aki"],
            "scope": "synthetic-qualification-only", "rootPin": hashlib.sha256(root).hexdigest(),
            "root": base64.b64encode(root).decode(), "intermediate": base64.b64encode(intermediate).decode(),
            "leaf": base64.b64encode(leaf).decode(), "now": int(now.timestamp() * 1000)})
    valid = cases[0]
    for variant in ["wrong-root-pin", "damaged-leaf", "damaged-intermediate", "damaged-root-self-signature",
                    "trailing-der", "truncated-der", "oversize", "reversed", "duplicate-extension", "algorithm-mismatch",
                    "nonminimal-outer-length", "indefinite-outer-length", "outer-ecdsa-null-parameters",
                    "signature-unused-bits", "invalid-ec-point", "zero-serial", "negative-serial", "version-v1", "leaf-pathlen-without-ca"]:
        item = {**valid, "name": variant, "expected": False}
        if variant == "wrong-root-pin": item["rootPin"] = "0" * 64
        elif variant == "reversed": item["leaf"], item["intermediate"] = item["intermediate"], item["leaf"]
        else:
            field = "intermediate" if variant == "damaged-intermediate" else "root" if variant == "damaged-root-self-signature" else "leaf"
            raw = base64.b64decode(item[field])
            if variant.startswith("damaged"): raw = raw[:-1] + bytes([raw[-1] ^ 1])
            elif variant == "trailing-der": raw += b"\0"
            elif variant == "truncated-der": raw = raw[:-1]
            elif variant == "oversize": raw *= 10
            elif variant == "nonminimal-outer-length":
                assert raw[:2] == b"\x30\x82"
                raw = b"\x30\x83\0" + raw[2:]
            elif variant == "indefinite-outer-length":
                assert raw[:2] == b"\x30\x82"
                raw = b"\x30\x80" + raw[4:] + b"\0\0"
            elif variant == "signature-unused-bits":
                while asn_x509.Certificate.load(raw)["signature_value"].native[-1] & 1:
                    raw = cert("leaf", "valid")
                signature = asn_x509.Certificate.load(raw)["signature_value"].native
                position = len(raw) - len(signature) - 1
                assert raw[position] == 0
                raw = raw[:position] + b"\x01" + raw[position + 1:]
            elif variant in ["duplicate-extension", "algorithm-mismatch", "outer-ecdsa-null-parameters", "invalid-ec-point",
                              "zero-serial", "negative-serial", "version-v1", "leaf-pathlen-without-ca"]:
                parsed = asn_x509.Certificate.load(raw, strict=True)
                if variant == "duplicate-extension":
                    parsed["tbs_certificate"]["extensions"].append(parsed["tbs_certificate"]["extensions"][0])
                elif variant == "algorithm-mismatch": parsed["tbs_certificate"]["signature"]["algorithm"] = "sha384_ecdsa"
                elif variant == "outer-ecdsa-null-parameters": parsed["signature_algorithm"]["parameters"] = core.Null()
                elif variant == "invalid-ec-point": parsed["tbs_certificate"]["subject_public_key_info"]["public_key"] = b"\x04" + bytes(64)
                elif variant == "zero-serial": parsed["tbs_certificate"]["serial_number"] = 0
                elif variant == "negative-serial": parsed["tbs_certificate"]["serial_number"] = -1
                elif variant == "version-v1": parsed["tbs_certificate"]["version"] = "v1"
                elif variant == "leaf-pathlen-without-ca":
                    for extension in parsed["tbs_certificate"]["extensions"]:
                        if extension["extn_id"].native == "basic_constraints":
                            extension["extn_value"] = asn_x509.BasicConstraints({"ca": False, "path_len_constraint": 0})
                if variant != "outer-ecdsa-null-parameters":
                    parsed["signature_value"] = inter_key.sign(parsed["tbs_certificate"].dump(force=True), ec.ECDSA(hashes.SHA256()))
                raw = parsed.dump()
            item[field] = base64.b64encode(raw).decode()
            if field == "root": item["rootPin"] = hashlib.sha256(raw).hexdigest() # Explicit trusted synthetic root; verify self-signature too.
        cases.append(item)
    output = {"scope": "PUBLIC_SYNTHETIC_CERTIFICATES_ONLY_NOT_APPLE_ATTESTATIONS", "cases": cases}
    Path(sys.argv[1]).write_text(json.dumps(output, indent=2) + "\n")
    print("Generated", len(cases), "public synthetic path cases; no private keys exported")


if __name__ == "__main__":
    main()
