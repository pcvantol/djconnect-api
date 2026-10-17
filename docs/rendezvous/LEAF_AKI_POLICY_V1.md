# Reviewed Apple leaf-AKI policy v1

Same API94 writer, existing0.4.0-draft wire design; no endpoint/schema change.
**Policy review GO; strict OpenSSL probe measured; Worker/runtime pending.**

## Exact rule

The genuine Apple leaves omit Authority Key Identifier (AKI), producing strict
OpenSSL error85. AKI helps select the issuer/key; certificate signatures and the
path to a trusted root establish trust. We do not edit the Apple certificate or
disable strict validation. [Earlier findings](GENUINE_APP_ATTEST_QUALIFICATION_V1.md)
remain historical evidence.

[Reference code](../../scripts/qualify_leaf_aki.c) keeps X509_STRICT and root
self-signature verification active. It loads only the official Apple App Attest
root, DER SHA256 `1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932`.
No system trust, supplied alternative root, AIA or OCSP network lookup.

Only one error may be continued, once per verification:

- Exactly error85, missing Authority Key Identifier.
- Depth0, current certificate equals the exact target leaf.
- AKI extension actually absent; a present malformed/mismatched AKI is not ignored.
- Leaf: critical Basic Constraints CA=false; critical Key Usage digitalSignature
  true/keyCertSign false; exactly one noncritical EKU `1.2.840.113635.100.4.24`;
  EC P-256/prime256v1,256bits; exactly one noncritical nonce OID
  `1.2.840.113635.100.8.2`. Missing/duplicate typed BC/KU/EKU fails the guard.

Every other validation error is fatal. No exception for intermediate/root.
State is zero-initialized and private to each X509_STORE_CTX, not shared globally.
After verification, built chain must exactly equal target leaf -> supplied
intermediate -> pinned root; depth permits one intermediate. Library purpose ANY
is paired with the explicit custom App Attest EKU guard, not an arbitrary purpose.
Critical-extension checking, signatures, time and constraints remain enabled.

This probe checks **only certificate path policy**. Nonce value, saved challenge,
app/key binding, assertions, receipts, deadlines and full protocol validation
remain required. It cannot enroll a key, transfer a route or grant HA ownership,
screen rights or a Session. Measured development app/version/platform scope is
unchanged; other shapes/distributions and Worker enforcement are not qualified.

## Executed tests and reproduction

Compiled with clang21/OpenSSL4.0.3, C11 and `-Wall -Wextra -Werror`.
[Runner](../../scripts/check_leaf_aki_policy.py) / [sanitized results](leaf-aki-observations-v1.json):
16 executed cases, eight for each of the two actual development keys.

| Case | Result |
| --- | --- |
| Original strict mode | Reject85, exception not used |
| Narrow leaf-AKI policy | Accept, exception used, final error0 |
| Damaged signature | Reject7 after exception already used |
| Wrong root | Reject at pin guard |
| Reversed leaf/intermediate | Reject at leaf guard |
| Wrong intermediate | Reject20 |
| Before validity | Reject9 after exception already used |
| After validity | Reject10 after exception already used |

This limited real-fixture matrix is not a full adversarial PKI corpus: all
intermediate-AKI, critical-extension, name/policy/path-length and signed alternate
layout combinations have not been separately exercised. Code returns failure
for every error except the exact guarded missing-leaf-AKI case.

Compile the probe against OpenSSL4 headers/libcrypto (tested Mac prefix
`/opt/homebrew/opt/openssl@4`). Run the Python runner with probe binary, public
anchor directory and existing private qualification directory in the isolated
cryptography50.0.2 environment. Inputs come from the authorized prior fixture
qualification; no new keys/capture. Optional C epoch is offline fault injection
only, never a server/client clock override. Later expired captures must fail;
never backdate production validation.

Public output: fixed labels/booleans/error codes/depth only. Raw certificates,
handles/receipts/proofs/private-evidence hashes stay private. Existing private
review/delete deadline2026-11-16 applies; no automatic cleanup or erasure claim.

## Review and next step

Independent supplied-guards/callback technical/security review returned **policy
GO**, noP1/P2. It subsequently assessed context-local state and the reported
16-case matrix, confirming this is no longer an unreviewed AKI design blocker.
Supplied-material UX/privacy/evidence review also GO. Reviewers did not inspect
Git/libraries/fixtures or execute code independently; receipts are in API90/PR94.

Next: maintained Worker-compatible stack with equivalent enforcement and full
negative PKI/CMS corpus/composed verifier review; finite initial-receipt production
policy; wire actions/DO lifecycle/recovery/revoke/races and consumer freeze.
No full-verifier, runtime, merge/Finalization or deployment approval follows.

Primary reference: [OpenSSL verification callback](https://docs.openssl.org/4.0/man3/X509_STORE_CTX_set_verify_cb/).
