# App Attest reference audit — 2026-10-17

Assignment `DJC-API-VIBECAST-RENDEZVOUS-V1-20261016`, same API94 writer.
This is qualification research for the unfrozen0.3.0 profile. **Do not select
the unmodified reference for runtime.** No Worker, binding, product dependency,
Apple app, signing, account, HA or Cloudflare deployment was changed.

## Exact source and method

Inspected `uebelack/node-app-attest`1.0.1 at
`f16c4bb71b737466872bc8b8a7dfd215364eaa83`:

| File | Exact UTF8 source SHA256 |
| --- | --- |
| `src/verifyAssertion.js` | `919f9678106318e787eb61fca1c37d2f0b2bca9cfe081e4110caaf996bd9e01b` |
| `src/verifyAttestation.js` | `2b42c220e99673f791e03814bc24edd1bbc02b10217e2ee023be896fa34d6c73` |

The [offline investigation harness](../../scripts/audit_rendezvous_verifier.mjs)
imports an externally supplied exact assertion source, verifies its SHA256 and
requires `cbor==10.0.11` and `nofilter==3.1.0`. It generates temporary software P-256 keys in memory,
signs synthetic data using the reference's hash layering, then exercises that
reference. No private key, real assertion, certificate, QR or route is emitted.
The harness intentionally expects the observed unsafe acceptance/false rejection
where listed; its success is **not** a verifier security PASS or proof that this
hash layering interoperates with App Attest.

Reproduce in a separate directory outside the product checkout: retrieve the
exact source from the pinned links below; install `cbor@10.0.11` and `nofilter@3.1.0` there with
scripts disabled; run `node scripts/audit_rendezvous_verifier.mjs ABSOLUTE_DIR`.
The harness performs no network or installation. This run also isolated the
reference attestation dependencies `asn1js@3.0.7` and `pkijs@3.3.3`; attestation
execution was not performed. No repository package/lock file changed.

Executed with Node24.19.0 and26.12.0,15 observations identical on both. Encoding
uses the library's asynchronous encoder: its synchronous encoder produced a
truncated object in the local Node26 setup. This harness workaround does not
qualify the library under workerd or explain that runtime difference.
The [recorded observations](verifier-reference-observations-v1.json) contain
metadata and fixed outcomes only, with no software private keys or signed bodies.

## Observed assertion behavior

| Case | Reference observation | Assessment |
| --- | --- | --- |
| Fresh software signature, counter1, saved0 | Accept | Control only; not an Apple vector |
| Counter0 with saved0; equal; lower | Reject all3 | Expected monotonicity controls |
| Counter0 with missing or NaN saved counter | Accept both | Caller-state precondition is unchecked; fail closed before invoking any future verifier |
| Second complete CBOR object after assertion | Accept | Trailing object ignored by `decodeAllSync(...)[0]` |
| Duplicate authenticatorData map key | Accept | Decoder keeps one value; incompatible with closed parsing |
| Signed authenticator with flags `0x80` and trailing byte `0xff` | Accept | Extensions are not parsed or policy-checked |
| New unsigned counter0x80000000 after0x7fffffff | Reject | Signed int32 parser falsely rejects valid monotone uint32 |
| New unsigned counter0xffffffff after0xfffffffe | Reject | Same signedness problem |
| Changed clientData, app identity, signature or signed counter | Reject all4 | Integrity controls, not full protocol qualification |

These15 checks establish the listed behavior at the exact source and decoder
versions. Missing state is an integration hazard, not a demonstrated remote
exploit against a deployed DJConnect service. No rendezvous runtime exists.

## Attestation source findings and current Apple rules

Source inspection, **not executed certificate attack tests**, found:

- The source identifies an intermediate using a subject substring, searches the
  submitted pair rather than enforcing credential-first order, and verifies two
  signatures. It does not establish certificate validity periods, issuer/path
  constraints, basic constraints/key usage or unknown critical extensions using
  a complete path validator. Signature verification alone is insufficient.
- Its nonce parser walks fixed ASN.1 object indices without a strict complete
  DER/schema/duplicate-extension check. Credential length and counters use signed
  readers; whole authenticator structure and extension policy are not validated.
- Development acceptance is a boolean that also permits production; future
  enrollment must enforce one exact configured environment and signed app policy.
- The currently published Apple guide adds validation-category and bundle-version
  checks in authenticator extensions and separate macOS requirements. The reference
  does not inspect these. Apple must identify actual supported OS/distribution
  fixtures and version applicability; no silent accept-missing compatibility
  policy or Mac support is inferred. App ID prefix must come from signed producer
  evidence, not automatically from an APNs team ID.
- The guide also calls for independent receipt validation/storage. The candidate
  key table does not specify an Apple fraud receipt policy (its operation receipts
  are different). Resolve necessity, fields, verification, bounded retention and
  privacy explicitly before enrollment implementation; no receipt is collected
  here and no fraud-service request/APNs credential reuse is authorized.

## Disposition and next evidence

Unmodified reference remains **REJECTED_FOR_RUNTIME**. This does not require a new
owner decision on the accepted copied-QR risk. The existing wire/security gate
now has reproducible parser/counter findings instead of only source questions.

Next API-owned step is selecting a maintained full validation stack, strict
bounded CBOR/ASN.1 adapters, explicit app/environment/version/receipt policy and
reviewing the exact implementation before use. Do not patch cryptographic hash
layering or hand-convert signatures from these synthetic cases. Obtain Apple's
actual controlled development attestations/assertions and official validation
fixtures; compare an independent implementation, then test under workerd with
the intended compatibility date and full negative certificate/parser corpus.
The existing Apple writer owns native support, key cadence and genuine fixture
production. Consumer acknowledgement, contractfreeze, DO race/crash/cleanup,
normal protected delivery, separate Finalization and authorized deployment remain
separate gates.

Two independent supplied-material reviews returned technical/security/evidence
GO and UX/privacy/evidence GO, with noP1/P2 in that scope. The technical reviewer
requested explicit hexadecimal spelling for the extension case, incorporated
above. They reviewed supplied descriptions/excerpts, not Git files, dependency
source, official documentation or harness execution independently. This is no
verifier/runtime/release approval or legal certification. Exact candidate receipts
belong in API94/API90 after the source commit is known.

Primary sources, retrieved2026-10-17:

- [Pinned assertion source](https://github.com/uebelack/node-app-attest/blob/f16c4bb71b737466872bc8b8a7dfd215364eaa83/src/verifyAssertion.js)
- [Pinned attestation source](https://github.com/uebelack/node-app-attest/blob/f16c4bb71b737466872bc8b8a7dfd215364eaa83/src/verifyAttestation.js)
- [Apple server validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- [Apple validation fixtures guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)
