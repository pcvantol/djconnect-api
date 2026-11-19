# Local workerd certificate-path candidate qualification v1

Same API94 writer, profile `0.4.0-draft`, wire `djc-rendezvous/1` NOT_FROZEN.
**Scoped candidate path GO; not a complete App Attest verifier or runtime GO.**

The [candidate](../../qualification/rendezvous/worker-path-candidate.mjs) now
executes the reviewed [leaf-AKI rule](LEAF_AKI_POLICY_V1.md) under actual local
workerd using maintained PKIJS3.4.1/ASN1js3.1.0. This replaces the missing Worker
path feasibility evidence, not the remaining composed-verifier/security gates.
No import from product `src/`, public endpoint, product dependency, binding,
D1 migration, lockfile, workflow or deployment changed.

## Closed path profile

The production-shaped entrypoint accepts leaf/intermediate/root bytes only;
root must hash to the pinned official Apple App Attest anchor. It uses the real
server clock internally, no supplied trust/time, no system roots or network
lookup. All certificates are bounded to8192 bytes, fully parsed and required to
round-trip to the same DER before cryptography. Version3, positive minimal
serial, zero unused signature/public-key bits, matching supported inner/outer
ECDSA algorithms with absent parameters, closed extensions and duplicate-OID
rejection precede path validation. Only BC/KU may be critical.

Critical BC/KU require the appropriate CA roles/certSign; a non-CA leaf cannot
have pathLenConstraint. Applicable path lengths, issuer names, validity of all
three certificates and root self-signature are checked. Leaf additionally has
P256/uncompressed point imported through WebCrypto, digitalSignature without
certSign, exact App Attest EKU and one noncritical nonce extension. This path
step checks nonce presence only; its value/challenge/app/key binding belongs to
the still-open composed verifier. Unknown noncritical extensions also fail this
closed measured profile; this is intentionally not a general X.509 validator.

Root/intermediate SKIs and the intermediate AKI are required and matched; root
AKI, when present, must match itself. Only the reviewed leaf AKI may be absent;
a present malformed/mismatched AKI never falls back. Per-call CryptoEngine and
chain state, fixed trusted root, explicit root signature check and exact final
leaf/intermediate/root DER identity avoid shared mutable trust. Every validation
failure returns false. PKIJS path verification remains required after the guards.

This maps the selected policy to a different engine. It does **not** prove full
RFC5280/OpenSSL X509_STRICT equivalence. No CRL/OCSP input or fetch is used:
revocation is **NOT_QUALIFIED**, not an assertion of good revocation status.
The candidate exports a separate synthetic helper with caller-supplied fake
trust/time for testing only. Its scope string is no security boundary. Neither
that helper nor this qualification module may be imported into a product router.

## Executed evidence

[Private-fixture sanitized observations](workerd-path-observations-v1.json):
**72/72 PASS**, including55 public signed synthetic cases; two actual prior Apple
paths; damaged leaf/intermediate signatures, wrong order/issuer and time faults
on each real chain; zero outbound fetch; parallel valid/invalid trust isolation;
and rejection of a fake root by the fixed Apple entrypoint.

[Public-only observations](workerd-path-public-observations-v1.json): **56/56
PASS**,55 signed synthetic cases plus fixed-Apple-wrapper rejection of fake trust.
These are actual workerd executions, not a Node-only model. Both runs used
Node26.12.0, Vitest4.1.11, pool0.22.0, Miniflare5.20260815.0-alpha and
workerd1.20260815.1, compatibility_date2026-06-20/nodejs_compat. These are installed
binary versions, not inferred from newer manifest version ranges.

The [public synthetic corpus](../../qualification/rendezvous/synthetic-pki-v1.json)
contains fake certificates only. It covers role/KU/EKU/path length, mandatory
intermediate AKI/SKI, mismatched AKI, unknown/duplicate extensions, algorithm/key,
DER framing, serial/version, public-point and signature/timing failures.
Semantically invalid TBS variants are re-signed by the synthetic issuer so they
do not merely fail because a signature became stale. The review correction
`cA=false/pathLenConstraint=0` is explicitly included and denied.
This finite corpus does not claim all ASN.1/PKI adversarial combinations.

Earlier attempts are retained privately: two65-test runs passed their tests but
failed the runner's package-metadata resolution, hence were **not** successful
whole-pipeline runs. That resolver was corrected; later65/71-test checkpoints
and the final72-test rerun completed. No failed result was relabeled PASS.

## Libraries and reproduction

[Public provenance](../../qualification/rendezvous/dependency-provenance-v1.json)
records exact package versions, npm SHA512 integrities, installed dependency set
and lock hash. Downloaded npm archives matched all six installed archive files
for each direct library. This verifies npm artifact identity, **not** a
reproducible source build. Declared gitHead metadata is absent; no source/build
identity claim is inferred. Upstream [PKIJS3.4.1 release](https://github.com/PeculiarVentures/PKI.js/releases/tag/v3.4.1)
includes an OCSP responder-authorization fix; that does not qualify this
candidate's revocation handling. [ASN1js3.1.0](https://github.com/PeculiarVentures/ASN1.js/releases/tag/v3.1.0)
is the explicitly tested decoder version.

Use existing repository test dependencies and an isolated directory outside the
repository with `pkijs@3.4.1` and `asn1js@3.1.0`, installed with scripts disabled.
Compare its resolved versions/integrities to the provenance before qualification.
The runner installs nothing and does not contact Cloudflare. Public reproduction:

```sh
node qualification/rendezvous/run_workerd.mjs /private/tmp/isolated-pki-deps /private/tmp/new-path-results
```

Output directory must not already exist. Runner creates it mode0700; its own
generated files use mode0600 and child test/log outputs stay within that private
directory. It isolates local Worker config/logs, captures raw diagnostics and
only emits fixed console labels. Full test JSON/logs stay private. Optional third
argument is the already-authorized decoded private Apple JSON from the earlier
[genuine qualification](GENUINE_APP_ATTEST_QUALIFICATION_V1.md); no new capture
or App Attest key is needed. Two genuine paths are absent in public reproduction
and explicitly listed NOT_RUN. Expired private captures must fail rather than
backdating the Apple entrypoint. Fake clock is confined to explicit tests.

To regenerate the fake public corpus, use the isolated cryptography50.0.2 /
asn1crypto1.5.1 environment and
`python qualification/rendezvous/build_synthetic_pki.py OUTPUT_JSON`.
Synthetic signing keys are generated in memory and never exported. Regeneration
creates new public fake certificates; the committed corpus is the exact tested
input. Official public Apple root is committed and its DER pin rechecked.

## Privacy, independent review and remaining gates

Raw actual Apple certs, identifiers, handles, receipts, decoded proofs and their
hashes are not published. Derived private workdirs share the existing owner
review/delete deadline2026-11-16. No automated erasure or hardware-key deletion
is claimed. The public summaries contain fixed case labels/results, software
versions and public source hashes only; no private-evidence digests.

Independent supplied-source/guards technical/security review identified oneP2:
explicitly prohibit pathLenConstraint on the non-CA leaf, as required by
[RFC5280 section4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9).
Corrected guard and re-signed negative fixture passed; follow-up review returned
**scoped candidate path GO, no remaining P1/P2 in supplied material**.
Independent UX/privacy/evidence review returned scoped GO. Reviewers did not
inspect Git/library/fixture files or execute tests themselves. This is not a
complete verifier or independent runtime acceptance/security approval.

Still open: composed CBOR/nonce/key/app/assertion verifier and receipt CMS,
finite initial-receipt production/revocation policy, full negative corpus and
review, actual action-specific wire/native JWE, durable lifecycle/counter/recovery/
races, receiver agreement and consumer freeze, full HA/iPhone/TV chain. Original
copied-QR product choice stays resolved. Rendezvous grants no HA ownership,
screen admission or DJ Session rights. Protected product merge, separate
Finalization and separately authorized production deployment remain pending.

Existing API verification at this checkpoint:40/40 Worker regressions,107 schema
cases plus2 exact clientData byte examples, TypeScript check, offline projection,
diff whitespace and56 local documentation links PASS. Secret-pattern scan:
102 baseline lines unchanged byte-for-byte, no new matches. No bindings or D1
schema changed; type generation/migration exercise not required for this isolated
checkpoint. No user-facing translations changed; five-language product review
still belongs to the eventual release. Ordinary CI does not run the private or
optional public path harness automatically; local path evidence is separate.
