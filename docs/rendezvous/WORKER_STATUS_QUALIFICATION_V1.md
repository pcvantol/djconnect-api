# Local workerd common receipt certificate status qualification v1

Same API94 writer; profile0.4.0-draft/wire djc-rendezvous/1 **NOT_FROZEN**.
**Scoped status component only: no complete verifier, enrollment or runtime GO.**

[Candidate](../../qualification/rendezvous/receipt-status-candidate.mjs),
[tests](../../qualification/rendezvous/receipt-status.check.mjs):
[68/68 local workerd cases PASS](workerd-status-observations-v1.json),
[34/34 public-only cases PASS](workerd-status-public-observations-v1.json).
These extend the separately qualified CMS and storage components; they do not
compose them into an admission decision. Product imports, dependencies, bindings,
routes, D1, secrets and deployment remain unchanged.

## Authenticated status and exact cache boundaries

Use pinned Apple RootG3, standard PKIJS3.4.1/ASN1js3.1.0 and WebCrypto.
Inputs are bounded to64KiB response/8KiB certificates, complete ASN1 consumption,
depth24/nodes4096; indefinite lengths are denied. This is a definite-length
closed status profile, not a claim of complete canonical DER/RFC5280 support.
Root pin/self-signature, current certificate validity, issuer signatures/names
and the measured receipt/intermediate purpose markers are checked. The preceding
closed CMS path/profile remains necessary; this is not its replacement.

OCSP requires successful basic response, one SingleResponse, SHA256 CertID,
ECDSA-SHA256/no parameters and1..3 embedded certificates. Unknown critical
response/single extensions fail. The maintained `BasicOCSPResponse.verify`
checks signature, ResponderID, trusted chain and responder authorization, with
explicit issuer certificates and **no trustedResponders bypass**. An issuer may
sign directly; a delegate needs OCSP-signing EKU, allowed digital-signature KU
and a certificate signed directly by the issuer whose name/key hashes match
the CertID. A chain to the same root alone is insufficient. Afterwards
`getCertificateStatus` must match the exact target serial/issuer hashes and GOOD.

Required signed times: thisUpdate<=now, producedAt<=now, nextUpdate mandatory,
nextUpdate>thisUpdate, now<nextUpdate, thisUpdate at most24h old. Embedded
certificate validity is also checked. Cache expiry is the minimum of nextUpdate,
thisUpdate+24h, checkedAt+1h and all relevant certificate expiries. CRL verifies
the exact root issuer/signature/AKI, only known noncritical CRL-level extensions,
**no entry extensions**, current signed window and target not listed. Its cache
deadline is at most1h/nextUpdate/certificate expiry. This checks the common
receipt intermediate, never the private attestation leaf or root's own status.

The private in-memory cache accepts only cryptographically verified fixed-root
responses. Its key hashes a JSON tuple of kind and separate exact certificate,
issuer and root hashes; concatenated-byte boundary aliases cannot collide by
construction. Inputs are copied, entries frozen, lookups copied. Reads never
renew checkedAt/deadline; equality at expiry or clock rollback denies. Signature,
unknown/revoked/stale/missing status denies insertion. This is **not** a deployed,
durable, bounded-capacity or distributed production cache. No outbound fetch is
implemented by this component; fixed egress/timeouts/response streaming limits,
operator policy propagation and outage integration remain required.

## Actual sources, synthetic controls and preserved failures

[Dated source observations](common-status-source-observations-v1.json) record
read-only POSTs to the two fixed advertised Apple common-certificate OCSP paths,
HTTP200 and successful GOOD responses. Both request CertIDs match. Signer signed
window:2026-10-17T20:40:15Z..2026-10-18T08:40:14Z; intermediate one second later.
Offline OpenSSL verifies both with only the pinned root, system CA path/store
disabled. Local workerd independently verifies the signed bodies. These samples
become stale at their signed deadline and never imply current status afterwards.
No private device leaf, receipt, challenge, user/HA payload, credentials or fraud
refresh is uploaded. The earlier CRL-only checkpoint retains its dated scope.

Public fake corpus has32 cases, with memory-only generated keys: authorized
delegate/issuer-direct/valid CRL positives; revoked/unknown/wrong target/hash,
missing/future/stale/equal signed times, missing EKU, wrong delegator, expired
certificates, critical extensions, duplicate response, missing/wrong responder,
tamper/framing/unsuccessful response; CRL revoked target, wrong AKI, unsupported
entry/CRL extensions and time/signature failures. The real-root wrapper rejects
fake roots. An independent Python implementation verifies the wrong-delegator
fixture's response/root signatures, EKU/KU and failure under the intended issuer.

Independent supplied-code review identified oneP2: unknown critical CRL-entry
extensions were ignored. The corrected closed profile rejects all entry
extensions. Regression fixtures have a valid root signature and an unrelated
serial, so rejection cannot be explained by target membership or bad signature.
Scoped follow-up status-component GO, no remaining supplied-scopeP1/P2. UX/privacy
scoped GO. Reviewers assessed supplied code/results, not their own source/library
inspection or execution; no complete security/runtime approval is inferred.

First combined59-case run:36PASS/23FAIL because the test read nonexistent
`accept` instead of corpus `valid`; corrected harness then59/59PASS. Subsequent
CRL review fix and expanded corpus yield68/34PASS. Earlier mixed ESM/CommonJS
library construction caused incompatible ASN1 class identities in a Node probe;
one dependency graph fixes that setup error. No verifier exploit is inferred
from either harness failure. All failed artifacts remain retained privately.

Actual-current eligibility tests use server Date.now and deny stale samples.
Other positive cache/fault controls use explicit fixed sample times; they are
never current enrollment or permission to backdate production. Software versions,
source/generator/corpus/root hashes bind the committed sanitized results.

## Reproduce and remaining gates

```sh
node qualification/rendezvous/run_status_workerd.mjs /private/tmp/isolated-pki-deps /private/tmp/new-status-results
```

Optional third argument is the already prepared private common-status directory
with signer/intermediate/root PEMs, status responses and dated observations. It
does not request a new device capture. Runner installs/deploys nothing, creates
new0700 output/own0600 files and keeps raw certificates/errors/results private.
Existing derived-evidence review/delete deadline2026-11-16 remains; no automatic
or physical erasure claim. Public output has fixed labels and public source/input
hashes only. Regenerate fake corpus with isolated cryptography50.0.2/asn1crypto1.5.1
using `build_synthetic_status.py OUTPUT_JSON`; keys are never exported and output
changes on regeneration.

Still required: reviewed fixed egress adapter/operational cache; complete original
challenge/AppAttest/CMS/status/policy/receipt-storage/action composition and replay
atomicity; actual provider cleanup/key operations; full independent review;
native wire/JWE/recovery/race vectors and consumer freeze; HA/iPhone/TV acceptance;
protected delivery, separate Finalization and authorized production deployment.
App Attest's explicit offline pinned policy and the issuer CRL's potentially
multi-month signed replay window remain exactly as documented in the
[policy candidate](REVOCATION_POLICY_CANDIDATE_V1.md). Hourly cache/refetch cannot
shorten that cryptographic staleness window. No owner/display/Session right follows.

Primary references: [RFC6960](https://www.rfc-editor.org/rfc/rfc6960.html),
[PKIJS OCSP API](https://pkijs.org/docs/api/classes/BasicOCSPResponse/),
[Apple certificate authority](https://www.apple.com/certificateauthority/).
