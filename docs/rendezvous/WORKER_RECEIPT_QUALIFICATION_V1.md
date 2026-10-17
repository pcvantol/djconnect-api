# Local workerd initial-receipt CMS qualification v1

Same API94 writer; profile0.4.0-draft/wire djc-rendezvous/1 NOT_FROZEN.
**Diagnostic CMS/signature/path/field evidence only. Revocation UNCHECKED;
no enrollment, complete-verifier, storage or runtime GO.**

The [isolated candidate](../../qualification/rendezvous/receipt-cms-candidate.mjs)
uses PKIJS3.4.1/ASN1js3.1.0 and standard WebCrypto. It implements the next bounded
step after [App Attest core](WORKER_CORE_QUALIFICATION_V1.md) and the reviewed
[finite receipt proposal](INITIAL_RECEIPT_POLICY_V1.md), without importing it
into product code or creating an endpoint, dependency, secret or binding.

## Exact receipt profile and separate validation stages

The real-root wrappers pin Apple Root CA G3 DER SHA256
`63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179`
and use Date.now internally. The public root was freshly retrieved from
[Apple's certificate authority](https://www.apple.com/certificateauthority/AppleRootCA-G3.cer)
on2026-10-17 and matched the committed DER exactly. No system trust, root chosen
by an API caller, remote payload fetch or caller clock is supported by those
wrappers. A separate synthetic test entrypoint admits fake roots/time only
inside this excluded qualification module; its scope string is no trust boundary.

ASN1 input is bounded to16KiB with depth24/nodes2048/content-length limits and
complete consumption. Actual Apple CMS uses seven indefinite BER containers,
including a chunked OCTET STRING. Only those measured outer container positions
may be indefinite; certificate/payload structures use definite minimal lengths.
Unknown fields, surplus structures, duplicate payload IDs and unsupported forms
fail closed. This is a closed measured profile, not general CMS/ASN.1 support.
The actual authenticated payload SETs are **not lexicographically DER-sorted**.
No global canonical-DER claim is made: signature verification uses the original
payload octets, while unique typed fields are interpreted by ID. No re-encoding
of receipt content substitutes for the bytes covered by its signature.

Supported SignedData: version1, one SHA256 digest, one issuer/serial signer,
three certificates, data content, ECDSA-SHA256 without parameters, no signed or
unsigned attributes/embedded revocation material. Such additions are denied
rather than partially interpreted. CMS certificate SET order is immaterial.
Signer selection must match uniquely; exactly one embedded pinned root and one
remaining intermediate build the exact signer/intermediate/root path.

All certificate signatures, current validity, role/BC/KU/path-length/key/algorithm,
SKI/AKI and closed critical/noncritical extension profiles are checked. The signer
requires measured noncritical purpose1.2.840.113635.100.12.15; the intermediate
requires1.2.840.113635.100.6.2.3, both exact DER NULL. Leaf/intermediate AKI is
mandatory and matched to issuer SKI. **No App Attest missing-leaf-AKI exception
is applied to CMS.** Root self-signature and exact built-chain bytes are checked.
Each verification gets its own CryptoEngine and state. After this explicit path
check, CMS signature verification must identify the same signer certificate.

This diagnostic path deliberately calls PKIJS with `passedWhenNotRevValues:true`
because no revocation inputs are supplied. Its result therefore says
`CMS_SIGNATURE_PATH_FIELDS_ONLY_REVOCATION_UNCHECKED_NO_ENROLLMENT`.
It is an explicit research exclusion, never a production soft-fail policy.
A positive result does not establish current certificate status, authority to
register a key, a live challenge or an atomic replay/counter decision.

Only after signature verification, parse eight unique version1 field records
(type/version/primitive OCTET STRING), exact IDs2/3/4/5/6/7/12/21. Check fixed
app ID2, exact previously attested certificate3, SHA256(saved clientData)4,
ATTEST6, sandbox7 and bounded opaque token5. Token is never extracted into logs,
indexes or public results. Creation12/expiry21 require exact UTC milliseconds,
valid calendar roundtrip and expiry after creation. Fresh evidence additionally
requires0<=age<=300000ms and now<receipt expiry. The original120s enrollment
challenge remains a separate, tighter necessary condition.

Actual receipts are archived and stale. `qualifyReceiptEvidence` exposes only
scoped metadata for research; `qualifyFreshReceiptEvidence` denies stale receipts.
Even fresh diagnostic metadata still says REVOCATION_UNCHECKED_NO_ENROLLMENT.
No key/receipt record is persisted or any HA/display/Session right granted.
Measured sandbox/iOS development receipt support is not production/macOS policy.

## Executed tests and preserved failure

[Private-fixture results](workerd-receipt-observations-v1.json): **83/83 PASS**;
[public-only results](workerd-receipt-public-observations-v1.json): **44/44 PASS**.
These are actual local workerd runs: pool0.22.0/Miniflare5.20260815.0-alpha/
workerd1.20260815.1, Node26.12.0, compatibility date2026-06-20/nodejs_compat.
Source, generator, public fake corpus and public root hashes bind the results.
Libraries/artifact provenance remains the prior path/core checkpoint, not a
new independent dependency audit or reproducible source build.

The43 [public synthetic cases](../../qualification/rendezvous/synthetic-receipts-v1.json)
use fake certs and memory-only keys: correctly signed wrong app/attested key/
client hash/type/environment/field versions/types/duplicates/unknown/missing,
invalid dates, expiry and exact5-minute boundaries; mandatory AKI/purpose/CA/
certificate time/critical extension failures; signed attributes/wrong digest/
extra certificates/signers/wrong signer ID, signature/content tamper and framing.
Fake trust is rejected by the fixed-real-root wrapper.

Both actual private Apple receipts validate signature/path/fields, deny current
fresh use and reject changed saved input/key/root/signature/signer/attributes/
certificate count/trailing/truncated/oversized data. BER-to-definite re-encoding
and certificate SET reordering preserve valid signed evidence. Offline fake-clock
controls accept capture creation+1s and exact5min; reject future creation and
300001ms. These are controlled-time tests, not current live enrollment or
permission to backdate production checks. Zero outbound fetch is verified.

First test run:82PASS/1FAIL because a synthetic wrong-signer-ID mutation was not
serialized by an ASN1crypto nested cache. Private inspection confirmed that test
fixture still contained the original matching signer ID. Generator now forces
serialization; an independent fixture check confirms serial1 matches no signer
certificate, and final83/44 reruns pass. Failed fixture-generation/test history
is retained privately, not relabeled successful or called a verifier exploit.
The earlier core DER failure remains separately recorded and corrected.

## Reproduction and independent review

Use external isolated PKIJS3.4.1/ASN1js3.1.0 dependencies plus existing repository
Worker test dependencies. The runner installs nothing and never deploys:

```sh
node qualification/rendezvous/run_receipt_workerd.mjs /private/tmp/isolated-pki-deps /private/tmp/new-receipt-results
```

Optional third argument is the already authorized decoded private Apple JSON
from [genuine qualification](GENUINE_APP_ATTEST_QUALIFICATION_V1.md). Public mode
omits genuine cases explicitly. Runner creates a new0700 evidence directory,
its own files0600, captures raw errors/results inside that directory and emits
fixed console labels. Device certs/receipts/clientData/handles/private hashes
remain private; public output contains only fixed labels, software versions and
public source/input hashes. Existing review/delete deadline2026-11-16 covers
private derived workdirs. No automatic/hardware erasure claim or new capture/key.

Regenerate fake fixtures with isolated cryptography50.0.2/asn1crypto1.5.1:
`python qualification/rendezvous/build_synthetic_receipts.py OUTPUT_JSON`.
Keys never leave process memory; regeneration produces different fake public
certificates. The committed corpus is the exact final tested input.

Independent supplied-guards/results technical/security review: scoped diagnostic
GO, noP1/P2 in supplied material. Review explicitly cautioned against general DER
equivalence; this document distinguishes Apple's authenticated unsorted payload
and measured BER from canonical DER. UX/privacy/evidence scoped GO. Reviewers
did not independently inspect files/libraries/fixtures or execute tests. Neither
review is complete CMS/PKI/revocation/composed-verifier/runtime acceptance.

Still required: exact reviewed revocation status source/freshness/cache/outage/
root policy, additional adversarial CMS/PKI coverage, receipt-key operations and
actual encrypted atomic storage/crash/deletion/cleanup, full composition with the
original challenge/key state and independent complete review. Then real action/
native JWE/DO/recovery/races and joint freeze/physical HA/iPhone/TV chain. Existing
receiver0.4 ACK and Apple diagnostic fixtures remain delivered. Protected product
delivery, separate Finalization and production deployment remain separate gates.
Production APNs/live push acceptance is unchanged by this receipt work.

Primary sources: [Apple receipt requirements](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk),
[PKIJS SignedData](https://pkijs.org/docs/api/classes/SignedData/),
[RFC5652 CMS](https://www.rfc-editor.org/rfc/rfc5652.html).

Current existing verification:40/40 Worker regressions,107 schema cases plus2
clientData byte examples, typecheck, offline projection, whitespace and80 local
links PASS. Secret scan102 unchanged baseline lines/no new matches. No bindings
or D1 changes; no type generation/migration needed. No user-facing translations
changed. Normal CI is separate from optional local/private CMS qualification.
