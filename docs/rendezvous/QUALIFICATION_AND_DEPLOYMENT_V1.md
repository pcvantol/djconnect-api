# Rendezvous qualification and deployment preparation

Status: preparation only; see [contract review](CONTRACT_REVIEW_V1.md).
No runtime, public wire-vector package, production binding or release is delivered yet.

Revision0.3 adds [KEY-STATE](KEY_STATE_V1.md), [wire/profile](WIRE_PROFILE_V1.md),
machine request/response/clientData schemas and explicitly nonfunctional
synthetic schema fixtures. The original limited-A owner choice is resolved;
do not repeat it as a blocker. Exact policy/profile remains a technical review
candidate, including its finite retention and bounded key-revocation window.

Reproduce structural validation with Python plus `jsonschema==4.25.1` in an
isolated environment: `python scripts/validate_rendezvous_contract.py`.
No runtime dependency or workflow was changed for this optional design check.
This checks schema/byte examples only; it is not an Apple/JWE/DO test.

Revision0.4 adds [bounded enrollment recovery](ENROLLMENT_RECOVERY_V1.md), an
action-separated recovery proof and structural cases/bytes. Apple-reported
Mac/Chromium results are not API-reexecuted or promoted to iPhone/TV/service
acceptance. Recovery race/crash/cooldown rows await an actual implementation.

The separate [reference audit](VERIFIER_REFERENCE_AUDIT_V1.md) records15 actual
software-signed synthetic observations on two Node runtimes. It demonstrates
specific flaws in an unapproved reference; it is not a new-service acceptance
matrix PASS, actual Apple proof or a qualified replacement verifier.

[Genuine app-bound qualification](GENUINE_APP_ATTEST_QUALIFICATION_V1.md) now
records independently executed private development-fixture checks:141 offline
observations and12 negative parser controls. The missing-fixture input is
delivered; [narrow leaf-AKI policy](LEAF_AKI_POLICY_V1.md) now has policy GO and
16 executed strict OpenSSL cases. [Closed workerd path candidate](WORKER_PATH_QUALIFICATION_V1.md)
now adds72 actual private-fixture /56 public-only local tests and scoped review GO.
Full composed Worker verifier/receipt policy and DO/action/HA-chain qualification
remain open. [Core qualification](WORKER_CORE_QUALIFICATION_V1.md) now adds93/44
actual workerd crypto/parser cases and a corrected DER regression; receipt remains
UNVERIFIED in that adapter. [Receipt storage proposal](INITIAL_RECEIPT_POLICY_V1.md)
has scoped review GO. [CMS workerd qualification](WORKER_RECEIPT_QUALIFICATION_V1.md)
now adds83/44 diagnostic signature/path/field cases; actual revocation/status,
complete-verifier review remain open. [Local receipt storage](WORKER_STORAGE_QUALIFICATION_V1.md)
now adds39 actual SQLite DO cases+isolated types with a confirmed precommit
cleanup alarm; scoped storage GO. [Status policy candidate](REVOCATION_POLICY_CANDIDATE_V1.md)
has scoped design GO; [local common certificate status](WORKER_STATUS_QUALIFICATION_V1.md)
adds68/34 actual OCSP/CRL/cache cases with corrected scoped component GO.
[Fixed egress qualification](WORKER_STATUS_EGRESS_QUALIFICATION_V1.md) adds101/35
local cases after a concurrencyP2 correction; production egress/cache/provider cleanup/propagation and
full verifier/action composition still require qualification. Archived receipts fail
freshness. The runtime acceptance matrix below remains NOT_RUN.
[Public-input software JWE generator](JWE_VECTOR_GENERATOR_V1.md) now adds52
local Node/CLI tests and scoped reviews for the receiver's live-key crossrun.
[Receiver concrete producer crossrun](RECEIVER_GENERATOR_CROSSRUN_INTAKE_V1.md)
is now delivered for Chromium/WebKit with48 combined denials; API read receipt/
hashes, no independent reexecution. This is not signed-iOS or runtime acceptance.
[Local assertion coordinator](WORKER_ASSERTION_STATE_QUALIFICATION_V1.md) now
adds75/73 actual SQLiteDO cases+types, with trusted fixture enrollment and
diagnostic raw-input seeds kept distinct. No transactionDO, public admission or
full enrollment/crypto/status composition is qualified by that component.

## Local checkpoint — 2026-10-16

On the contract branch based on `3bb5f2b01401827e8a1072e1668fbb4a2223f26f`:
existing `npm test -- --run` passed **40/40**, `npx tsc --noEmit` passed,
offline projection validation with profile `djconnect-api` passed and
`git diff --check` passed. The first restricted test attempt could not open its
local Worker listener/log file; a permitted local-only rerun passed. These are
existing regression checks, not rendezvous tests, independent review or CI.
No bindings changed; types generation and new DO migration validation await
runtime implementation after contract review.

## Required acceptance matrix

All rows below are **NOT_RUN** for the new service. Expected results are test
requirements, not test results or executable cryptographic fixtures.

| Scenario | Required assertion |
| --- | --- |
| Successful scan | Paired selected host approval, exact context, one envelope, no HA grant |
| Expired QR / late submit | Original server deadline rejects at and beyond equality |
| Tampered QR / key / ciphertext | No ready state and no navigation |
| Concurrent two scans | Exactly one committed submission, no replacement |
| Concurrent double consume | Exactly one ciphertext response |
| Replay / old rotated generation | Denied without reviving state |
| Wrong browser / window | Claim or key mismatch denied |
| Wrong HA installation | App/HA selected-install mismatch denied; genuine different paired scanner classified separately without inventing TV-owner proof |
| App Attest | Real independent vectors for chain/app/env/nonce/assertion/counter; no unauthenticated fallback |
| App-key lifecycle | Privacy-qualified retention/deletion/recovery, cross-transaction counters and crash-safe authorization |
| Finite key-state profile | Absolute30-day expiry, finite tombstone, no reset/rolling retention,5s internal authorization window and crash recovery |
| Code-free UX | No A-only comparison, PAKE secret or extra TV input; only existing HA six digits |
| Wrong / missing / null Origin | Browser denied; native requires independent proof |
| Unsafe initial URL / IDNA | Apple and browser reject same raw-string corpus before normalization |
| Post-navigation redirects | Actual HA/proxy direct200/no-login configuration; acknowledge subsequent navigation is outside bootstrap control |
| Cancel versus submit/consume | Linearizable winner, no result after winning cancellation |
| Reconnect / suspended browser | Deadline unchanged; terminal state wins |
| Lost consume response | No second release, explicit fresh QR |
| Rate / payload / allocation budgets | Before expensive work, bounded across instances |
| Worker/DO outage | 503/unavailable, no fake QR success |
| Missing HA route | Apple explains remote-route requirement; no guessed address |
| HA unreachable from TV | Honest destination failure, no SSRF or HTTP fallback |
| Alarm delay / object restart | Request-time expiry and persisted state still enforced |
| Unknown ID / deleted state | No state recreation or token oracle |
| Privacy diagnostics | No secrets/destinations in success, rejection or exception logs |
| Existing API regression | APNs, proof/token, D1/operator suite remains green |

After TRUST-2 selection, commit real synthetic, deterministic interoperable
vectors generated by one implementation and verified by another browser/native
implementation: valid envelope, changed protected header/context, wrong key,
wrong signature/issuer/installation, ciphertext/tag/nonce mutation, expired and
replayed records. Record library versions, standards sections and vector hashes.
Do not substitute JSON state examples for crypto or real E2E qualification.

## Proposed deployment delta, not an executable manifest

| Item | Required reviewed delta |
| --- | --- |
| Worker | Existing `djconnect-api`, new isolated router, disabled by default |
| Binding | `RENDEZVOUS` to `VibeCastRendezvous` |
| DO migration | New SQLite class under a new immutable migration tag; confirm no existing namespace/class collision |
| D1/APNs | No schema, secret, registration or semantic migration |
| Config | Exact service/browser origin, protocol enable switch, global admission ceiling, reviewed rate settings |
| Secrets | Only new justified abuse/trust material after review; no HA/Profile/Session bearer |
| App Attest state | No implicit device-key registry; resolve key/counter privacy, lifecycle and atomicity before configuration |
| Artifact | Existing immutable API artifact must contain DO export/config/migration plus schema/vector digests |
| Dispatch | Exact SHA/artifact/hash and approved operational manifest through existing protected deployment route |

The existing deploy consumer is bound to the Platform 4.0 RC2 operational
manifest. A rendezvous candidate needs an explicitly reviewed applicable
manifest; the old manifest must not be assumed to authorize a new SHA or binding.
No rollout command is executable from this preparation document.

Before deployment: verify actual account/plan, namespace/class/migration state,
edge controls, secret presence without values, observability/retention and
current artifact. Run local isolated Worker/DO tests, types, D1 local migration,
dry-run bundle, regressions, secret scan, five-language review and required CI.
Preserve existing Owner Authorization/TDE/release controls.

Post-authorized-deployment smoke must use synthetic credentials: exact live
service version/source readback, real allowed/disallowed origins, fixed expiry,
two competing submits, one consume, replay rejection, cancel, payload/rate
denial and metadata-only logs. Verify APNs/operator health separately. Real
Apple scan -> selected HA navigation -> independent display admission needs
the existing consumers and separate actual-device acceptance.

## Rollback and cleanup requirements

Capture prior deployment/artifact/config/bindings and all namespace migration
state before deployment. First disable new creation; existing records expire
within their original deadline. No deletion of D1, APNs data or secrets.
Return to the previous reviewed Worker artifact only after verifying DO migration
compatibility; a Worker version rollback does not automatically undo namespace
migrations. Retain class/namespace as required to expire and clean up state.
Deleting a class/namespace is a separate reviewed irreversible operation.
Confirm old-generation denial, metadata/payload cleanup and existing API
regression health. Keep exact receipts even for failed deployment attempts.

## Capacity model and unresolved operating budget

Proposed 120-second lifetime and 2-second minimum poll interval imply at most
60 poll requests plus create/submit/consume/alarm, approximately 64 DO calls
per completed worst-case attempt. 10,000 such attempts/day imply about
640,000 DO calls/day, excluding edge denials and separate abuse coordination.
This is a request-volume model, not a load test or dollar estimate. Short-poll
handlers must avoid outstanding timers/I/O that keep objects resident.

The [current DO pricing page](https://developers.cloudflare.com/durable-objects/platform/pricing/)
separately bills requests, active duration and storage; Worker and abuse-control
costs also apply. The [DO limits page](https://developers.cloudflare.com/durable-objects/platform/limits/)
and [Worker limits](https://developers.cloudflare.com/workers/platform/limits/)
were read on 2026-10-16. Account plan, included/shared usage, measured duration,
write amplification, traffic estimate and acceptable spend remain unverified.
OPS-1 must produce a numerical budget and hard admission strategy before live
enablement. No claimed free-tier fit, production SLA or funding approval.
