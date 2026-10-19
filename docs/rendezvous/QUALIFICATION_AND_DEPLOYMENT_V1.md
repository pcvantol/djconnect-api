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

[Local enrollment evidence composition](WORKER_ENROLLMENT_EVIDENCE_QUALIFICATION_V1.md)
adds95/87 cases, declaration-consumer typing and core93/CMS83/API40 regressions.
Positive orchestration uses explicit stubs; default rawnonce32 and old diagnostic
paths remain distinct. Atomic registration/fresh genuine positive/runtime remain open.

[Local atomic registration](WORKER_REGISTRATION_QUALIFICATION_V1.md) now
adds141/137 workerd+isolated TypeScript cases, encrypted key/receipt plus nonce
consumption in one SQL transaction and actual private-facade RPC denial tests.
Initial positives use explicit software fixtures; fresh native enrollment,
controller/global admission/transaction DO and public runtime remain unqualified.

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

## Historical initial deployment sketch, superseded by exact preparation

The initial single-class sketch below is historical. The current five-component
[deployment preparation](DEPLOYMENT_PREPARATION_V1.md) and [cost model](COST_CAPACITY_MODEL_V1.md)
supersede its inventory and64-call approximation. Neither authorizes deployment.

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

## Isolated HTTP/allocation qualification continuation

[Ingress qualification](WORKER_INGRESS_QUALIFICATION_V1.md) records265 actual local
workerd cases and strict types for closed transport and a private atomic
allocation-budget candidate. Public dispatch, immutable allocator/unknown-ID
coverage, trusted edge identity and provider-wide cost containment remain open.
Its additional raw JSON syntax restrictions and numerical allocation policies
require joint review before contract freeze; unchanged schemas alone do not
prove those consumer promises. Default harness is disabled; no production
binding, migration, secret or deployment is introduced.

## Private transaction index continuation

[Allocation/index qualification](WORKER_INDEX_QUALIFICATION_V1.md) records436
actual local workerd cases+strict types, including existing322 transaction and46
budget cases. Unknown/expired transaction IDs fail before child stub access via
the private router. One original-window budget charge precedes immutable server
allocation. No automatic fresh QR/retry after an unknown create outcome. This
does not freeze public wire, qualify key namespaces or enable a public service.
The fixed index adds RPC/bottleneck costs absent from the earlier64-call volume
model; complete numerical operating costs and capacity remain unqualified.

## Private global key-RPC admission continuation

[Key routing qualification](WORKER_KEY_ROUTING_QUALIFICATION_V1.md) records490
actual local workerd cases+strict types and265 HTTP/budget regressions. The
proposed50,000/day global call gate precedes every selected key child access;
the500/day ceiling counts registration ATTEMPTS, including failed/identical
retries, not500 new installations. That capacity policy needs joint review
before freeze. No long-lived key journal or changed recovery/key lifetime was
implemented. Unknown-key challenges/coalescing remain; their child creation is
bounded by routed-call admission, not forbidden. Public coverage/edge costs,
operations, native and physical functional acceptance remain OPEN.


## Local HTTP-to-state composition continuation

[HTTP composition qualification](WORKER_HTTP_COMPOSITION_QUALIFICATION_V1.md) adds746 actual local workerd cases
with strict types, including37 new composed HTTP cases and709 unique regressions.
Eleven routes now join private state and budgeted key adapters in an isolated
factory; software initial enrollment plus real P256/JOSE one-time delivery is
proved locally. Default harness remains503. Profile0.4.0-draft remains NOT_FROZEN;
public edge/abuse/operations, genuine native and real HA/TV acceptance stay OPEN.
No product binding or deployment is enabled.


## Local pre-body request admission continuation

[Request admission qualification](WORKER_REQUEST_ADMISSION_QUALIFICATION_V1.md) records815 actual local workerd
cases+strict types,69 new cases and746 regressions. Exact recognized routes pass
finite minute-HMAC/global admission before Origin/method/body/backend work; malformed
requests and preflights count. Proposed120total/20native perIP/minute includes
polling/sharedNAT effects requiring joint review. New gate Retry-After is qualified;
existing routed-backend hint loss remains an explicit follow-up. Public edge,
provider/cost/native/HA/physical and contract freeze remain OPEN. No activation.


## Routed budget hint correction

[Routed backoff qualification](WORKER_RETRY_HINT_QUALIFICATION_V1.md) records853 actual local workerd
cases+strict types:38 new cases and815 regressions. Selected trusted429/503 budget
hints now survive key/transaction/composition into existing Retry-After; malformed
hints fail503, absent hints remain absent. This supersedes the preceding routed-
hint-loss limitation only for those qualified paths. Original expiry/retry budgets
and profile0.4.0-draft NOT_FROZEN remain unchanged. No public/timer/deploy activation.


## Offline operational preparation continuation

[Exact deployment preparation](DEPLOYMENT_PREPARATION_V1.md) pins supplying source49ecb95,
53 source digests, existing root config/workflow and five selected private classes.
The offline validator can only return BLOCKED_NOT_AUTHORIZED; all22 service/
operational gates stay OPEN, artifact/account/approval null.21 consistency/negative
tests PASS. The201-DO-call/65-HTTP-call source model replaces the old64-call sketch;
request-only price scenarios are not account/cost/load/spend qualification.
No runtime source/config, consumer, Cloudflare, timer or deployment change.


## Controlled unqualified-status correction

[Provider status qualification](WORKER_PROVIDER_UNAVAILABLE_QUALIFICATION_V1.md) records961 actual localworkerd
cases+strict types:21 new,87 existing verifier and853 prior regressions. Only the
exact controlled unqualified-status negative becomes existingattestation_unavailable503;
no key/receipt commit, original nonce/expiry/attempt budget retained. This is not
proof of an Apple outage or a complete provider/internal-error taxonomy. A separate
source-qualified deployment-preparation rebind preserves22OPEN/null/activationfalse.
No public, consumer, Cloudflare, timer or deployment activation.

Separate offline preparation rebind: supplying source `86c80faebfaf98da02ebc5b3e4f832da00021d33`,
new provider-unavailable961-case proof and56 source hashes. Previous49ec baseline
correctly rejected the changed runtime before this rebind. All22 gates remain OPEN,
activation false and account/approval/artifact/public entrypoint null. This is
preparation consistency only, not contract freeze, Finalization or deployment.

Full-protocol review continuation: [exact contract HOLD](CONTRACT_READINESS_V1.md)
and [local challenge/management qualification](WORKER_CHALLENGE_BUDGET_QUALIFICATION_V1.md).
Three source P2s corrected: atomic4issuance attempts per transaction,28/2/2
reserved proof-operation groups and controlled missing receipt-config503.
1002/1002 local workerd+strict types PASS; full
source/test/evidence reviews and exact-head CI receipts belong on API90/PR96.
Shared-NAT/poll/retry ACK and lost-create-without-ID/deadline recovery remain
concrete contract decisions. No new polling policy/consumerACK/native/live claim.

Separate preparation rebind now pins immutable supplying source083ddb2d16351b4f785e52a23aad675b0a2cf9ef,
its1002-case proof and58source hashes. Previous86c80fa baseline correctly rejected
changed bytes first.21offline checks retain22OPEN/null/false; no deployment
authorization, public activation or consumer contract release is inferred.

[Shared-NAT capacity decision](CAPACITY_QUALIFICATION_V1.md): receiver's
independent reviews6266032306 received; API owns the evidence/release decision.
1068localchecks pass (1002regressions+66individuallyboundcapacitycases), yet the
four-TV target is HOLD:54handoffcases/126TVflows yield80consumed/46expired.
Real localChromium/WebKitCORS traces are separate from fixed offered-script replay,
synthetic sustained schedules, native/edge/load/physical proof. Runtime58pins and
083ddb2supplying source remain unchanged; no opsrebind/threshold/hint/receiverchange.
API must qualify corrected admission/terminal headroom or an explicit narrower
target before exact contract release. No unchanged consumerACK/capture requested.


Current local admission correction: [partition qualification](ADMISSION_PARTITIONS_QUALIFICATION_V1.md). Policy/2 partitions IP attempts
256poll/16create/64native/16terminal; global hard limits unchanged with terminal
reserve.1118checks,54/54handofftargets,126/126consumed locally. Historical80/46
remains unchanged oldpolicy evidence. No live/native/load/SLA or contractfreeze
claim; API retains lost-create recovery and exact release, receiverreviewsreceived,
consumer sources clean and timer off. Offline preparation rebind is separate.


New pre-QR recovery proposal/reference: [qualification](CREATE_RECOVERY_QUALIFICATION_V1.md),
policy djc-pre-qr-replacement/1-draft, NOT_RELEASED.1184local checks/65pins and6new
Worker scenarios qualify the bounded reference only. No new endpoint/schema,
server runtime, guessed expiry, cancellation or idempotency claim. Known non201
headers terminate even at deadline; one fresh-authority replacement is proposed
only before anyQR exposure. Existing receiver owner must ACK this NEW exception
and adoption before freeze; prior reviews remain received, timer stays off.
