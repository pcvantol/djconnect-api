# Pre-QR replacement reference qualification, not receiver adoption

Profile **0.4.0-draft**, wire **djc-rendezvous/1 NOT_FROZEN**; proposed recovery
policy **djc-pre-qr-replacement/1-draft**, **PROPOSED_NOT_RELEASED**.
Fresh admission API90/6269455602, existing sole API writer/PR96. Main advanced via
protected Dependabot95 to a4322fe; preserved by normal merge faf6b64 with no
history rewrite. Actual installed locked tools now include pool0.23.0 and
Wrangler4.151.0. No additional dependency selection, forced audit fix or tool
migration. Existing main dependency audit remains4high package entries through
sharp1241331/advisory dependency propagation; this package does not resolve or
claim production-security clearance of that existing issue.

## Exact new contract proposal

[Proposal](CREATE_RECOVERY_PROPOSAL_V1.md) permits ONE replacement only in a retained
foreground controller before ANY QR exposure/accepted201. On unknown transport
outcome or201-body transport loss, fence old attempt first, best-effort abort/drop
caller references, then use independent fresh nonextractable RSA authority,
32byte claim and incremented generation. At most2createPOST starts,5000ms keyprep,
10000ms per sent attempt,30000ms interaction; local bounds never infer server
expiry. Known non201 (including429/503) becomes terminal at observed headers,
even at/after local deadline; incomplete body cannot convert denial into retry.
Complete malformed/context-invalid201 also stops. Exposure is sticky BEFORE
renderer/accessibility/share callbacks. Hidden/unload/context loss stops; no
reload or postQR/lostconsume/uncertaincancel exception, no automatic retry loop.

The old unknown transaction may still commit much later and remains live until
its own original server120s expiry. It is NOT cancelled, renewed or idempotently
reused. New authority cannot consume its destination; old response cannot become
current. No new endpoint/schema, deterministic ID, recovery lookup, cryptographic
protocol, owner-authentication or HA display/session grant is added. Both creates
spend normal admission/allocation quotas; one attempt may still429/503.

## Actual source and execution

New **API-owned reference**, `pre-qr-replacement-reference.ts`, is a synchronous
policy/state machine with identity/epoch/phase/clock guards, not receiver SDK or
product code. It contains no network fetch, event listener, actual key generation,
rendering, timer, storage or key disposal implementation. Caller owns actual fresh
WebCrypto authority, each asynchronous guard and reference disposal; reference
compares key/claim fingerprints only. It cannot prove entropy, garbage collection,
secure erasure, browser scheduling, foreground event delivery or real receiver UX.
These are explicit adoption obligations, not hidden successful implementation.

[Final b full evidence](workerd-create-recovery-observations-v1.json):
**1184/1184 actual local workerd checks + isolated strict TypeScript + exit0 PASS**,
65source/input pins matching current bytes.1118 existing private-worker/capacity
cases remain passing, plus60reference race/boundary cases and6actual composed
HTTP/SQLite recovery scenarios. The existing1118 baseline was independently
executed again on current main tools before the new package; neither run relabels
historical pool0.22 evidence. All54handoff targets still pass:126fixtureTV flows
consumed/0expired, not a released capacity/SLA guarantee.

| New Worker scenario | Actual finite result |
| --- | --- |
| Committed201 lost; old reply before current QR |2allocations, only currentQR exposed; current JOSE delivery1,old0 |
| Committed201 lost; old reply after current QR |Same, separate RSA/claim/context; old-key decryption fails |
|201headers/body lost, replacement reply also lost |2allocations,0QR/0handoff,no thirdPOST |
| Original request reaches server only20s later |Original expiry140s/current130s from start, demonstrating no guessed expiry |
| Four initial screens plus four replacements |8POST starts,5allocations,1replacement201,3replacement429,no third attempts |
| Controlled admission dependency503 via actual HTTP |1POST,0allocations,headers terminal,no replacement |

The sixth case injects a private dependency503; it is NOT actual DO busy/provider
outage/load proof. Old-row410 demonstrates logical expiry, not alarm execution,
physical deletion or cancellation. Existing alarm/component tests remain separate.
Integration deliberately retains old keys only as negative fixtures to prove
claim/key/context rejection, not as a proposed receiver retention behavior.
Real software P256 assertions and standard JOSE deliver/decrypt the current
transaction; genuine supported-iOS/HA/TV input remains empty. No actual browser
lost-network/key-GC/presentation or receiver code is qualified by these tests.

The runner requires EXACT66capacity +6recovery observations, each uniquely bound
to a passed JSON test receipt/taskID/name, with no partial/duplicate allowance.
[Compact source proof](workerd-create-recovery-source-proof-v1.json) derives all
1184cases/65pins/72hashed observation receipts and the full-proof SHA256 from final
b. It is not another execution. Each observation hash uses UTF8 Python
`json.dumps(observation, sort_keys=True, separators=(",", ":"))` without trailing
newline. Existing offline1MiBJSON/2MiBblob guards can use the compact proof;
full3.14MB observations are independently reviewed immutable evidence, not read
or reparsed by that preparation validator.

## Independent review and corrections

Security and UX/privacy reviewed the exact proposal before reference source.
Security first found an ambiguity allowing429/503 with incomplete bodies to
appear retryable; explicit known-status priority corrected before source.
Both reviewers then independently found the concrete source ordering bug:
headers checked attempt deadline before known denial, leaving a10s+429/503
eligible for a following timeout. Source now validates current phase/attempt,
then retires ANY non201 before clock/deadline checks; only201 enters the live
body path. Twelve added429/503cases cover exact10s,10.001s,15s,30s,nonfinite and
backward clock, followed by both timeout and stream failure: no replacement.

Run a1172PASS missed that race and is superseded, NOT accepted final coverage.
Final b1184PASS includes the fix/newtests without weaker predicates. Review also
corrected the dependency503/physical-expiry evidence wording. Source/test reviews
now have no remaining P1/P2 in this bounded reference scope; final evidence/doc
review receipts are bound separately on API90/PR96. Neither reviewer ran the full
suite/provider/native/receiver acceptance; independently recomputed hashes/counts
must be distinguished from executor's actual run.

Existing API40/40,root types,107schemas/two clientData bytes and projectionPASS.
The prior preparation remains consistent only with its older98e7550/62source
scope, because APIserver runtime is unchanged; no false rejection is claimed.
A distinct post-source rebind will select current65source/1184case compact proof,
keeping22OPEN/null/false and all offline Git/size/control-flow guards. Exact-head
protected CI/remote blob/readback receipts belong on API90/PR96, not inferred here.

## Required receiver decision before freeze

**REFERENCE_QUALIFIED_NEW_RECEIVER_EXCEPTION_ACK_REQUIRED**. API supplies this
exact proposal/proof; the existing receiver owner must review/ACK only this NEW
preQR exception and its actual async/exposure/adoption feasibility. Existing
receiver reviews/crypto/capture/crossruns stay received. No unchanged rerun or
new source writer is requested. Until that ACK and exact joint release, the
current rotation restrictions remain; this proposal alone enables no consumer.

Core/Apple wire/paired-host/HA-route/separate B-admission semantics are unchanged;
notify producer delta without source pickup outside their existing lane. Genuine
same-key finite native recovery, publicedge/WAF/provider/error taxonomy/load/cost/
retention/logging/productartifact, actual HA/iPhone/physicalTV and explicit deploy
authorization remain separate open gates. Timer off; no public router/rootbinding/
D1/APNs/pairing change, merge, Finalization, Cloudflare write or live readiness.

```sh
node qualification/rendezvous/run_create_recovery_workerd.mjs /private/tmp/pinned-pki-deps /private/tmp/fresh-create-output /private/tmp/pinned-jose-package
```

Isolated output0700/files0600, Worker network egress and telemetry disabled.
