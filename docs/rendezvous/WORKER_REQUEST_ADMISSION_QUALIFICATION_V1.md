# Local pre-body request admission

Profile `0.4.0-draft`, wire `djc-rendezvous/1`, **NOT_FROZEN**. Continuation from
c3953a8 on existing sole-writer draft PR96; main e67f402 remains unchanged.
Fresh ACK: https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6261392310.
Independent security and UX design reviews preceded source. No product Worker,
root binding/configuration, dependency, D1/APNs/pairing or consumer source changed.
No Cloudflare write/deployment, device/key capture or timer activation occurred.

## Actual implementation and policy candidates

[Request admission](../../qualification/rendezvous/request-admission.ts) adds one
fixed private RequestAdmission DO, name `djc-rendezvous-requests/1`, local policy
`djc-request-admission-qualification/1`. The guarded factory selects this gate
before reading bodies or reaching allocation/key/transaction services. The existing
[ingress](../../qualification/rendezvous/http-ingress.ts) optional constructor hook
runs after exact service URL/eleven-route matching and before Origin, method,
content type, cookies, OPTIONS handling and payload parsing. Unknown paths/query
variants remain cheap invalid_request without identity resolution or a gate RPC.
The old ungated QA constructors remain explicitly separate, not public adapters.
Default harness HTTP remains503; missing policy/resolver fails503.

| Counted downstream admission | Candidate cap |
| --- | --- |
| Global per UTC day | 1,000,000 |
| Global per minute | 10,000 |
| Per minute-local IP pseudonym, all recognized route requests | 120 |
| Per minute-local IP pseudonym, native route requests | 20 |
| Live pseudonym buckets across retained minutes | 20,000 |

These are proposed availability/capacity choices, not Cloudflare quotas, approved
spend, SLA, throughput or joint consumer acceptance. Every recognized route,
including malformed bodies and failed Origin/method checks, counts if admitted.
OPTIONS uses total only, regardless of its route. The native classification uses
a fixed server table: inspect, both submit routes and all attestation routes.
Create/poll/consume/cancel use total only. Origin/header/callerflags cannot select
another category. Native here describes a route, not authenticated app identity.
A saturated native bucket still permits total-only routes within their own cap.
Existing 5 create/IP/minute,10,000 transaction/day,500 registration ATTEMPTS/day
and50,000 key-RPC/day budgets remain separate and unchanged.

All caps are checked before three counter increments, committed atomically in
SQLite. Denied new identities allocate no bucket/counters; no admitted work is
refunded after downstream refusal, outage or lost response. Day and minute come
from the server, never request fields. Wrong object ID, malformed closed input,
stale identity, policy or SQL/alarm failure fails closed. The earliest cleanup
alarm is acknowledged before writes; clock/policy/window are rechecked after
awaits. Overlapping calls on one busy engine may return503; cross-engine SQL
transactions still enforce the exact caps. No unbounded queue or retry is added.

The identity resolver is a trusted constructor callback, invoked once per request.
Its validated/copied existing HMAC identity is request-local and reused by create
and registration; those existing budget charges occur exactly once. No raw IP,
X-Forwarded-For, CF-Connecting-IP fallback, proof/body/destination or long-lived
key/transaction journal is accepted or stored by this layer. This does NOT prove
real Cloudflare IP provenance; public edge/worker-chaining/Pseudo-IPv4 settings
and trusted resolver integration remain open. Policy, backwards clock and the
original identity minute are checked again after gate and body awaits. A minute
crossing fails503 rather than silently deriving a fresh identity/window.

## Privacy, errors and consumer behavior

Storage contains only day/count/expiry, minute/count/expiry and IP-derived HMAC
key/minute/total/native/expiry. HMAC buckets are briefly linkable pseudonyms, not
anonymous records; operators holding the secret have additional correlation
capability. Bucket/minute expiry is original minute start+120s; day aggregates
expire at original UTC midnight. Subsequent requests do not extend these dates.
Cleanup works with admission disabled, removes expired rows and re-arms the
remaining earliest alarm. Faults throw for retry. Logical expiry/purge is tested;
provider physical deletion, backups and monitoring are not qualified.

Pre-body gate denials preserve the existing closed error shape, bounded
retry_after_ms1..60000 and HTTP Retry-After seconds. Hint validation is fail-closed.
Because admission precedes validation,429/503 can precede an otherwise403/400/415.
A wrong Origin never receives Access-Control-Allow-Origin. Responses remain
no-store/no-referrer with redacted errors and no body/proof logging.

A delay is advice, not a longer original120s transaction deadline, additional
poll retry budget, permission for busy loops, new QR, new key or re-attestation.
Genuine consumers must qualify shared-NAT users, total polling/OPTIONS load and
bounded fallback backoff before freeze. No new normal-flow user step is added.

[Receiver's independent bounded review](https://github.com/pcvantol/djconnect-api/pull/96#issuecomment-6261463500)
found no structural wire/UX blocker on c3953a8 and identified an existing,
nonblocking limitation: routed backend retry_after_ms can be dropped by the
key/transaction/composition error path. **That routed-backend backoff propagation
is still NOT qualified/fixed by this increment.** Only the new pre-body gate's
hint propagation is proved. Absent hints require bounded fallback within original
expiry; this is not evidence of a definitive invalid iPhone or provider failure.
Receiver's accepted schema/crypto crossruns need no unchanged repeat. Its production
adapter remains gated on API release; its timer remains stopped. Core1197 is
source-merged at c98cbf3e3114afb8b8212e18224a337b12af3e27, not a current draft blocker;
that alone does not prove installed/HA/physical or separate Finalization acceptance.

## Executed evidence and independent reviews

[Source-bound observations](workerd-request-admission-observations-v1.json):
**815/815 actual local workerd tests + isolated strict TypeScript + exit0 PASS**.
69 new request-admission cases plus746 prior regressions. A new complete guarded
HTTP positive uses software initial enrollment followed by real P256 assertions,
standard JOSE envelope encryption/decryption and one-time consume. Its ten HTTP
requests produce exactly ten total/five native gate increments, one allocation,
one registration attempt and four key calls: no double charge or redelivery.
Initial enrollment is explicitly software; this is not genuine iOS or live HA/TV.

All eleven routes are tested for pre-body refusal and malformed requests, along
with OPTIONS, errors, hint/CORS behavior, global/day/minute/IP/native/cardinality
caps, concurrent last slots, identity isolation/copying, no fallback IP headers,
clock/policy changes across gate/body awaits, first alarm/SQL faults, restart,
early/earliest alarms and disabled cleanup/repaired retry. Denied stalled bodies
are not pulled and poisoned downstream namespaces remain unreachable.

Run a passed807/807. After eight extra cases, run b FAILED:813 passed/2 failed.
One parallel test incorrectly required400 while the documented busy gate correctly
returned503; it now accepts that fail-closed response and retries the same request/
original identity after completion. The other exposed a pre-existing receipt-test
fixture using separate Date.now reads for its nominal120s window, occasionally
creating120001ms. The fixture now captures one clock value; runtime expiry checks
are unchanged. Run c815 passed. Independent security then found a test P2: throwing poisoned
namespaces alone could falsely satisfy an expected503 after an accidental backend
access. Every poison now counts accesses, with an explicit zero-call assertion
for body-await cases and an afterEach zero-call assertion for all poison probes.
Final d815 passes. Failed run history is preserved here.

Existing product API40/40, root types, offline projection and107 schema cases/two
clientData byte examples also pass. Independent source/security and actual-file
UX/privacy/evidence review receipts and exact-head CI are recorded on API90/PR96.
Review GO remains scoped to local source; neither review is native/runtime/deploy GO.

Reproduce with existing pinned cbor10.0.12/PKIJS3.4.1/ASN1js3.1.0/JOSE6.2.12:

```sh
node qualification/rendezvous/run_request_admission_workerd.mjs /private/tmp/pinned-pki-deps /private/tmp/new-request-admission-results /private/tmp/pinned-jose-package
```

The runner preserves pinned trust/dependency manifests and source/tool hashes,
adds one temporary SQLite class/binding to the ten prior local bindings, denies
fetch and telemetry, and writes output0700/files0600. Public sanitized observations
contain test names/versions/hashes, no proofs, real/user IPs, keys or destinations.
Fixed reserved synthetic addresses may appear in test labels.

## Operations and remaining owners

This fixed gate limits downstream work/live application rows; rejected gate RPCs
and Worker requests still incur provider work/cost. A global object is an explicit
bottleneck, not scalable throughput proof or DDoS/WAF protection. It adds RPC/SQL/
alarm costs to the earlier incomplete volume estimate. Actual provider/edge policy,
load tests, spend/plan approval, provider error taxonomy, all deployed bypass paths,
physical retention/backup cleanup monitoring and deployment manifests remain OPEN.

No root binding changed, so root type generation is unnecessary. Rollback of
this undeployed local increment is a reviewed source revert, not a Cloudflare
operation. A future deployed rollback must preserve compatible cleanup of the
three tables and their original deadlines. Product activation remains jointly
contract/security-gated and production deployment separately owner-authorized.

API owns public integration, edge/abuse/provider/operations qualification and
routed-backoff follow-up. Apple owns fresh supported signed-iOS action/genuine
composition proof; original capture/ACK is delivered. Core owns actual external
HA route and separate screen admission. Receiver owns its gated adapter; accepted
prior crossruns are delivered. Real HA/iPhone/TV acceptance remains separate.
Rendezvous never authenticates an HA owner, grants display/Session access or
centrally fetches/decrypts HA destinations or stores HA/Profile/Session credentials.
The assignment is OPEN; no source merge, Finalization or live-service claim.
