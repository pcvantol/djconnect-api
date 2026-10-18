# Local global key-RPC admission and routing

Profile `0.4.0-draft`, wire `djc-rendezvous/1`, continuation from70d80ad on the
same sole writer/draft PR96; main remains e67f402. **LOCAL KEY-RPC BUDGET /
NOT_FROZEN / NO_PUBLIC_OR_EDGE_GO.** No product handler/binding/configuration,
D1/APNs/pairing, dependency, consumer/device or Cloudflare mutation. Default
harness still returns503. A successful source review or merge cannot close this
function's public/runtime/native/configured-provider/physical acceptance gates.

[Key router and trusted submit adapter](../../qualification/rendezvous/key-routing.ts)
compose the existing private enrollment/assertion coordinator with the
[extended allocation budget](../../qualification/rendezvous/allocation-budget.ts).
The new global counter is not a per-key index and is not authentication.

## Design correction before source

The initial design proposed a routing journal retaining hashed key addresses for
30days+240s even after a failed enrollment. Independent security P2 identified a
squatting/availability flaw: knowing a keyID could reserve its admission, then
prevent legitimate same-key enrollment for most of that horizon. API also read
the existing [recovery contract](ENROLLMENT_RECOVERY_V1.md): management challenges
must be issued/coalesced for known **and unknown** keys. Membership rejection
would violate that promise. The journal and proposed enrollment deadline argument
were withdrawn before any source write; neither is implemented or authorized.
No long-lived failed-enrollment metadata category is introduced. API90 records
ACK6250658579 and corrected design6250686676. Independent security and UX/privacy
reviewed the replacement before code, with scoped local design-GO.

## Exact candidate application policies

| Counted work | Proposed ceiling | Where charged |
| --- | --- | --- |
| All routed key RPC | 50,000 per UTC day | Once before every child namespace ID/stub access |
| Registration attempts | 500 per UTC day | Additionally before each routed `enroll` |
| Transaction allocations | Existing10,000/day and5/IP/minute | Existing allocation/index path, unchanged |

Every issueEnrollment, enroll, issueAction and authorize call passes
`AllocationBudget.admitKeyCall()` exactly once. That private method accepts no
caller arguments/day/namespace. `enroll` additionally calls existing admission
with kind:key and a copied server-derived identity. **500 now explicitly bounds
registration attempts, including invalid proofs and identical registration
retries**, not500 distinct new installations or guaranteed successful enrollments.
Already charged work is never refunded after denial, timeout or a lost reply.
A registration can burn its global-call charge even if the attempt budget denies.

These values are unqualified application policy candidates, not Cloudflare/Apple
quotas, approved spend, burst/load capacity or complete abuse protection. The
stronger registration-attempt interpretation is a material capacity decision
requiring joint consumer/security/operations review before freeze. Budget exhaustion
preserves the pending key handle/recovery and original deadlines; it never
instructs new SDK key generation, re-attestation, pairing or automatic renewal.
Existing client retry counts and original-deadline eligibility still apply.

One fixed budget DO chooses its own UTC day, verifies object identity and policy,
confirms the earliest cleanup alarm before writes and atomically commits the
counter. It checks day/policy and backward-clock movement after alarm awaits.
No await occurs between the final checks and SQL increment. The router captures
the global charge day before the budget RPC and rechecks before child access;
registration also checks its identity minute after attempt admission. Late
cross-window results fail closed without refund. Existing transaction/key caps
and their SQL table remain unchanged.

The new table contains only day/count/next-UTC-midnight expiry. Cleanup covers it
alongside existing aggregates and IP buckets, preserves the earliest alarm and
runs with admission disabled. SQL/first-alarm failure cannot increment the count;
cleanup failure throws for retry. Logical expiry is authoritative; actual provider
retry scheduling, physical retention/backups and monitoring are not qualified.

## Trust and compatibility boundary

Constructor-only budget/namespace/enable choices are trusted server seams. Closed
bounded inputs, copied attestation bytes/identity/binding and canonical encodings
are checked before budget/namespace work. The key address still uses the exact
existing SHA256 compact UTF8 tuple of development/policy/canonical Apple keyID,
under the fixed private key prefix. No request can select an app policy, namespace,
method, verifier, counter or grant. The adapter copies the four exact ProofInput
fields and rejects extra operation/key selectors before calling the router.

Budget success grants only permission to invoke the existing child. All actual
App Attest/receipt verification, action-separated saved challenge bytes,
coalescing, monotone counters, active30day expiry, revocation, original enrollment
and authorization deadlines remain unchanged. No new child enrollment parameter
or per-key lifetime exists. Unknown-key management challenges keep the existing
shape/coalescing; an unknown key may instantiate its bounded temporary child
state after admission. **There is deliberately no zero-allocation-on-unknown-key
claim**. Routed calls and at most one child namespace get per call are bounded
by the daily aggregate; historical provider object retention is not thereby bounded.

The trusted submit authorizer adapter applies the same one-call gate before
child authorization. The transaction engine now preserves trusted negative
rate_limited/service_unavailable results as those fixed errors instead of
misreporting them as invalid_sender_proof. Other negative proof results still
fail sender authentication. No success predicate, lease, counter or state commit
was weakened. No central URL/decryption/HA owner/screen/session authority is added.

Existing ungated private QA adapters/bindings remain explicitly separate. Public
integration must select and audit these gated paths, without a second gate on
the same authorize call, and prove there is no bypass. This component does not
establish full service coverage, edge IP provenance, per-IP/challenge/invalid-proof
limits, WAF/request-cost containment or a public deployment.

## Executed evidence and independent review scope

[Final composed observations](workerd-key-routing-observations-v1.json):
**490/490 actual local workerd + strict TypeScript + process exit0 PASS**:
54 new key-routing/budget cases plus436 index/budget/transaction/framing/public
registration/assertion/storage regressions. Run `a`488/488 passed; executor then
found the trusted budget-error translation issue above and added two pending-row/
zero-key-namespace-access regressions. Final `b`490/490 binds current source hashes.
There were no failed runs in this increment; prior index harness failures remain
in their own historical evidence.

Coverage includes atomic49999->50000 concurrency, UTC rollover and backward clock,
policy changes across awaits, confirmed first/earliest alarm, SQL rollback,
restart, disabled cleanup/fault/repaired retry, no caller selectors, all four
operations charged exactly once, denied/malformed quota outcomes before namespace
access, registration attempts/retries, copied data, preserved unknown/known
management challenges/coalescing and same-key challenge issuance after expiry.

Actual P256 software assertions prove uncertain-registration recovery after the
original enrollment window without a new key, counter advancement, invalid-proof
denial, revocation and a budgeted submit authorization. A separate actual SQLite
transaction test uses the gated software assertion authorizer with a structural
JWE fixture, ready commit and one-time consume. It is not plaintext/context/native
or full HTTP acceptance. The unchanged existing dedicated software+JOSE encryption/
decryption flow also reruns in the436 regressions. Initial enrollment is explicitly
software evidence; no genuine native positive or new private diagnostic capture.

[HTTP/budget regression observations](workerd-key-routing-ingress-observations-v1.json):
**265/265 actual local workerd + strict types PASS** against the new budget source,
including107 unchanged canonical schema fixtures. Existing product40/40, root
types, projection and107 schema cases/two clientData byte examples PASS. Neither
local suite is misrepresented as an added CI job or real provider acceptance.

Independent source security and actual-file UX/privacy review, findings/corrections
and final exact-head CI receipts are registered on API90/PR96. Full supplied-source
review does not imply independent Git/hash/test execution. Both design and source
approvals are scoped and cannot establish public/native/security or deployment GO.

Reproduce with existing pinned dependency/JOSE directories and new output paths:

```sh
node qualification/rendezvous/run_key_routing_workerd.mjs /private/tmp/pinned-pki-deps /private/tmp/new-key-routing-results /private/tmp/pinned-jose-package
node qualification/rendezvous/run_ingress_workerd.mjs /private/tmp/new-key-routing-ingress-results
```

The composed runner preserves the existing cbor10.0.12/PKIJS3.4.1/ASN1js3.1.0,
Apple public roots and JOSE6.2.12 manifest checks; it records source/toolchain
hashes and runs sequential temporary local SQLite files/bindings with fetch and
telemetry disabled. No install, secret, private diagnostic or provider mutation.
Output0700/runner-owned files0600. Committed observations use fixed test names,
versions and hashes without keys, proofs, user IPs or destinations.

## Operations, rollout and open owners

No numerical money/SLA/plan fit or load result is qualified. Global budgets can
be exhausted by unauthenticated traffic; per-IP/edge controls and an operational
spend/cleanup policy remain essential API-owned work. Fixed budget coordination
adds RPC/bottleneck costs; the earlier64-call volume model is incomplete. Future
manifests need exact classes/private bindings/migrations, enable switches,
cleanup alerts, acceptable spend and complete bypass/coverage review. This
increment has no product binding, so root type regeneration is unnecessary.
Rollback is a reviewed source revert; no deployed namespace/provider operation
exists. A future rollback must preserve compatible cleanup of its extra table.

Public HTTP mapping/full gated composition and aggregate per-IP/challenge/invalid
attempt controls remain API-owned, plus complete operational deployment preparation.
Joint exact contract/security freeze is still required. Apple owns fresh supported
signed-iOS nonce/actions/genuine composed-positive proof; original capture/ACK
remain delivered. Receiver's exact-generator crossrun is delivered, no unchanged
repeat. Core owns real HA/proxy and separate screen admission; physical HA/iPhone/TV
acceptance remains separate. No lane or entire function is closed by this evidence.

References: [DO coordination](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/)
and [SQLite storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).
