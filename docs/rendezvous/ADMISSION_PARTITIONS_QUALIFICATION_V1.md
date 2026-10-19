# Partitioned admission: local target met; public contract still HOLD

Profile **0.4.0-draft**, wire **djc-rendezvous/1**, **NOT_FROZEN**. Existing sole
API writer/PR96, fresh ACK6267254902, parentac565d2. Exact source commit and
protected CI receipts are recorded on API90/PR96 after commit. Root Worker,
Wrangler/D1/APNs/pairing, dependencies, workflows and all consumer source unchanged.
No public route, deployment, timer, merge or Finalization is enabled.

## Correction and design review

[Reviewed exact design](ADMISSION_PARTITIONS_DESIGN_V1.md) changes only private
pre-body admission. Policy marker **djc-request-admission-qualification/2** rejects
old configuration. Recognized canonical route alone selects the class, including
OPTIONS and malformed/method/Origin attempts; no client-selected lane. Per-IP
per UTC minute: **poll256 / create16 / native64 / consume+cancel16**, total352.
Native-route OPTIONS now charges native as well. No borrowing of terminal slots.
Global hard ceilings stay10000/minute and1000000/day,20000IP rows; nonterminal
stops at9000/minute and900000/day, leaving bounded terminal headroom. Terminal
may use unused regular space but never bypasses the hard totals or its IP16.
All admitted attempts count, including invalid ones. Daily registration-attempt,
key-routing, create-allocation, challenge/operation quotas are unchanged.

Global/IP/partition checks and increments are synchronous SQL-atomic. Two added
bounded tables retain the same HMAC-minute identities and original expiries, no
raw IP/proofs/destinations. Stored counters are safe nonnegative integers and
aggregates must equal lane sums/native. Missing/orphan legacy IP partitions503
until originalexpiry, never a free new budget. Old global counts without terminal
rows conservatively count all as regular. Cleanup works with disabled policy and
keeps original earliest alarm; SQL fault rolls back all five tables. No added DO
RPC. Additional SQL/storage and higher per-IP attempt limits require new cost/load
qualification; prior partial costs are historical, not silently reused as current.

Independent security and UX/privacy reviewers both gave pre-source design GO.
Their invariants (stored-count consistency, original expiries and no execution
priority guarantee) were incorporated before implementation. Actual source/test
review also found no P1/P2; final evidence/report review is recorded separately
on API90/PR96. These reviews do not approve native/production/contract freeze.

## Executed evidence

[Complete new workerd proof](workerd-partition-capacity-observations-v1.json):
**1118/1118 local checks + isolated runtime strict TypeScript PASS**,62source/input
pins matching current bytes. A separately [compact source proof](workerd-partition-source-proof-v1.json) derives metadata, all1118testreceipts,62pins and66hashed observation receipts from that exact c proof; it binds the complete proof SHA256, not another execution. Each observation digest hashes UTF-8 bytes of Python `json.dumps(observation, sort_keys=True, separators=(",", ":"))`, with no trailing newline. It stays below the existing offline validator size limits without relaxing them. This is1002existing checks adjusted only where the
private policy contract/reset changed,66capacity cases with stronger target
assertions, plus50new partition cases. No duplicate-counting or new CI job claim.

| Handoff family | Scenarios | All-screen target met | Consumed | Expired |
| --- | ---: | ---: | ---: | ---: |
| Fixed measured offered-prefix,30s approval |24 |24 |56 |0 |
| Synthetic worst preflight,90/115s approval |24 |24 |56 |0 |
| Independent scanners / cold-key repair |6 |6 |14 |0 |
| Total |54 |54 |126 |0 |

ALL54 handoffcases now require target_met=true. Every successful TV requires
actual one-time consume plus standard JOSE decryption/context equality, with
nonextractable test RSA key and software P256 app assertions. Poll saturation
additionally leaves consume/cancel available in four ready-state cases, including
5000ms before originalexpiry; all return200 before expiry. Fifty new boundary
cases cover four exact quotas/no-change denial, all lanes' saturation,total352,
global regular reserve versus hardcaps, atomic global/IP final slots,11routes
with OPTIONS/invalidGET, corrupt counters/context, legacy/orphan buckets, new-table
rollback,restart/disabled cleanup,oldmarkerrefusal and actual overlapping busy503.

The prior [capacity report](CAPACITY_QUALIFICATION_V1.md), old66case source, actual
browser traces and80consumed/46expired proof remain unchanged historical evidence
of the old120/20policy. They are superseded only for the current local admission
candidate; their measured limitations remain relevant. Browser software was NOT
rerun. New Worker tests use the same fixed offered browser script plus separately
synthetic sustained schedules/controlledDate, NOT coupled stateful browser feedback
after denial, real tab-refresh authority recovery, actual browser-native integration,
wall latency, concurrent provider load or public edge/WAF behavior. Warm-key setup
costs are excluded from that family; preseeded500/50kday limits are boundary checks,
not daily live volume. Native keys are software fixtures, genuineinputs empty.

### Failure history and regressions

Run a stopped at types: SQL row interface lacked an index signature, corrected
to a structurally typed row alias. Run b1106passed/12failed: copied historical
capacity assertions still required the old failures although actual delivery was
now successful. The new suite was strengthened to require success in ALL54cases,
without changing offers/cadence/approval deadlines or runtime predicates.
Final run c1118PASS is the only accepted new proof. All66observations have unique
one-to-one passed test receipts; partial/duplicate/missing evidence is rejected.
Existing API40/40/root types/projection/schema/preparation checks are separately
recorded; old offline preparation first correctly rejects changed runtime bytes.
It must be rebound in a distinct post-source commit, retaining22OPEN/null/false
and the only success status BLOCKED_NOT_AUTHORIZED.

## Release boundaries and next ownership

**LOCAL_PARTITION_TARGET_MET_NOT_RELEASED**. The four-screen synthetic/local
handoff target is now met for this matrix; no released concurrency/SLA or whole
capacity acceptance follows. A same-IP attacker can exhaust terminal16; global
hard/terminal saturation and daily caps still deny. The actual overlap test
proves a simultaneous terminal request can receive busy503: quota reservation
reserves no executionqueue, CPU, provider or DO availability. Original120s TTL,
60poll ceiling and2000ms hint never extend. Existing finite retry/expiry behavior
still applies; no automatic newQR/key or new receiver workaround is selected.

Receiver reviews are RECEIVED and prior hint correction CLOSED. API owns exact
lost-create-withoutID/deadline recovery and joint contract release. Same-key serial
native/24h-recovery/day27/30 policy, genuine supported Apple/HA actions, physicalTV
and publicedge/provider/cost/retention/logging/artifact integration remain separate.
No unchanged capture/crossrun/ACK is requested or another lane writer started.
The normal UX remains TV QR -> app confirmation -> separate HA screen admission.
This service hands off destination A and never grants B/session/display rights.

## Reproduce

```sh
node qualification/rendezvous/run_partition_capacity_workerd.mjs /private/tmp/pinned-pki-deps /private/tmp/fresh-partition-output /private/tmp/pinned-jose-package
```

Output0700/files0600, Worker egress/telemetry disabled; pinned dependencies and
software vectors follow existing runners. Original measured trace is a fixed
input, not new browser evidence. Deployment remains separately authorized with
immutable source/artifact/bindings/rollback/smoke evidence. Cloudflare design and
limits reference: [DO rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/),
[DO limits](https://developers.cloudflare.com/durable-objects/platform/limits/).
