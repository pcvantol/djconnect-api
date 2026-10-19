# Rendezvous cost and capacity scenarios

Current source overlay: [a780 operations preparation](CURRENT_OPERATIONS_PREPARATION_V1.md).
It accounts for the current partitioned gate counter writes and preserves the
distinction between conditional components and actual account/bill approval.
The historical arithmetic and supplying source below remain historical.

**MODELED_ONLY / NOT_ACCOUNT_QUALIFIED / NOT_SPEND_AUTHORIZED.** Price/limit
references read2026-10-19; supplying source49ecb9512fe3b894e6dc420a682920dde9204a9c.
Current083ddb2 qualification replaces the challenge-context inspect with a quota
reservation: same RPC count, one additional SQL write per charged challenge
attempt. The historical partial request/gate-write model below does not include
that write or claim a complete bill. No price/provider readback is repeated here.
No provider billing/account-plan qualification, load measurement or deployment occurred.
Separate read-only existing-service/binding metadata does not qualify these prices
or assumptions.

## RPC accounting inferred from selected source

Each private stub method call is counted separately, including fixed admission
and index lookups. This is a source model, not measured provider billing/telemetry.

| Selected successful path | Worker HTTP calls | DO method calls |
| --- | ---: | ---: |
| Create | 1 | 5 (request gate, allocation index, allocation budget, transaction create, index lookup) |
| Inspect | 1 | 3 (request gate, index lookup, transaction inspect) |
| Submit challenge | 1 | 5 (request gate, index lookup, transaction inspect, key budget, key issue) |
| Submit | 1 | 5 (request gate, index lookup, transaction submit, key budget, key authorize) |
| Poll or consume or cancel | 1 | 3 (request gate, index lookup, transaction action) |
| Initial enrollment challenge | 1 | 3 (request gate, key budget, key issue) |
| Initial registration | 1 | 4 (request gate, key budget, registration-attempt budget, key enroll) |

A modelled success with60 polls plus create/inspect/submit-challenge/submit/consume
is65 HTTP calls and201 DO calls, excluding initial enrollment. First enrollment
adds2 HTTP/7 DO calls. Historical accepted submit retries avoid key authorization,
but still incur gate/index/transaction calls. The dedicated guarded10-request
functional test is consistent with a37-DO-call source decomposition; no new
instrumented RPC-count test or provider measurement is claimed here.

Thus the older approximate64-DO-call model is superseded for this selected graph.
No promise that every scheduling of60 polls and success fits the original120s
window: this is an upper traffic scenario, not deadline/capacity qualification.

## Request-overage component only, assumed Paid plan

[DO pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)
lists1m included monthly requests and$0.15 per additional million, with request-unit
rounding; alarms count. [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
lists10m monthly included requests plus$0.30/million. The calculations below assume
30days, those included pools wholly unused by other services, one successful
transaction attempt per counted flow, no re-enrollment and stable same-worker RPC
accounting. DO overage rounds up to whole millions as in the published example;
Worker overage is illustrative proportional arithmetic, not an invoice receipt.

| Successful flows/day | HTTP/month | DO calls/month | DO request overage USD | Worker request overage USD | Sum of these request components USD |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 195,000 | 603,000 | 0.00 | 0.00 | 0.00 |
| 1,000 | 1,950,000 | 6,030,000 | 0.90 | 0.00 | 0.90 |
| 10,000 | 19,500,000 | 60,300,000 | 9.00 | 2.85 | 11.85 |

Storage can exceed those request components: the selected RequestAdmission success
writes three SQL counter rows and calls setAlarm once per admitted HTTP request.
At10,000 daily65-request flows, that is a source-modeled78million monthly write
operations from this gate alone, before indexes/deletes/other classes. The cited DO
pricing lists50million included monthly SQLite writes plus$1/million, and bills
setAlarm as a row write. With the same unused-inclusion assumption this gate-only
write component would be about$28, subject to actual provider accounting. It is
not included in the request table or a complete storage estimate; read/index
scans, alarm retries and remaining objects need measurement too.

These numbers exclude plan base fees, Worker CPU, DO wall-clock active duration,
SQL row reads/writes/index amplification/deletes/alarms, stored data, provider
status calls, logs/export, taxes, shared account usage and every retry/OPTIONS/
invalid/denied or attack request. They are NOT total cost, a spending cap or a
recommendation that this plan is suitable. Actual usage could be far higher.

A denied request can still invoke Worker+request gate; arbitrary distributed
traffic is not bounded by admitted-work caps. A single busy gate can fail503.
Account-edge controls and explicit spend/incident policy are required before live
admission; the application cannot turn its source counters into a provider bill cap.

## Capacity and measurement gates

[DO limits](https://developers.cloudflare.com/durable-objects/platform/limits/)
describe a per-object soft request limit; this is not this application's throughput.
[Worker limits](https://developers.cloudflare.com/workers/platform/limits/) define
plan CPU/memory/request bounds, not a successful crypto latency target. The
10,000/minute global candidate is about167 allowed requests/s, but denied work and
bursts also hit the same object. Multiple global coordinators add separate queues.

Before approval, measure p50/p95/p99 HTTP and DO latency under allowed+denied mixes,
shared NAT/OPTIONS/poll behavior, Worker CPU, active DO GB-s, SQL rows read/written,
row/index size and alarm/cleanup behavior. Capture node/provider/tool versions and
exact source/artifact. Test distributed bursts, budget saturation, provider stalls,
concurrent software/genuine paths and outage recovery without fail-open behavior.
Use actual account quotas/plan/shared usage and measured retained data to produce
a full numerical budget, maximum acceptable spend and alerts/kill-switch policy.
Local853 tests or this arithmetic cannot close those measurement/approval gates.
