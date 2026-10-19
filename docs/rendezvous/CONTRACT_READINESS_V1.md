# Current decision: implementation release candidate; public activation HOLD

Assignment `DJC-API-VIBECAST-RENDEZVOUS-V1-20261016`, same sole API writer/PR96.
Historical source profile `0.4.0-draft`, wire `djc-rendezvous/1`. Current limited
[implementation release record](IMPLEMENTATION_CONTRACT_RELEASE_V1.md) is the
canonical status/precedence entry: candidate outside protected main, implementation
contract released only on protected main plus exact delivery receipt. Public
activation remains NOT_AUTHORIZED; no full production freeze/readiness claim. Fresh admission:
https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6265985814.

This is the current decision/index following full independent protocol/security
and UX/privacy review of source `b1dee1794fb1a75801bbeca87ab2d87122ff3ba2`, plus
separately reviewed local source corrections below. It is not a frozen contract,
public entrypoint, deployment authorization or live qualification. The exact
NEW receiver ACK6270491529/6270497278 is now RECEIVED; previous open-ACK status
text in historical proof documents is superseded by the release record.

## Precedence and delivered evidence

WIRE_PROFILE/KEY_STATE/ENROLLMENT_RECOVERY and the closed wire schemas define
candidate messages and lifetimes. This decision reconciles current numerical
limits and recovery wording; historical stage-by-stage claims in CONTRACT_REVIEW
and qualification documents do not retract subsequently delivered evidence.
The old single-DO sketch is superseded by the five selected private bindings in
[deployment preparation](DEPLOYMENT_PREPARATION_V1.md). The eleven test classes
are not a product migration. No public router/configuration is enabled.

Delivered evidence remains delivered: receiver generator/browser crossrun,
original Apple diagnostic capture/ACK, Core route/context source and earlier
component reviews. Do not request unchanged captures/crossruns or another writer.
Local composed source evidence includes standard JOSE envelopes, P256 assertions,
SQLite counter/receipt/lease, atomic destination winner/consume/cancel, immutable
allocation and pre-body admission. Software enrollment is not a genuine signed-iOS
positive. Full-function, native, installed, physical and deployment claims remain
separate from source proofs.

The accepted limited-A trust choice remains unchanged: genuine-app reported route
from the already paired app; the API cannot independently attest HA ownership or
that a photographed QR belongs to its scanner's intended TV. No extra TV code,
PAKE, account or OOB step. A is encrypted destination handoff; B is separate HA
screen/session admission. No HA/Profile/Session bearer or central HA fetch.

## Three source findings corrected without changing the wire schema

- Four submit-challenge issuance **ATTEMPTS per transaction** now have one
  transaction-owned persisted SQL counter shared across all key IDs/digests.
  Charge follows valid QR/generation/live-pending/original-expiry checks and
  precedes key RPC admission. A downstream denial/outage/lost reply still costs
  an attempt; identical challenge HTTP retry is a new issuance attempt. No refund,
  renewed expiry or winner reservation. Fifth attempt429, no key RPC; inspect is
  read-only. This replaces context-inspect with reservation, adding no DO RPC.
- The per-key32 live proof_operations bound (plus one separate enrollment_operation)
  is partitioned: maximum28submit,2recover-key,
  2delete-key; challenges and immutable receipts count. Existing same-action
  pending-management coalescing runs before quota. Submit pressure cannot crowd
  out management; one old recover receipt can coexist with a fresh challenge.
  No premature erasure, counter reset, new key or weaker assertion is introduced.
- Missing/malformed active receipt-encryption configuration now gives a controlled
  service_unavailable503 before enrollment nonce/proof work. Original context/expiry
  guards precede late-result classification; the install uses one stable key snapshot
  and checks configuration/continuity synchronously before writes. Bad proof with
  healthy configuration still401. No after-commit guard pretends an unknown committed
  outcome was rolled back; repair retains one original key/expiry. This does not
  qualify all provider/internal failures or public configuration admission.
- The daily500 bound means registration **ATTEMPTS**, including identical/failed
  retries; never a promise of500 newly enrolled installations. Reload/401 does not
  authorize fresh creation: confirmed cancellation, authenticated terminal state
  or known original expiry must permit rotation first.

Exact implementation/tests and failure history:
[challenge/management qualification](WORKER_CHALLENGE_BUDGET_QUALIFICATION_V1.md).
These fixes do not silently select a new poll hint or expand candidate caps.

## Capacity review received; API release decision remains HOLD

[Receiver6266032306](https://github.com/pcvantol/djconnect-api/pull/96#issuecomment-6266032306)
delivers the two independent numerical-policy reviews and concrete qualification
questions. This is RECEIVED review, not a generic unreturned receiver ACK. The
old retry-hint defect is CLOSED. Historical [capacity evidence](CAPACITY_QUALIFICATION_V1.md)
records the old120/20policy failing (80consumed/46expired). The independently
designed [partition correction](ADMISSION_PARTITIONS_QUALIFICATION_V1.md) now uses
poll256/create16/native64/terminal16 perIP/minute, global9000regular/10000total
minute and900000regular/1000000total day. Exact private policy /2; route-only
classification counts all methods, including nativeOPTIONS.352total max/IP.

New local1118checks pass: all54handoff scenarios meet their target,126fixtureTVs
consumed/0expired; late poll-saturated consume/cancel200 before originalexpiry.
This closes the demonstrated quota-starvation cases in this local matrix, not
released concurrency/SLA, executionpriority, actual native/browserfeedback,
provider/public edge/load/cost or joint release. Busy503 can still block simultaneous
terminal work; arbitrary sameIP terminal abuse can exhaust its16attempts.
Original2000ms hint/120sTTL and finite key/retry semantics are unchanged.
API owns exact protected implementation release; lost-create exception review is received,
no unchanged capture/crossrun or generic ACK is requested. Timer stays off.

## Current implementation release decisions and separate acceptance

| ID | Exact open decision/evidence | Owner/action |
| --- | --- | --- |
| CREATE-RECOVERY | Exactff9ff57proposal/reference and policy received both receiver independent ACKs [6270491529](https://github.com/pcvantol/djconnect-api/pull/96#issuecomment-6270491529)/6270497278. Proposal bytes unchanged. | CLOSED as a review request. Select only via exact protected implementation release; real receiver async/foreground/exposure/online/BFCache adoption remains required before activation. No repeatedACK. |
| POLL-NAT | Privatepolicy/2 and local54/54targets/126consumes qualify disclosed matrix; limits explicitly selected by release record. | No new generic consumerreview. Actual coupled browserfeedback/provider/load/cost/abuse/SLA stays operational/acceptance work, not assumed capacityPASS. |
| APP-RECOVERY | Apple6231637013 ACKs finite policy design. Local1208checks/66pins add samekeycounter/receipt/budget/originalexpiry evidence:24targets,22deliverycases/58consumes,2finiteexpiryrefusals. | Design/interface ACK preserved; actual nativequeue/restart/24h/twohandle/day27cadence/throttle/fraud practicality remains owning-native/product-enablement evidence. No new genericpolicyACK/captureloop or per-installation enforcement. |
| EXACT-RELEASE | Full current security and UX release audits found no new concrete wire/design P1/P2 for consumerimplementation. One exact [release record](IMPLEMENTATION_CONTRACT_RELEASE_V1.md) pins source/schema/crypto/policy/ACKs with clear precedence. | API must obtain final record reviews, protected delivery/CI and exact-main receipt. Outside protected main it remains candidate; no consumeractivation or public runtime/deploy authorization. |

Core retains raw HTTPS-route/context/selected-install checks and the separate
B-screen admission contract. Core need not own receiver HTTP polling or Apple
native retries. Prior Core route delivery is preserved; installed HA/proxy
reachability and physical acceptance remain separate evidence obligations.

## Historical unpartitioned-policy examples, not current limits or SLA

Assume two independent TV flows with already enrolled keys behind one public IP.
Each flow uses create,inspect,submit-challenge,submit,consume:5POST,3native calls,
2key RPCs and1create charge. Assume every browser POST needs one OPTIONS and native
calls have no Origin/preflight. The fixed non-poll cost is7recognized requests per
flow,14 for two flows. With P polls **per TV in one UTC minute**, two flows cost
`14 + 4*P`, provided those fixed actions are in that minute.

| Explicit scenario | Recognized total/minute | Native/minute |
| --- | ---: | ---: |
| Two TVs,30polls each at2s, worst preflight |134 (>120) |6 |
| Two TVs,20polls each with a suitably spaced >=3s schedule |94 |6 |
| Previous row plus two initial enrollments, each registration initial+2identical retries |102 |14 |
| Previous row instead plus three attempts each for the six native TV actions |114 |26 (>20) |

The last row combines the94total/6native example,12extra native TV retries and
8enrollment calls:114total/26native. It proves that independently bounded retries
cannot be multiplied without a shared budget/cadence policy. It does not prescribe
retrying every native error. If a2s flow consumes a minute's total cap just before
the original expiry, a next-minute retry hint cannot extend the QR to rescue it.
No advertised two-TV guarantee follows from the2000ms minimum/hint.

The3s example assumes no other native retries and correct UTC-window scheduling;
it is not a selected consumer algorithm, timing test, preflight-cache guarantee,
service latency promise or approved cap increase. Genuine receiver/Apple behavior
must be reviewed on exact proposed code. Gate503, transport timeout and missing
hints still require bounded original-deadline fallback, never key/QR churn.

At daily scale10,000 flows with60polls each cost650kPOST in the source model;
worst preflight adds620kOPTIONS, giving1.27m recognized requests, above the1m/day
candidate.10kallocation/day and1mHTTP/day are intersecting ceilings, not a promise
of10k successful maximum-poll flows.500registration attempts only accommodates
166complete three-attempt budgets, not500three-attempt enrollments. Existing
[partial cost scenarios](COST_CAPACITY_MODEL_V1.md) remain modeled, not account,
full-cost, throughput or spend approval. No threshold changes occur here.

## Distinct later gates and who can close them

The22 OPEN preparation flags are full-service/operations gates, not22 identical
contract blockers. Do not postpone the concrete source/contract findings above
behind a generic request for physical-TV proof. Equally, contract ACK or source
review cannot close actual edge identity/WAF/alternate-ingress behavior, complete
provider/error taxonomy, native supported signed-iOS composition, load/cost/spend,
logging/retention/backups, cleanup/secret rotation, public bundle/bindings or
migration collision/readback. API/operator retain those implementation and
qualification obligations under the assignment.

Protected source merge and separately bound Finalization still need their own
exact evidence. Applicable central manifest, immutable product artifact and exact
production authorization precede any Cloudflare mutation. Actual live smoke is
later evidence. Apple/HA onboarding and physical HA/iPhone/TV are joint gates;
public service health alone grants no HA display/session access. Receiver adapter
remains gated; timer off. No full-function closure or production-readiness claim.


Current CREATE-RECOVERY producer package is the independently reviewed
[pre-QR replacement proposal](CREATE_RECOVERY_PROPOSAL_V1.md) and
[reference qualification](CREATE_RECOVERY_QUALIFICATION_V1.md). It changes no
API endpoint/schema/server runtime. Existing receiver reviews remain received;
one NEW exception/adoption ACK is required, not an unchanged generic review.
Current main a4322fe was normally merged; historical source/tool receipts retain
their own exact pins.1184current-tool checks/126capacityconsumes are local only.


## Received pre-QR review and current precedence

The source snapshots above/linked qualification records recorded the pending
receiverdecision before API refreshed it. Exact ACK6270491529/6270497278 has now
been read in full; that NEWexceptionreview is CLOSED. The [implementation release
record](IMPLEMENTATION_CONTRACT_RELEASE_V1.md) supersedes generic NOT_FROZEN/HOLD/
openACK labels only for its exact SOURCE/WIRE implementation scope. It retains
ALL22opsOPEN/null/false and true native/receiver/physical/live/production gates.
Online/reconnect/start and persisted pageshow/BFCache must never replenish the
once-only preQRallowance; actual adoption remains the existing receiverowner.
