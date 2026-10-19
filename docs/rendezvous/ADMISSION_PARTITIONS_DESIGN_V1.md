# Admission partitions: proposed correction, review before runtime

Continuation of API90/6267254902; sole existing API writer, candidate parent ac565d2.
This is a numerical API-owned admission proposal, NOT contract freeze, deployed
capacity, an accepted SLA or a change to cryptography/owner trust. Prior
CAPACITY_QUALIFICATION_V1.md remains immutable evidence of the old policy failing.
No public/root Worker, bindings, dependency, consumer or timer changes are selected.

## Proposed exact limits

Retain original request admission order before body parsing/dispatch: recognized
routes count malformed/method/Origin failures; unknown paths never allocate.
Classify by the canonical server route alone, including OPTIONS and invalid
methods. Client headers/body/native flags never select the class.

| Per-IP per UTC minute class | Routes, all methods | Admitted attempts |
| --- | --- | ---: |
| poll | /poll |256 |
| create | /create |16 |
| native | /inspect, /attestation/challenge, /attestation/register, /submit-challenge, /submit, /attestation/recover, /attestation/delete |64 |
| terminal | /consume, /cancel |16 |

Each admitted attempt also increments existing total/native aggregate accounting;
maximum total352, maximum native64. No borrowing from another class: poll/create/
native cannot spend terminal16. OPTIONS on a native path now counts native class
and native aggregate, removing an unclassified preflight bypass. Every reservation
is for request attempts, including invalid ones, not an authenticated guarantee.
A same-IP attacker can exhaust any chosen route's class; edge abuse/fairness and
actual provider isolation remain separately unqualified. This is not a way to
bypass capability/proof/Origin checks or prioritize untrusted requests as owners.

Keep service-wide10000/minute and1000000/day hard ceilings and IP cardinality20000.
Within those ceilings, nonterminal requests stop at9000/minute and900000/day
(nonterminal = total minus terminal). Terminal attempts may use the remaining
1000/minute/100000/day plus any unused regular space, but never exceed total.
No cross-IP terminal guarantee after terminal/global exhaustion. Both UTC-minute
and UTC-day checks apply atomically with per-IP class checks; denial changes no
counters and creates no new identity/partition row.429 advice remains existing
next-minute bounded1..60000ms, including when a daily cap is exhausted; clients
must still honor original transaction/key lifetimes and stop finitely. Revising
that daily-cap advice is outside this numerical slice.

Arithmetic motivation, not measured capacity: four screens at one poll/2000ms
with OPTIONS every poll offer at most240 poll requests/minute;256 leaves16 phase/
transport attempts.16 create supports4 fresh create request/preflight pairs plus
8 bounded retries/errors, not an automatic retry contract.16 terminal supports4
consume or cancel request/preflight pairs plus8 retries/errors.64 native allows
four cold paths of5 requests each plus bounded repair/scanner traffic. These are
qualification targets, not guarantees under arbitrary retry/repair/adversarial
traffic, provider503 or actual browser feedback. The original120-second hard TTL,
60poll ceiling,2000ms minimum,5allocations/IP-minute,10000transactions/day,
500registration attempts/day,50000keycalls/day,4challenge attempts/transaction
and28/2/2proof slots remain unchanged.

## State and lifecycle

Private RequestInput changes from closed {identity,native} to closed
{identity,lane}, where lane is one exact enum. The trusted factory chooses the
lane; no public schema change. Export one limits constant for source/tests, not
consumer-selected values. Keep policy/object identity fail-closed, bump policy
marker to /2 so old policy configuration cannot accidentally run new quotas.

Keep existing request_days/minutes/ips tables and their original expiries. Add
request_ip_partitions keyed by the same pseudonymous minute key, with minute,
poll/create/native/terminal counters and the same original two-minute expiry;
add request_terminal_totals keyed by closed minute/day scope with count and the
same corresponding original expiry. All checks, inserts and increments execute
inside the existing synchronous SQL transaction; policy/time guards still cross
alarm awaits. At most20000partition rows alongside20000IP rows plus two minute
terminal rows and one day terminal row under normal cleanup bounds. No raw IP,
request body, tokens, key IDs or destinations stored/logged.

If an old unexpired IP aggregate exists without its partition row, refuse503
until its original expiry; never reset/synthesize empty lanes under a spent old
bucket. If a partition exists without matching IP aggregate or counters disagree,
fail closed503. Every stored counter must be a safe nonnegative integer; lane sum equals IP total, lane native equals IP native, and key/minute/original expiry match exactly. Existing global totals without terminal counters conservatively
count all old requests as regular. New terminal counter must never exceed its
global aggregate. Constructor only creates new tables; no destructive migration,
expiry extension, aggregate reset or global budget renewal. Alarm cleans both new
tables even with policy disabled and retains earliest original deadline. SQLite
fault rolls back all five tables. Terminal budget reserves no execution queue/DO capacity: busy503 can still block a terminal call, which the tests must expose. No added DO RPC; extra bounded SQL work means
old partial provider-cost estimates are historical and need separate refresh.

## Required qualification and honest outcomes

Preserve old1068 proof as historical; new runner/source/evidence gets a separate
name. Test exact lane boundaries, all eleven route/method classifications,
nonterminal IP/global saturation followed by terminal progress, terminal/global
hard exhaustion, malformed caller/result, same-IP and distinct-IP atomic races,
late-context/clock/policy failures, old-state reconstruction, row consistency,
SQL rollback/cardinality, original cleanup and IP privacy. Keep real P256/JOSE
one-time consume/decrypt, expiry/replay/origin/tamper regressions. Run original
four-screen schedule matrix against revised source, recording any remaining
fails as FAIL/HOLD; do not weaken handoff assertions. Native key/routing busy503
or four challenge attempts may still block scanner/repair cases and must not be
hidden by raising assertions' allowed failures. Explicitly test saturated poll
plus late ready consume/cancel before originalexpiry. No new actual browser
measurement is inferred merely by replaying old measured traffic.

After actual evidence and independent source/test/security/UX review, commit
source first, then separately rebind offline preparation to immutable new source
and exact new proof. Old preparation must first reject changed runtime bytes.
Exact protected CI, GitHub receipts and consumer handoff follow; no merge/freeze/
Finalization/live claim while remaining required contract/security gates are open.
API still owns lost-create recovery decision and exact joint release. Receiver
reviews are received; no unchanged ACK/capture rerun or consumer workaround.
