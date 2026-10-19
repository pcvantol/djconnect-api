# Shared-NAT capacity decision: HOLD

Profile **0.4.0-draft**, wire **djc-rendezvous/1**, **NOT_FROZEN**.
Same sole API writer/existing draftPR96; runtime source remains
`083ddb2d16351b4f785e52a23aad675b0a2cf9ef`, parent producer6463927.
Fresh ACK: https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6266431789.

[Receiver's two independent reviews and exact questions](https://github.com/pcvantol/djconnect-api/pull/96#issuecomment-6266032306)
are RECEIVED. The routed retry-hint correction49ecb95 is CLOSED, not a blocker.
Existing schema/crypto ACKs/captures/crossruns remain delivered. API owns this
capacity evidence, policy correction and exact contract-release decision; this
report does not substitute another generic request for consumer ACK.

Qualification target: **four concurrent TVs behind one IP**, warm or cold native
keys: timely valid approval should yield encrypted one-time delivery before each
original120s deadline. Overload/faults must separately fail finitely and honestly. This is a target, not an already promised service capacity.
A target failure is not converted to success by expiring safely. No lower released
capacity/SLA is inferred from successful one-TV examples.

## Decision and result

**HOLD_CURRENT_POLICY_FAILS_TARGET**. Current120total/20native-IP-minute admission
has no reserved terminal headroom; pending traffic can prevent timely submit,
consume or cancel. Four-TV sustained/scanner/repair cases fail; even two TVs fail
some late-approval schedules. No numerical threshold, poll hint, receiver fallback
or extra user step was changed to hide that result.

[Machine decision](capacity-decision-v1.json), [complete Worker observations](workerd-capacity-observations-v1.json),
[actual browser traces](capacity-browser-traces-v1.json).

| Evidence family | Scenarios | Scenarios meeting handoff target | Consumed TV flows | Expired TV flows |
| --- | ---: | ---: | ---: | ---: |
| Fixed measured offered-prefix replay, approval30s |24 |24 |56 |0 |
| Synthetic every-poll preflight, approval90/115s |24 |12 |18 |38 |
| Independent concurrent scanners or cold-key repair |6 |4 |6 |8 |
| Total handoff scenarios |54 |40 |80 |46 |

Each TV is counted per scenario, not as126 real devices. The other12 cases test
specific failure/budget boundaries; their boolean test targets are not successful
TV handoffs. **1068/1068 workerd checks + isolated runtime strict TypeScript PASS**
means1002regressions plus66 complete capacity cases passed their assertions,
including assertions that unsupported targets fail. It is not capacity-PASS.

## Real browser transport measurement

Playwright1.64.1, Chromium156.0.8078.4 and WebKit27.2 ran on macOS/arm64 using
fresh isolated contexts and two loopback HTTPS ports. No system hosts/DNS,
truststore, existing browser profile, receiver source, public Cloudflare service
or deployment was changed. A temporary self-signed certificate is accepted only
inside the test contexts; this is not TLS security qualification.

The fixed trusted bridge maps local URL/Origin to the exact canonical ingress and
maps its ACAO back to the fixed local page origin. The probe uses actual
createIngress headers/JSON validation with a trusted always-admit callback and
synthetic pending responses, WITHOUT transaction state/authority. Browser HTTP
routing interception is not enabled: preflight/cache behavior is the engine's.
This topology is not actual api.djconnect.dev/vibecast.tv or Cloudflare edge proof.

Each engine ran1/2/4screens for approximately65s,33polls/screen, waiting2000ms after
the previous completed round. At round10 it reloads the same context; at round20
it replaces contexts. These operations measure transport cache only; they do NOT
qualify recovery of transaction authority lost by a real reload. Per screen both
engines received33pollPOST+12pollOPTIONS and a request/preflight pair on each of
create/consume/cancel:51requests total,0poll transport errors. The create/consume
route probes return409 and cancel200 as synthetic CORS responses, never real
stateful creation/admission/cancellation. All timestamps, phases, methods, routes,
statuses and preflight header names are in the trace; no proofs/URLs/destinations
or private keys are stored there.

The c trace source list omitted its input create-schema fixture. The separate
[post-execution input provenance](capacity-browser-input-provenance-v1.json)
records unchanged fixture bytes equal to immutable083ddb2/current1002proof plus
actual tool versions. This supplements that run, not a browser rerun or altered
trace. Its other source pins still match the executed source. Earlier constructor
failure a used an incompatible Miniflare options shape; the installed adapter
fixed that. Exploratory b used fixed-grid timing, superseded by c's response-based
cadence; b is not presented as the current transport qualification.

## Stateful Worker replay and its limits

Actual createRequestBudgetedHandler, request/allocation/key/index coordinators,
SQLite state, software initial enrollment, P256 assertions and standard JOSE
execute in workerd. Each TV has a nonextractable test RSA key. A success requires
one actual consume and decryption/context equality; it never means HA-screen or
session admission. All received11route types, OPTIONS, statuses/advice, original
lifetimes, poll counts, challenge attempts, key counters, operation-group counts
and retained budget snapshots are recorded without sensitive identifiers.

The measured family replays the fixed offered poll script prefix plus explicit
synthetic native/terminal actions. A denied preflight suppresses that planned POST
until the next recorded OPTIONS; every offered/skipped request and reason is
retained. Real browser feedback might retry a preflight sooner because a denial
creates no successful cache entry. Therefore this is **NOT coupled stateful
browser feedback or post-denial cache/request-budget qualification**. It also
retains synthetic replay keys/claims through the probe's refresh/context phase;
that is not real tabrefresh/reconnect recovery or authorization continuity.

Sustained cases use separately labeled synthetic worst-preflight schedules for
90/115s approval; they are not extrapolated measured traces. Server Date is
controlled at UTC-minute phases0/59000ms and a day boundary; it is distinct from
browser wall timing and cannot establish latency/CPU/provider throughput/SLA.
Warm-key setup enrolls software fixtures180s before a case, then resets admission
counters for an empty-budget baseline. Prior setup/shared-account usage is excluded
from that scenario; no daily traffic/spend inference follows. Original120s expiry,
60poll ceiling,2000ms minimum/hint,4issuance attempts and28/2/2
operation groups remain unchanged. Sequential schedule replay is not concurrent
load qualification. The independent-scanner cases do invoke two paths concurrently
with separate native keys; per-scanner stage/status/error records show where each
actually stopped. A busy503 can stop a scanner before submit; no full path is
claimed merely because it was started, and at most one winner is accepted.

## Terminal headroom, loss and budget boundaries

- At ordinary ready-state saturation, consume/cancel initially429. At that429,90s original lifetime remains; the next minute arrives30s later,
  leaving60s, and the retried action succeeds.
- At late saturation, only5000ms remains but the actual hint is6000ms. Next-minute
  consume/cancel returns410; no cancellation success, redelivery, renewed QR/key or
  deadline is claimed. The row may retain ciphertext until its alarm; logical
  expiry still prevents use. This is a concrete current headroom failure.
- Lost create response leaves the consumer without ID/deadline and with no selected
  recovery exit. The test offers no second create or guessed deadline. API retains
  that contract decision; no new receiver wire blocker is invented here.
- Lost submit may recover only its historical202 receipt. Lost consume yields
  consumed state/no envelope, server release1/browser handoff0; no second release.
- Three exact registration requests charge three attempts while keeping one key
  and original expiry. Challenged recovery increments its counter; independent
  deletion revokes it. Both endpoints use existing proof semantics.
- The500registration-attempt case and50kkey-call case use separately preseeded
  budget rows; these are boundary probes, not500/50k measured live operations. At500attempts,
  denied registration still costs the preceding routed key call (no refund).
  At50kkeycalls, neither key-child work nor registration charge occurs. Day rollover
  does not renew a surviving transaction.
- Controlled no-hint503 and60000ms advice with5000ms remaining stop within original
  expiry. The explicit finite5000ms fixture fallback is NOT selected receiver code
  or a hidden runtime policy. It is dependency-fault injection, not provider busy
  load measurement. Actual concurrent scanner503s are separately recorded.

## Evidence integrity, review corrections and reproduction

Final Worker run e records1068passed checks,61source/input hashes and exactly66
capacity observations. A Node reporter ties each observation's test task ID to one
passed test name/status, checked against the JSON test result. The runner rejects
missing/duplicate/unmatched records and any count other than66. Intermediate a had
1067checks pass but summary FAILED because the JSON reporter omitted console data;
it produced no accepted capacity summary. Review corrected the initial insufficient
'minimum20 observations' condition, split mixed day gates, strengthened independent
scanners and exposed offered/skipped traffic. b/c/d are superseded by final e's
complete counters and scanner-stage audit, not relabeled as that execution.

The runtime58hashes remain equal to083ddb2. Existing1002proof and the offline
preparation pin are still valid; no runtime rebind is required by new test files.
Existing API40/40, root types, projection,107schema/two byte examples and21offline
preparation checks pass. The preparation result still says BLOCKED/NOT_AUTHORIZED,
22OPEN/null/false. Protected CI is recorded separately on API90/PR96; local1068 is
not a newly added CIjob or a product-bundle proof.

Reproduce with existing pinned PKI/JOSE dependencies and isolated browser packages:

```sh
PLAYWRIGHT_BROWSERS_PATH=/private/tmp/pinned-browser-deps/browsers node qualification/rendezvous/run_capacity_browsers.mjs /private/tmp/pinned-browser-deps /private/tmp/fresh-browser-output
node qualification/rendezvous/run_capacity_workerd.mjs /private/tmp/pinned-pki-deps /private/tmp/fresh-worker-output /private/tmp/pinned-jose-package
```

The Worker runner uses the checked-in exact browser trace; a fresh browser run is
new evidence and must be separately inspected/bound before replacing that input.
Temporary outputs are0700, files0600, telemetry/Worker egress disabled. No real
HA/Profile/Session bearers, application secrets or user destinations are involved.
Sources: [Playwright browsers](https://playwright.dev/docs/browsers),
[network behavior](https://playwright.dev/docs/network),
[Cloudflare test APIs](https://developers.cloudflare.com/workers/testing/vitest-integration/test-apis/).

## Required next decision

API must revise and independently qualify admission/polling/terminal headroom, or
obtain an explicit jointly accepted narrower target. No substitute threshold or
silent receiver workaround is selected by this report. Receiver reviews are
received; public contract release remains API-owned and **HOLD** on the current
capacity result and the still-unselected lost-create recovery contract.

Public edge/WAF/provider/cache propagation/load/cost/retention/logging/secret and
artifact/binding qualification remain separate API/operator work. Genuine signed
Apple/HA onboarding and physical TV remain separate. No public entrypoint,
production mutation, protected merge or Finalization is claimed. Receiver stays
clean/gated, timer off. The full assignment remains OPEN.
