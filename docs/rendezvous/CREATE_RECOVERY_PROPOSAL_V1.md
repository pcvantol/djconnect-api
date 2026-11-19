# Lost create recovery: pre-QR replacement proposal

Status **PROPOSED_NOT_RELEASED**, recovery policy
**djc-pre-qr-replacement/1-draft**, existing profile0.4.0-draft/wire
djc-rendezvous/1 NOT_FROZEN. Fresh API90 ACK6269455602; sole existing API writer,
PR96, current main a4322fe incorporated by normal merge faf6b64. No consumer
writer/source, public route, Cloudflare mutation, timer or deployment selected.
This proposes an exact narrow exception to CREATE-RECOVERY, not an invented
server expiry, cryptographic protocol, HA ownership or screen/session grant.

## Problem, options and proposed choice

A create may commit but its201 response is lost. Browser has its own ephemeral
key/claim but no transaction ID, server created_at or expires_at. It cannot poll
or cancel that unknown transaction. Browser elapsed time/network timeout cannot
prove server expiry: network delivery may be delayed. AbortController cancels
client work, NOT a committed server transaction.

An idempotency/recovery endpoint would require new request binding, server-side
mapping/retention/tombstone and unknown-outcome rules; it is not necessary merely
to regain a QR which was NEVER exposed. Deterministic IDs or lookup using public
key/commitment are not selected. We instead propose **one fresh pre-QR replacement**
with strict client authority fencing. It abandons the original unknown transaction;
it does NOT recover, cancel, renew or overwrite it. Original server lifecycle and
all quotas apply to both allocations. No extra user action in this rare recovery.

## Exact eligibility and limits

Only one still-live foreground page/controller which retains complete original
state may use this exception. Required together:

1. The initial create POST was sent using newly generated nonextractable RSA-OAEP
   private key/public JWK, fresh32byte claim secret and generation1 (or a positive
   caller-supplied starting generation below2147483647).
2. NO QR for this interaction has ever been exposed. Exposure means before ANY
   renderer/share/accessibility/clipboard/log/analytics callback could receive a
   valid QR; the exposure flag becomes sticky before handing off the data, even
   if the renderer throws or partially displays it. No QR/payload in logs.
3. The original attempt has no accepted validated201. A transport failure with
   no known response/status, or a201 body-stream transport failure, or the10000ms local
   create-attempt deadline may retire it. A local timeout is an abandonment
   deadline only; it never estimates server expiry. A known non201 HTTP status (including429/503) stops immediately when headers are
   observed, BEFORE any body await and regardless of body completeness. A later
   stream failure/deadline cannot convert that known denial into replacement.
   A complete but malformed JSON/schema or mismatched201 context stops finitely and does NOT
   trigger automatic replacement. No429/503 bypass, retry advice change or
   automatic repair after invalid data.
4. The page has not hidden/unloaded/navigated, lost controller/key context or
   exposed any QR, and its one replacement allowance has not been spent.

Retire/fence the original attempt FIRST, then best-effort abort its transport,
drop controller references to its keys/claim/body/result, and allocate the one
replacement allowance. Garbage collection is not secure memory erasure; network
cancellation is not server rollback. A fenced old callback must never display,
store, poll, consume, cancel, submit or otherwise use its old result/authority.
All asynchronous continuations check controller epoch AND attempt identity AND
current phase before using data, including key generation, response body parse,
QR validation and render commit. Reentrancy/duplicate timeout or failure cannot
spend the allowance twice. Set exposure flag before invoking untrusted renderer.

Generate a new nonextractable RSA key pair and independent fresh32byte claim;
replacement generation increments once without wrap. Never reuse original JWK,
claim, browser key thumbprint, response, transaction ID or QR. Replacement uses
an ordinary create POST with unchanged schema and no idempotency/recovery field.
Maximum **two create POST starts per controller interaction**, including both
attempts, with no overlapping eligible authority. Generation/key preparation has
a5000ms local deadline; each sent create has10000ms local deadline. The interaction
has a30000ms active-page monotonic deadline from first key preparation. Clock
regression, hidden/unload or deadline exhaustion retires everything and stops;
timers may run late under suspension, so every continuation checks deadlines.
These bounds limit client behavior, not server arrival/expiry or physical cleanup.
No new client/system wall-clock synchronization requirement.

One valid current201 must be validated against the unchanged wire schema,
canonical service origin, current generation/JWK thumbprint and internally
consistent QR/transaction/expiry fields before exposure. Then normal existing
server-expiry/poll/consume rules apply. This proposal does not weaken their
clock/context validation or define a new interpretation of server timestamps.
Once exposure/acceptance occurs, no pre-QR replacement path remains, including
lost poll/submit/consume, uncertain cancellation, lost browser context or reload.
Those retain existing finite original-transaction rules and separate recovery
requirements. New page/reload cannot assume this retained-state exception.

If the replacement itself times out/fails, show the existing finite unavailable
outcome, not a third create, background timer, newQR/key loop or renewed lifetime.
The reference policy represents retry as a state transition, not a new localized
UI string; owning receiver supplies its existing five-language unavailable UX.
No manualIP, login, comparison code, PAKE/OOB or additional owner step is added.

## Server and capacity semantics

No API endpoint/schema/crypto/DO-runtime change is required for this proposal.
Each request independently traverses the existing /2 pre-body create lane,
allocation5/IP-minute,10000transactions/day, index and atomic child create.
Two independent original-lived rows may exist. The abandoned original may still
commit after timeout or after the replacement; this is NOT cancellation or
single-allocation idempotency. Its unexposed QR must never become visible later.
It remains inaccessible to the current browser controller by discarded authority,
and expires on the original server120s deadline/alarm. The service may not fetch
HA, grant B display/session rights, centrally retain user credentials or deliver
its envelope to the replacement's different key/claim/context.

The four-screen normal matrix still qualifies only its existing scope. Four
simultaneous initial creates plus four replacements exceed the unchanged5/IP-minute
allocation cap; some replacements must429 and stop finitely. Every OPTIONS/POST
and failed/lost admitted allocation counts normally. No quota refund, free
retry, SLA or successful four-screen-loss guarantee is selected. Existing busy503,
public edge/load/cost/native/physical and same-key finite recovery gates remain.

## API-owned qualification and receiver acceptance

Before selection: independent security/privacy and UX contract design review of
this exact exception, including whether pre-QR abandonment is sufficient and the
receiver can implement strict exposure/async authority fences. Then API-owned
reference policy/tests, not receiver source, qualify transitions, late replies,
reentrant events, context loss, deadline/clock anomalies and finite quota failure.
Explicit429/503/non201 headers followed by stream failure, body deadline or late
callback must remain terminal with no secondPOST; complete malformed201 is terminal.
Actual local Worker tests must withhold committed201, replace with fresh authority,
release late original replies before/after replacement, show only current QR,
prove transaction/claim/key independence, old/new context rejection and original
row expiry without fake cancellation. Real JOSE consume/decrypt succeeds only
for the accepted current context; abandoned-context delivery is never a success.

This candidate can be delivered as an exact producer contract proposal and proof;
**receiver owner must ACK/review the exact exception and adoption feasibility
before joint freeze/consumer activation**. API cannot substitute its own reference
controller for actual receiver implementation or browser UX acceptance. Existing
receiver ACKs/reviews remain delivered; this asks only for the NEW exception,
not unchanged capture/crypto crossruns. Core/Apple wire/proof semantics are
unchanged; notify exact producer delta without starting another lane writer.
