# Rendezvous App Attest KEY-STATE — review candidate 0.3.0

Assignment `DJC-API-VIBECAST-RENDEZVOUS-V1-20261016`, existing API94 writer.
**DESIGN_CANDIDATE / NOT_FROZEN / NO_RUNTIME_GO.** All durations and capacities
below are proposed application policy, not existing Cloudflare or Apple quotas.

## Resolved product boundary

[API94/6226306251](https://github.com/pcvantol/djconnect-api/pull/94#issuecomment-6226306251)
and [API90/6226325313](https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6226325313)
record the limited app-reported paired-route choice. The API writer independently
read the original Apple conversation: concrete copied-QR question, direct human
`ga verder`, explicit limited readback, subsequent `akkoord`. Do not ask it again.
No intended-TV-owner/independent HA-owner/physical-presence proof is claimed.
A genuine other paired scanner with a copied active QR can win with its own
possibly misleading URL. B's HA six digits do not repair earlier A phishing.
This accepted product boundary does not approve storage, crypto or deployment.

## Exact proposed state and retention

| Record | Contents | Eligibility / cleanup |
| --- | --- | --- |
| Attested key | Public key, app-policy ID, environment, highest unsigned32 counter, created_at, key_expires_at, status | Active for at most30 days from successful registration; never extended by activity |
| Key address | SHA256 of environment, configured app-policy ID and canonical Apple key ID, under a fixed internal namespace | Linkable identifier; not anonymized, never a user/HA/paired-install index |
| Enrollment challenge | Random32-byte nonce/ID, key address, action, created_at, expires_at |120s; one successful enrollment; no existing-key overwrite |
| Submit challenge | Exact clientData bytes/hash and transaction/key/envelope binding | Original transaction deadline, at most120s; no winner reservation |
| Authorization | Operation ID, immutable tuple/digest, counter, admitted_at, authorization_expires_at | At most5s, capped by transaction and active-key deadline |
| Operation receipt | Same operation binding and outcome, no envelope/URL | Until original transaction expiry, at most120s; retry never refreshes it |
| Revoked-key tombstone | Key address, status revoked, original key_expires_at, purge_at | Immediately remove public key/counter/receipt; retain minimal denial until original key deadline+120s |
| Transaction | Original browser/key/generation/deadline, capability commitments, pending/ready/terminal state; ciphertext only while ready |120s fixed; clear ciphertext on consume/cancel; remove application state after original deadline |

Time is server UTC integer milliseconds; equality with a deadline is expired.
Logical access is denied at the deadline even if an alarm is late. Cleanup alarms
delete expired application rows and retry failures. Operational target: cleanup
within15min of purge_at; overdue cleanup is a privacy incident/alert and pauses
new key enrollments until investigated. It is not a promise of physical erasure
from provider backups. Live qualification must establish cleanup monitoring and
provider retention. No automatic activity-based renewal or permanent denylist.

No account, owner/Profile/Session/device ID, installation mapping, IP, HA URL or
pairing credential is stored in key records. Keys still link activity across
transactions during their finite lifetime; infra connection metadata is separate.
The maximum active-key lifetime is30 days. After revocation the linkable
key-address tombstone remains until original key expiry plus120s, so retention
after early revocation can approach30 days plus120s. These finite periods require
independent privacy/technical review before enabling this profile. No D1
migration, namespace or key registry is created here. Existing D1/APNs stays out.

## Registration, rotation, deletion and recovery

Enrollment is controlled by the API: issue one bounded fresh challenge after
admission limits, verify the complete Apple attestation and actual configured
app identity/environment, then atomically create the key record with counter0.
The same key cannot overwrite an existing active or tombstoned record or reset
its counter. A duplicate exact enrollment operation may return its original
result; it never resets created_at, expiry or counter. Unknown enrollment operation,
expired nonce, caller public key alone or a cached old attestation fails closed.

The app retains its install-local App Attest key handle, separate from HA pairing.
One active key per app installation/environment is the intended normal state;
not one key per QR. Proposed rollover: start one new independently attested key
after day27; old key expires irrevocably at day30. This permits at most3 days
overlap. No transfer of counters, public keys or identity from old to new key.
Each key has its own registration challenge and actual Apple verification.
No cross-device sharing, cloud backup or borrowed Mac/iPhone assertions.

This monthly cadence differs from Apple's typical once-per-user/device rollout
guidance. **Apple-owner validation of its practicality, throttling and fraud-metric
implications is a release gate**, not an asserted Apple recommendation or quota.
Do not generate recurring keys against Apple while reviewing this document.
If this cadence cannot be qualified, revisit the finite-retention design; do not
silently keep keys forever or regenerate them per QR.

Authenticated key deletion uses an independently challenged App Attest assertion
with action `delete-key`; it transitions active to revoked and erases public key,
counter and enrollment material, retaining only the finite tombstone above.
An operator's separately authorized key revocation may use the same transition;
no new public admin/account API is implied. Unknown callers cannot delete keys.
Deletion is not advertised as immediate total erasure while the tombstone exists.

App update keeps the current key handle if valid. Reinstall/restore/migration,
lost key, unknown server key or expiry requires fresh enrollment with a new key;
it does not re-pair HA. Persist a pending enrollment attempt locally so an API
timeout does not trigger key-generation loops. A timed-out attestation call uses
Apple's documented retry handling; do not assume successful re-attestation of an
already attested key. All recovery backoff is bounded and server-directed.

After purge the API cannot promise permanent device exclusion or remember every
historical key. Old registration challenges remain expired and assertions for
unknown keys fail. Any future enrollment requires a genuinely fresh challenge and
valid attestation, not restoration of the prior counterless record. This is key
replay/revocation policy for finite state, not a permanent identity/ban service.

## Counter owner, transaction owner and crash ordering

Proposed DO roles: one private `AttestedKeyState` coordinator per key address,
one `VibeCastRendezvous` per server-generated transaction. The Worker is the only
public router. Private RPC results are not client-bearer tokens; do not expose
an endpoint that accepts `verified:true`, a caller-supplied counter grant or
arbitrary DO names. No new cryptographic receipt/signing scheme is introduced.

1. Worker validates request bounds and immutable tuple, then obtains the saved
   challenge/clientData. A transaction DO never advances ready on this alone.
2. The key coordinator verifies the App Attest assertion against its own verified
   public key/policy. It serializes per-key processing. After any asynchronous
   crypto it rechecks key state, deadlines and stored counter inside its own
   storage transaction before committing highest_counter and an immutable
   authorization/operation receipt together. Require unsigned32 new_counter>
   highest_counter; never wrap or decrement. Exhaustion requires a new key.
3. The operation ID is challenge_id. Same operation+same digest/context may
   recover its original result without incrementing/resetting a counter. A
   different tuple for that ID conflicts. A consumed nonce cannot authorize a
   second operation. Receipt lookup is server-internal and bound to that tuple.
4. Immediately before the transaction's atomic pending->ready commit, obtain a
   still-valid coordinator authorization through private RPC. The transaction
   stores only its immutable source-policy/result metadata and ciphertext.
   Inside its own transaction recheck pending state, original generation,
   capability, deadline, tuple and the absolute authorization_expires_at.
   Competing submissions cannot replace ready. No external await occurs between
   this final synchronous state check and committing the state transition.
5. If the coordinator committed but the transaction did not, that counter is
   burned. During the5s authorization window the same operation can finish
   identically; afterward obtain a fresh challenge/assertion with a higher counter
   if the transaction is still pending and unexpired. New challenge IDs cannot
   reuse the old assertion. If ready already committed, status may report ready
   for the original operation, without re-delivering any destination to the app.
6. If a reply is lost after ready, retry/status returns the committed operation
   disposition; it is not evidence of browser consume or B admission. Browser
   consume remains one-time; a lost consume response needs a fresh QR. Local
   cancellation cannot recall a possibly committed/consumed address.

There is **no cross-DO atomic transaction**. Authorization at step2 is the
key-authority admission point; step4 is the winning transaction-state point.
Key revoke/expiry prevents new authorizations. A previously returned authorization
can still win for at most5s, capped by its original deadline; a ready destination
is not recalled by later key revocation and expires with its120s transaction.
This bounded revocation window must be reviewed explicitly; do not promise
instantaneous atomic key revocation across the two DOs. Browser cancellation
does linearize atomically against ready/consume inside its transaction DO.
At revocation the coordinator refuses subsequent lookup/minting, but cannot
withdraw an internal result already returned. B still requires current HA state.

App assertions are serialized per key, not merely per QR. A later counter arriving
first can make an older in-flight assertion fail. This is safe rejection, not a
reason to lower the highest counter. Both app and API use original deadlines.
No Profile/HA authority is inferred from a successful counter transition.

## Bounds and monitoring for review

Proposed admission ceilings:500 new keys/day,10,000 new transactions/day,
32 unexpired challenge/receipt records per key,4 submit-challenges per transaction,
one active crypto verification per key, and per-IP edge budgets. Enforce aggregate
allocations in a dedicated private budget coordinator before persistent allocation;
Worker isolate memory counters or regional limits alone are not global proof.
Reject overload503/429 before certificate crypto. Native unsupported/Apple outage
never receives an unsigned fallback. Thresholds need real duration/load/cost
qualification; this draft neither funds nor provisions them.

Counters, key IDs, certificates, receipts, operation/transaction IDs, assertions,
URLs and bodies are excluded from application logs. Only fixed route/error and
aggregate admission/cleanup metrics. Never send Apple fraud-metric requests or
reuse existing APNs credentials without a separately reviewed authorized need.

## Review and test obligations

Test with controlled clocks/fault injection: fresh registration; duplicate no
reset; active/tombstone overwrite denied; expiry equality; no rolling retention;
revoke and purge; enrollment-response loss; stale enrollment challenge; unknown
key recovery; counters equal/lower/max; two transactions with one key; same op
retry/different digest; crash before/after each of the two commits; RPC reply
loss;5s lease equality; cancel/revoke between authorization and ready; failed
alarm and cleanup alert. Keep synthetic model tests separate from actual DO
and Apple-device proof. None has been run for a runtime that does not exist yet.

External gates: finite-state/privacy acceptance of this exact policy; Apple
key-lifecycle cadence and real App Attest fixtures; verifier/path-validation
qualification; actual DO race/crash tests; contractfreeze and independent reviews.
The resolved copied-QR product choice is not another external gate.
