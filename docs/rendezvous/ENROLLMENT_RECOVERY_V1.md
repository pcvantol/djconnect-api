# Enrollment recovery — review candidate0.4.0

**NOT_FROZEN / NO_RUNTIME_GO.** Refines [KEY-STATE](KEY_STATE_V1.md) and
[wire profile](WIRE_PROFILE_V1.md); not a deployed recovery service. Addresses
Apple's concrete120s enrollment-timeout finding without extending a QR, retaining
HA credentials, creating an account or repeatedly generating hardware keys.

## Separate deadlines and local state

An enrollment challenge has its own fixed120s deadline. A TV transaction has its
own fixed120s deadline; enrollment never extends, reserves or revives it. A key
registered before enrollment expiry has its original absolute30-day deadline.
The device persists one enrollment attempt: opaque challenge/key handle, original
nonce/hash/deadline and exact prepared registration request, under existing local
app data protection. Never sync or log it; no HA/Profile credentials or account
mapping. Public API proof/challenge bodies must not enter analytics/crash reports.

Local states are `enrollment_pending`, `registration_uncertain`, `key_active`,
`recovery_pending`, `recovery_paused` and `replacement_pending`. State labels are
local diagnostics, not public key-existence responses or automatic UI steps.
The following limits are candidate application policy, not Apple quotas.

| Event | Required transition |
| --- | --- |
| Apple `serverUnavailable`, original challenge still live | Bounded same-key/same-clientDataHash SDK retry; no new key/challenge on that retry |
| Apple attestation received before deadline | Submit exact prepared request; API must finish verification and atomic registration before deadline |
| Registration answer lost, original challenge live | Retry identical registration at most twice, after2s then5s; retries share the original operation and cannot reset expiry/counter |
| Challenge expires before Apple success or before a certain registration answer | Stop SDK/registration retries; retain handle, discard expired proof/nonce/request, enter `registration_uncertain` |
| Fresh key-recovery assertion succeeds | Adopt returned original key expiry, enter `key_active`; original TV QR may already require replacement |
| Any recovery rejection, timeout, unsupported API or ambiguous response | Enter `recovery_paused`, retain handle, no automatic key generation or re-attestation |
| App restarted/resumed | Restore state and absolute deadlines; do not restart the enrollment/repair budget |

At most three Apple calls in an enrollment attempt (initial plus two retries,
2s/5s eligibility, only for Apple's documented retryable case), always within
the unchanged deadline; active SDK calls cannot overlap. Retry-After or OS
availability can delay eligibility, never bring it forward. If the original
deadline passes during a call, do not submit its late result. The remote Apple
key might nevertheless have been attested; do not claim hardware cancellation
or reuse its attestation with another nonce. No retry of a terminal SDK failure
as if it were `serverUnavailable`. Actual error mapping needs Apple fixtures.

## Fresh authenticated recovery of an uncertain registration

Add action `recover-key` to POST `/v1/rendezvous/attestation/challenge` (1KiB).
Issue a fresh32-byte challenge with120s lifetime, original key ID and exact saved
clientData, regardless of whether that key is present. Apply aggregate/per-IP
admission **before allocation**, at most one outstanding management challenge
per key address/action and32 total unexpired challenge/receipt records per key
address including unknown keys. This bounds allocation; it is not installation
identity or a timing-side-channel guarantee. Do not allocate a new key record.

For the same key address/action, repeated management challenge requests return
the existing unexpired challenge and exact clientData without changing nonce,
operation ID or deadline. Never replace/invalidate it or reserve it for the
requester. Apply identical coalescing to known and unknown keys. Invalid proofs
do not consume a challenge or advance a counter; successful verification
consumes it atomically. Rate limits still apply before lookup/allocation/crypto.

Management challenge responses for `delete-key` and `recover-key` use the same
closed shape `{v,challenge_id,challenge,expires_at,client_data}`. The decoded
clientData for recovery is exactly
`{v,action:"recover-key",service_origin,key_id,challenge_id,challenge,expires_at}`.
It contains no QR, transaction, route, user or installation ID. Native validates
every field against the captured action/key/origin/nonce/deadline, hashes the
exact saved bytes and obtains an assertion using that existing key. No blind
signing, JSON reserialization, registration or delete/submit proof reuse.

POST `/v1/rendezvous/attestation/recover` (16KiB) accepts exactly
`{v,key_id,challenge_id,client_data,assertion}` with the existing assertion and
clientData byte limits. The key coordinator requires a current active verified
key, exact saved bytes/action/nonce and a verified strictly higher uint32 counter.
After crypto it atomically rechecks deadlines/state, advances counter, consumes
the nonce and saves an immutable recovery-operation receipt before returning
200 `{v,key_expires_at}`. No5s cross-object authorization is issued here; this
single-object operation cannot submit a destination or grant anything in HA.

Receipts store operation ID, exact request digest, original result and original
challenge expiry only; no proof or route. Retain until that original120s deadline,
capped by key expiry. Identical retry before that deadline can recover the
original result without a second assertion/counter increment, only while key
remains active. Changed request for same operation fails; revoke/expire wins
over a cached receipt. At deadline equality return failure and delete receipt
logically even if physical cleanup is delayed. This differs deliberately from
the transaction's historical accepted-submit receipt; no destination was accepted.

Unknown/revoked/expired keys, invalid counters/proofs and mismatches all receive
the existing `invalid_sender_proof` without exposing key state, counter or cause.
Absent/expired management challenge also returns that same error; do not use
public `expired` to disclose a key's presence. Unavailable service returns503;
rate/payload errors keep their existing bounded semantics. No status-by-key-ID
endpoint or weaker proof fallback. A generic rejection cannot safely tell the
app to regenerate its key.

Recovery request timeout permits at most two identical retries,2s/5s eligibility,
inside original recovery deadline. No second recovery challenge automatically
after exhaustion. Before a retry the current key may be revoked/expired and
must fail closed; a recovered old response is not a fresh proof of current HA
route or authority. Ordinary submit still needs fresh context and assertion.

## Paused repair and replacement limits

`recovery_paused` stops this QR attempt and preserves ordinary app/HA pairing.
Explain that secure connection could not be prepared and can be retried later;
do not show a successful connection, unknown-key cause or a new normal-flow code.
Scanning again, foregrounding, app restart and changing Profile do not reset
the repair state or trigger key generation. Server Retry-After always applies.

Candidate local repair policy: persist a24h cooldown from entry into paused
state; it limits replacement-key creation, not all use of an existing key.
During that window, permit at most two further **explicit** same-key recovery
attempts, at least60s apart and subject to server Retry-After. Each gets its own
bounded challenge/identical-request retries; no background or scan-triggered
retry. Count these across restart/Profile changes in the original persisted
repair window. Re-entering pause does not reset its start or replenish attempts.
A successful same-key recovery restores the still-valid original key without
waiting24h; no expiry or QR is renewed. If those attempts fail, pause without
further automatic work. This avoids treating a short outage as a mandatory
day-long lockout while keeping replacement generation bounded.
After the cooldown expires, an explicit user's retry may start one replacement
enrollment, subject to API admission and SDK support. Never infer replacement
authority solely from `invalid_sender_proof`. Reuse neither old attestation nor
old registration nonce; a replacement is a fresh independently attested key.
Maintain at most two locally unresolved handles: the retained old handle plus
one pending replacement. If the replacement also becomes uncertain, pause and
require diagnostic resolution; no third key, periodic retry or handle-discard
loop. These are local loop limits, not server enforcement of one installation
or a promised fraud/throttling budget. Reinstallation cannot establish that bound.

After acknowledged replacement registration, retire the old local handle and
keep the new active one. An old possibly registered server key can remain until
its original30-day deadline if authenticated deletion could not be obtained;
do not claim remote revocation or hardware key erasure. No more than one
replacement attempt per24h within retained local state; no central device index.
Monthly normal rollover remains separate: day27 is foreground eligibility,
day30 is hard expiry; no background-scheduling or production-quota guarantee.
Apple must qualify whether this finite recovery/cadence is practical before freeze.

## Evidence and remaining gates

Apple's [feasibility report6230012929](https://github.com/pcvantol/djconnect-api/pull/94#issuecomment-6230012929)
and [follow-up6230629149](https://github.com/pcvantol/djconnect-app/issues/87#issuecomment-6230629149)
report19+15Mac/Node interop checks,5Chromium checks and signed development
artifact40210. These are producer-reported results, not API-rerun or independently
retrieved source/artifact qualification: the local unpublished Apple commits
`50d050a` / `cd23fa0708c881f8899b95b44029b2d119683071` were unavailable in this
API host's Apple checkout. The physical runner's `isSupported=true` proves
device capability only. No app-bound Apple fixtures, iPhone/WebKit/TV or new
service runtime proof exists in that handoff. Generic JOSE decrypt acceptance
is not closed header/context/parser acceptance.

Absence of App Attest entitlement alone is not a demonstrated development
blocker under Apple's sandbox guidance; establish the actual environment from
verified app-bound evidence. Do not alter signing/account settings speculatively.
Unsupported targets fail closed; never borrow a phone assertion or admit a
different test-runner identity. Actual AAGUID/version/distribution-extension
policy and initial Apple fraud-receipt verification/binding/finite retention
remain unresolved before enrollment implementation. No fraud receipt collection
or hardware diagnostic is dispatched by this document.

The schemas/byte examples below are structural cases only. Required future
runtime cases: registration reply lost before/at expiry; Apple unavailable through
deadline; recovery after successful/absent registration; recovery counter race
with submit/delete; duplicate/changed recovery; lost recovery response; revoke
after receipt; expiry equality; crash around counter/receipt commit; cooldown
across restarts; second uncertain handle; cleanup failure and global admission.

Independent supplied-policy/excerpt technical/security and UX/privacy reviews
returned GO after oneP2 correction: coalesce rather than replace/reserve an
outstanding management challenge. Both reviewers also assessed the bounded
explicit same-key retry refinement. No remainingP1/P2 in those text scopes;
neither reviewer independently read Git/source/SDK or executed schemas/runtime.
This is no full privacy acceptance, contractfreeze or implementation approval.

Primary Apple references: [preparation](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service),
[integrity/retry guidance](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity).
