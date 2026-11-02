# Watch Moment alert transport candidate

This is the API-owned transport part of API #193 / Core #1426 / Apple #297.
The existing relay, D1 database, encrypted tokens and provider key path are reused.
No Worker endpoint imports this candidate yet; no migration, registration,
provisioning, provider call or production activation is supplied by its tests.

The [single proposed contract and shared fixture](watch-moment-alert-proposal-v1.json)
are explicitly awaiting Core/Apple adoption. The fixture is expired synthetic
test data, not a genuine publication, permission or native registration receipt.
An unimplemented detail URL is not advertised.

## Implemented transport behavior

`src/watch-moment/wire.ts` validates one bounded additive publication envelope,
rejecting private/unknown fields, duplicate JSON keys, accessors, route injection,
invalid encodings and excessive windows. It uses the original creation/expiry
pair. `payload.ts` emits only a generic five-language alert and the exact opaque
Session/Moment destination. It carries no contribution, question, profile name,
audio, artwork URL, installation identity or credentials to APNs.

`service.ts` requires a real server-only admission supplier and synchronous final
currentness check. There is no default implementation, self-issued grant or new
general R2 prerequisite. The supplier must authenticate the existing Core
producer and verify the original committed publication, recipient/Session rights,
external-relay permission, current preference, pairing/registration incarnation
and trustworthy original clock. Cancellation requires its distinct original
withdrawal authority, including after opt-out. Structural validation is not that
authority. No caller-provided boolean can replace it.

An original withdrawal checks the original publication/registration bindings
against its once record. It does not require a currently active registration,
encrypted token or current-owner credential. Its server-supplied authority must
remain specific to that original withdrawal; no send authority is inferred.

The exact registered Watch app, owner, installation, device, environment and
encrypted token binding must match an actual row in the existing API database.
The send marker atomically checks that registration, and the provider handoff
reads it again to deny a shared-store opt-out, owner switch or token rotation
even when a caller still holds an earlier admission snapshot.
Publications from before current opt-in or
pairing are denied. Final checks occur after asynchronous work, including after
token decryption/provider signing and directly before provider fetch. Expiry,
revocation, cancellation and local clock rollback deny new effects.

`store.ts` uses actual SQLite conditional writes and unique original identities.
Both original Session/Moment and publication ID are fenced per recipient. A new
event ID, expiry, destination or registration incarnation cannot manufacture a
retry. Only one reservation/CAS owner can send. A reconstructed service observes
the same durable outcome. In-flight or uncertain outcomes never cause automatic
resending. Known 429/5xx rejection may retry at most three total attempts, with
the original deadline and provider backoff. A provider delay beyond that deadline
is terminal. No background polling or second event bus is introduced.

Cancellation retains a tombstone even when it arrives before the producer send.
It stops reserved/retryable work; it cannot promise to retract an in-flight or
OS-delivered notification. Capacity is finite and explicitly selected by server
assembly, with a reserved cancellation slot. History is never silently evicted.
Exhaustion is reported as unavailable rather than dropping original outcomes.
Provider-invalid token updates are conditional on the exact old token/owner/
device/topic/environment, so a late callback cannot disable a replacement.

`relay.ts` wraps the existing `sendApns` implementation. It reuses provider signing
and token decryption, checks the decrypted token against the actual registration
hash and fixed APNs destination, then performs its final handoff check. It adds
bounded cancellation, alert priority, original expiry and per-publication collapse
identity. It preserves the registered environment. Session grouping and retry
collapse remain distinct.
Provider acceptance is recorded as `provider_accepted`, never as device delivery.
The synthetic example-token smoke shortcut is disabled for this candidate.
`transport_expires_at_ms` describes this send window. Apple must use Core's normal
authorized detail read to establish whether retained content remains available;
the notification timestamp neither grants access nor changes content retention.

## Remaining integration and acceptance

Core/Apple must adopt the same pinned fixture or identify concrete corrections.
Core must supply the actual original publication/current recipient authority;
Apple must adopt the notification category/preference and exact cold-start-open
decoder/detail read. Only then can API complete the thin authenticated assembly,
select and migrate the existing database schema through the normal protected
deployment procedure, and qualify a concrete test plan. No inferred permission
tuple or fake native key is an acceptable substitute.

Local workerd tests use real SQLite and real WebCrypto with synthetic authority
and a mocked provider. They cover the transport and denial boundaries; they do
not prove actual Core adoption, APNs delivery, notification visibility or tap
navigation. The integrated physical test must prove a background/cold Watch alert
and one tap opening the original Moment through an authorized Core read, without
TTS, playback or Session creation as a side effect.
