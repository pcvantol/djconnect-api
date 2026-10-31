# Separate content-free host-app wake: candidate source contract

This source implements a separate issuer, encrypted token registration, bounded
SQLite operations, terminal withdrawal and background APNs construction. It is
not imported by the public Worker or existing surface composition. `schema.sql`
is a source-only schema, not an automatic production migration. The namespace,
version and role below are candidate API choices for joint Core/Apple review;
they are not an existing deployed endpoint or independently qualified client
adoption pin. Existing widget enrollment, rich DATA codec and update/end adapter
are unchanged. No rich content, read/asset credentials, owner secrets or artwork
are carried in the provider payload. `external_relay:false` remains unchanged.

## Mandatory original server authority

`createHostAppWakeService` has no default ports. `admitOriginalPurpose` must
authenticate the actual selected original issuer/custody wire and return one
stable original wake-purpose identity. An operation UUID, installation ID or
client assertion is not that identity. `assertCurrent` must synchronously check
the real current original scope, owner/device/install/source binding, withdrawal
and clock continuity. It must throw on uncertainty; a boolean or promise is
refused. `now` must be the actual qualified clock supplier, not a fabricated
Date/uptime mapping. Local monotonic checking retires this service generation
on rollback; it is not proof of native clock qualification or continuity after
restart. The actual issuer/trust and native clock suppliers remain absent. A separate
mandatory `admitNativeRegistration` port must authenticate the actual native
host-app token observation and installation/target binding before token
encryption or registration. A capability and syntactically valid token do not
substitute for that genuine enrollment input. No default implementation or
public native-proof wire is invented here.

The structurally closed `OriginalPurpose` contains exactly `version`,
`purpose_id`, `token_role`, `owner_binding`, `device_binding`, `source_binding`,
`target`, `apns_environment`, `platform`, `issued_at_ms`, `expires_at_ms`,
`display_expires_at_ms`, `max_operations` and `max_wakes`. The three bindings are original 64-character
lowercase hex digests. Target is exactly `host_bundle_id` plus `installation_id`;
these must come from real admitted native identity. Platforms are iOS/iPadOS;
APNs environment is separately sandbox/production. This purpose grants cache
invalidation only, not Core read, asset, display, Activity start or remote-start
rights. Display-purpose lifetime and short-lived content/asset expiry retain
their independent Core decisions.

`issueOriginal` is a server-only method, not a public HTTP issue endpoint or a
new operator secret. It inserts a unique original purpose and credential hash
before returning one random `djchw_` capability. The secret is returned once and
never stored or exposed through status. A lost acknowledgement, restart,
withdrawal or a new operation UUID cannot recover/reissue that same purpose.
The real supplier must preserve original identity across retry: calling a new
purpose ID the same original approval would violate the port contract.

## Closed candidate operation grammar

Version is `djc-host-app-wake/1`; token role is `host_app_wake`. Candidate
POST paths under `/v1/push/host-app-wake/` are `register`, `wake`, `revoke` and
`status`. They require the separate capability as Bearer authorization; legacy
app/HA, WidgetKit and ActivityKit credentials are not accepted. Origin, cookie,
query/fragment, compressed bodies, malformed UTF-8, duplicate JSON keys and
unknown fields are refused. Bodies are capped at 8192 bytes. All requests have
exactly `version`, `purpose_id` and `operation_id` plus these action fields:

| Action | Additional exact fields |
| --- | --- |
| register | `generation`, `revision`, `token_role`, `target`, `apns_environment`, `apns_token` |
| wake | `generation`, `revision`, `event` with the sole value `direct_rich_refresh` |
| revoke | none |
| status | none |

Tokens are actual host-app APNs tokens, never renamed WidgetKit, ActivityKit
update or push-to-start tokens. Target, role and environment must equal original
scope. A registration generation identifies the original registration sequence;
token rotation increments its revision through SQLite CAS and retains the same
generation and original expiry. Encryption AAD binds the full original purpose,
generation and revision. Initial revision is one. A conflicting CAS consumes
bounded operation space and grants no target. Status reports current state,
generation/revision, original expiry and operation/provider observation only;
callers must compare the actual returned tuple, not infer registration success
from HTTP 200. It never returns a token or credential.

## Once, retirement, limits and delivery

Purpose issuance and operations use real SQLite atomic transitions, not a RAM
once-set. Same-operation replay is observation-only across service restart;
different request bytes under that identity are refused. Dispatch requires the
reserved claim and current registration tuple. Its durable marker is the
authorization linearization point before the one outbound call; withdrawal or
rotation before that point prevents dispatch. An already marked request cannot
be unsent by later withdrawal. A lost marker/provider reply is unknown and
cannot become a retry. An uncertain final persistence/currentness response is
reported as unknown. Provider acceptance is not native receipt or display. Each wake transport deadline is captured before request-body/authentication awaits and is at most thirty seconds, capped by the original wake-purpose expiry. The deadline is retained in SQLite and never recomputed on replay.

Original bounds are immutable: at most eight hours as a defensive API ceiling,
256 active operations and 64 wakes per purpose. These are ceilings for the new
wake scope, not a selected rich display duration. Actual smaller budgets must
come from original admission. Server-selected purpose capacity is at most 4096
retained identities; no expired/withdrawn history is evicted to mint room.
Withdrawal uses the existing purpose row, needs no operation insertion,
remaining budget, encryption key or APNs credential, clears ciphertext and is
terminal. It remains available to its authenticated capability after expiry.
Status is read-only. Semantic invalidations inside thirty seconds of the preceding reserved attempt
are durably coalesced across purposes sharing actual host bundle, installation
and APNs environment. A coalesced operation is terminal and spends no send
budget; retrying it later cannot mint a new dispatch or transport lease. Its
tombstone still occupies bounded operation-history space. Unknown or not-sent
reserved attempts count conservatively toward the original send budget.

The entire APNs body is fixed to `{"aps":{"content-available":1}}`. Topic is
the admitted host bundle, push type `background`, priority `5` and transport expiry is no later than thirty seconds from the original
pre-await wake capture or the original wake-purpose expiry. URLs are fixed Apple sandbox or
production hosts; redirects are refused. Final synchronous owner/clock checks
precede the sole call, and cancellation is combined with a bounded timeout.
Provider 410 invalidates only the actual sent generation/revision.

Apple documents that background delivery is discretionary, may be delayed,
coalesced or throttled, and is not a per-track refresh guarantee. A held
notification can be discarded when the app is killed. See [background
updates](https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app)
and [APNs requests](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns).
These limits follow Core's explicit, still-to-review October 31 candidate choice:
`host_app_wake` / `direct_rich_refresh`, original wake purpose at most eight hours
and never beyond the original display deadline, at most sixty-four sends and
thirty-second transport/coalescing bounds. They are not a protected Core contract
pin yet. No client may claim that this wake renews Core permission or original content,
forces local ActivityKit work, or proves artwork/display acceptance.

## Qualification and remaining activation boundary

The dedicated workerd suite uses actual local D1/AES, synthetic original
authority/clock/encryption fixture and a simulated APNs transport. It exercises
restart, competing CAS, unknown/lost replies, rotation/withdrawal/cancellation
across awaits, budgets, strict grammar, expiry and missing supplier controls.
The source package pins its complete inputs and installed esbuild bytes, rejects
drift/unexpected compiled inputs and provides a separate packaged-ESM structural
check. Neither test supplies genuine Core/native authority or calls real APNs.

Joint exact source/contract review, protected source delivery and its separate
Final, real original issuer/enrollment/clock wiring, controlled schema
provisioning, compiled runtime admission, deployment and real provider/device
acceptance are still separate prerequisites. No real principal, signer, native
environment, clock tuple, key custody, root route or operational grant is
invented here. The twenty-two rendezvous operational gates remain unchanged.
No UI or en/nl/de/fr/es translation changes are part of this source slice.
