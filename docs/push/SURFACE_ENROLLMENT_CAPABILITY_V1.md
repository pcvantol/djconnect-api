# Single-use enrollment authorization — closed source preparation

The frozen machine contract is `surface-enrollment-capability-contract-v1.json`.
The new internal `createSurfaceEnrollment` factory implements operator authorize,
operator revoke and one original Core redemption. It does not create a Core
owner, purpose credential, registered target or provider request. The existing
issuer remains responsible for later challenge/issue/status/withdrawal. Ordinary
pairing/admin authentication is not implicit surface consent.

## Original authority and private transfer

The actual privileged API operator must evaluate the original current owner
consent, exact reviewed plan, Core service/custodian generation and complete
enrollment tuple before authorizing. `approval_reference` and `plan_digest` are
comparison/audit fields, not that evaluation. K1 generation and K2/operator
execution remain separate human decisions. Source fixtures are not approvals.

Core receives only one opaque `djce_` credential through a separately qualified
explicit private owner-management action, into the SAME pending consent and
RAM-key attempt. No API operator secret enters Core. No generic purpose JSON,
configuration import, startup factory or pairing shortcut creates authority.
The actual private transfer and concrete Core consent/custodian implementation
are not supplied by this API component. Never publish real credentials, nonces
or household metadata in GitHub inputs, artifacts, job summaries or logs.

## Atomic, hash-only lifecycle

The API stores the credential hash, original request/consent/key/scope digests,
immutable original deadlines and bounded operation state. Credential comparison
uses the existing constant-time digest comparison. The raw random32-byte
credential is returned once to the winning operator request; repeating that
request exposes metadata/unknown only. Nonce and original install/generation/
action have separate durable unique keys. A new authorization/operation ID cannot
remint the same original consent. No cleanup, rotation or automatic repair is
provided.

Core redeems with the exact original enrollment and consent, plus P1363 ES256
proof by that enrollment's SAME P-256 key over the new domain/exact route/payload.
A stolen ticket alone cannot change the request, enroll another key or supply
the required proof. The original grant cannot outlive the original consent.
The ticket expires at the earliest consent/grant/authorization-operation/
enrollment-operation deadline. Existing UUIDv7 five-minute windows, fifteen-minute
trial upper bound and narrow widget budgets do not restart at any await/reply.

One actual D1 batch claims the ticket, writes the existing enrollment ledger and
delegation, and settles the outcomes. SQL failure rolls all of that back. The
claim predicates check the runtime clock and actual SQLite wall time, so queuing
past ticket expiry cannot create the delegation. After body/key/signature
suspension, original deadline/cancellation are rechecked before mutation. An
already committed operation cannot be recalled by cancelling its HTTP reply.
Unknown/lost results therefore remain unknown; callers must not replay or infer
the internal rollback result. A spent credential never returns another success
or another enrollment. No enrollment-status/recovery endpoint is invented; the
old issuer/status is not a live enrollment proof.

Privileged operator ticket revocation has its own fresh bounded operation and
works after ticket expiry without the lost Core key. Early revocation leaves a
tombstone, preventing delayed authorization of that ID. Revoking a ticket does
not withdraw an already enrolled delegation: the existing independently
authorized `issuer/operator/withdraw` remains required. Concurrent redemption
before revocation may already have committed; no broader rollback is promised.

The successful redemption response comes directly from Core's fixed HTTPS call
and binds original authorization/operation/request/consent/key/scope/expiry. It is
not a portable signed approval. Core validates it against its same live original
wall/monotonic consent/custodian context, then applies its final no-await current-
generation fence before constructing an owner. Later issuer/adoption checks must
still reject a delegation withdrawn after that response.

## Public defaults and delivery boundaries

The factory is deliberately not imported, composed or routed by the Worker in
this increment. Existing `SURFACE_PUSH_HTTP_ENABLED=false` reserves every new
path with503 before body/credential/env access; hostile root tests verify it.
Migration0011 is source-only and has not been applied remotely. Existing runtime
composition/provider/Activity source and configuration remain byte-identical.
The separate OIDC proposal is retained locally on branch
`codex/api-surface-operator-result-20261026`, commit `9e5e653`; it is not shipped
alongside this selected path and is not an operational runner.

The expired public vector has a genuine disposable software P-256 signature,
canonical original requests, exact expected response metadata and all scope
digests. Actual workerd verifies its bytes/signature. It contains no private key,
operator credential or issued enrollment credential. Its authorization metadata
explicitly omits the raw credential and is not a complete authorization reply.
Separate current synthetic real-D1 cases exercise winning enrollment, concurrent
mint/consume, wrong proof/scope, early/late revoke, deadline/cancel during crypto,
actual SQLite rollback and SQL-time expiry, collision/unknown/replay and zero
provider traffic. These are local source proofs, not real operator enrollment.

Actual local qualification: the complete Worker suite passes280 cases in9 files,
including42 new enrollment cases. Root and dedicated source/test strict types
pass. The original first migration-fixture read failed before running cases
because the fixture split a semicolon inside a SQL comment; its35 skips/failure
remain in the external evidence root. The comment was corrected before the
35-case successor passed and before expanding to the final42. The initial
ArrayBuffer/type-project setup failures are retained separately as failures.

The standard Worker suite runs these controls; a dedicated strict type project
checks the actual source/test/fixture graph in existing CI without new secrets
or OIDC permissions. Exact independent contract/whole-source review, protected
Source/original own-main CI and separate Final qualification are still required.
Composing the reviewed factory into the closed owning service is a later exact
source/provenance join, followed by separately admitted deployment/configuration.
None of this is public activation, provider/native acceptance or Help CI action.

Core can implement its concrete private consent/custodian manager and exact
one-HTTPS-call response decoder against the frozen contract/vector. Apple can
independently qualify actual installed widget target/signing/environment/token
and original credential/read/revoke lifecycle. Widget authorization remains
`activity_profile=null`, external-content false; real Activity Attributes/
ContentState/date/update/end/stale/dismiss/locked-display and provider rights
need their separate exact Apple/Core/API admission. No v3 reimplementation or
Activity right is inferred from this widget enrollment source.
