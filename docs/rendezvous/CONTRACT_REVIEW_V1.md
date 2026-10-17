# VibeCast rendezvous v1 — pre-implementation review candidate

Assignment: `DJC-API-VIBECAST-RENDEZVOUS-V1-20261016`.
Document revision: `0.4.0-draft`; proposed wire version: `djc-rendezvous/1`.
Status: **BLOCKED_CONTRACT_REVIEW**. No endpoint below exists yet. This is
a decision package, not a frozen consumer contract or a production manifest.

Revision0.3 reconciles the resolved limited-A owner choice and current Core
producer6e560061. [KEY-STATE](KEY_STATE_V1.md) now proposes exact finite retention,
recovery and counter/transaction crash ordering; [WIRE profile](WIRE_PROFILE_V1.md)
defines exact request/clientData/JWE candidates and interoperability gates.
Those documents supersede the older sketches below where they refine fields,
limits, lifecycles or owner-choice status. They remain joint-review candidates.

Revision0.4 incorporates Apple's producer-reported Mac/Chromium evidence and
specific enrollment-timeout finding in [bounded recovery](ENROLLMENT_RECOVERY_V1.md).
It adds a fresh action-separated recover-key proof, original-deadline receipts,
paused repair rather than key-generation loops, and structural schemas/examples.
Actual app-bound diagnostic fixtures have now been independently processed in
[offline qualification](GENUINE_APP_ATTEST_QUALIFICATION_V1.md). Action-specific
wire fixtures, strict path/verifier and receipt storage policy remain open. No
runtime or frozen contract follows from these results.

Receiver16/6241859224 now delivers isolated Mac/browser profile-oracle evidence.
[API's requested software JWE generator](JWE_VECTOR_GENERATOR_V1.md) is implemented
with52 local cases and scoped reviews. This resolves the missing producer tool,
not concrete crossrun, actual signed-iOS action binding, full verifier/action
composition or joint freeze. Do not request stale ephemeral keys in comments.

## Current owner correction and route disposition

Owner decisions [6224544182](https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6224544182)
and [6224667994](https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6224667994)
supersede the comparison/OOB proposals in revision0.1.0. Route A is a QR shortcut
for the already paired iPhone's explicitly selected existing external HA URL.
No additional TV code, PAKE secret, mandatory comparison, account or pairing.
Only the existing separate HA six-digit display admission follows navigation.
Magic Wormhole/PAKE is not selected for v1; its transport feasibility research
does not authorize extra TV input or a mailbox implementation.

The [code-free App Attest review](CODE_FREE_APP_ATTEST_REVIEW_V1.md) supplies the
current concrete candidate, remaining claims, state/privacy conflict and release
gates. App authenticity and HA-owner/installation authenticity remain different.
The subsequent explicit limited-A disposition API94/6226306251 has been read
back from the original human exchange. The product choice is resolved; runtime
still needs technical qualification of that precisely limited claim.

API design acknowledges Core ROUTE-1 at exact
`da9a08c0968fc914a9b1d1cf99ccff075cc78aa6`: independently authenticate the initial
raw HTTPS route/context; navigate top-level; thereafter selected HA and its
configured reverse proxy form the execution trust boundary. Direct200 without
login/redirect is a measured configuration requirement, not a JS redirect fence.
No iframe or central HA fetch/proxy. This acknowledges that direction, not a
frozen or implemented Core/API/Apple/receiver contract.

## Authority and admission

- [Owner assignment](https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6222362850).
- [Executor ACK](https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6222484621).
- Fresh remote baseline: `3bb5f2b01401827e8a1072e1668fbb4a2223f26f`.
- Core design predecessor: `f32b625eb0a3d1b8abfc2c81378d25d769c6766d`,
  `docs/product/VIBECAST_ONBOARDING_GUEST_AUTHORITY_V1.md` and
  `docs/product/VIBECAST_WEB_ENTRY_DISTRIBUTION_V1.md`.
- Receiver public-web Finalization: `fe0916f53f76cb8468d33d91e533be4226be673d`.
- One clean local API worktree; no other visible API writer, open API PR or
  Git lock at admission. Existing Core/Apple writers retain their assignments.

The canonical trust predecessor explicitly requires crypto, origin-bound
bootstrap and denial tests to be independently reviewed before implementation.
The owner assignment additionally requires the exact producer contract to be
aligned before runtime writes. These gates are still open.

## Decisions required to freeze the contract

| ID | Required decision and evidence | Existing owner |
| --- | --- | --- |
| TRUST-1 | Owner-selected limited genuine-app reported route; preserve copied-QR risk and reject stronger owner claims | Product choice resolved; technical review open |
| TRUST-2 | Reviewed sender-authenticated encryption profile, library/version, browser/native interoperability and positive/negative cryptographic vectors | API + Apple + receiver, independent security reviewer |
| ROUTE-1 | Direction acknowledged at Core da9a08c; joint raw-URL policy adoption and actual configured HA/proxy qualification remain open | Core + Apple + receiver |
| WIRE-1 | Confirm QR framing, native scanner entry, code-free installation confirmation, error mapping, cancel/rotate and lost-consume behavior | Apple + receiver + Core, independent UX reviewer |
| OPS-1 | Account/plan, namespace admission budget, cost guard, infrastructure logging/retention and reviewed deploy artifact mapping | API/operator before deployment |

### Why TRUST-1 blocks runtime

A fresh TV browser has no prior relationship with the owner's HA installation.
The QR can bind a browser public key, but anyone who photographs it can encrypt
to that key. An authenticated-encryption tag proves ciphertext integrity, not
that the sender is the selected installation's paired owner. A self-supplied
signing key or installation ID does not establish that relationship either.

The existing pairing bootstrap handler validates request metadata and issues a
push-registration proof. It does not attest an existing Apple/HA owner pairing.
Neither that proof, APNs registration data, an install relay token nor a new
central paired-device registry may be silently repurposed as rendezvous trust.

The current candidate uses Apple App Attest for the genuine app instance and
existing Apple/Core pairing checks for the explicitly selected route. App Attest
does not independently attest HA pairing or that the scanner belongs to the TV's
intended user. The owner-selected limited claim and remaining wrong-owner risk
require technical/security qualification; the stricter independently trusted HA-issuer
alternative has no established root today. No custom ECDH/KDF/AEAD composition,
extra code or encryption-only authentication claim is authorized.

JWE (RFC 7516), JWA (RFC 7518), JWS (RFC 7515) and JWK thumbprints (RFC 7638)
are possible standard building blocks, not a complete solution to TRUST-1.
No algorithm suite, application key distribution or trust claim is frozen.
No fabricated crypto test vectors are supplied before that selection.

## Proposed service isolation

Use the existing `djconnect-api` Worker with a distinct `/v1/rendezvous/`
router, bypassing the existing D1 diagnostic recorder for these requests.
Proposed binding `RENDEZVOUS`, exported class `VibeCastRendezvous`, with one
SQLite-backed Durable Object per server-generated random transaction ID.
No APNs/issuer/operator handler changes, D1 schema changes or HA fetches.
No new repository, user/session backend or receiver website.

Candidate public service origin is `https://api.djconnect.dev`; it is **not**
a live rendezvous claim. No production binding/configuration is changed by
this document. A reviewed explicit enable switch should default to disabled;
missing configuration returns `503 service_unavailable` before state allocation.

## Proposed wire surface

All inputs are JSON objects with `v: "djc-rendezvous/1"`, reject unknown fields,
duplicate JSON keys, malformed UTF-8 and noncanonical identifiers. Integers are
safe integer Unix milliseconds; deadlines are server-issued. Opaque values
use unpadded base64url, exact lengths and CSPRNG entropy. Schema publication,
field lengths and crypto framing require WIRE-1/TRUST-2 before wire freeze.

| Operation | Proposed method/path | Input besides version | Successful output |
| --- | --- | --- | --- |
| Create | POST `/v1/rendezvous/create` | `generation`, `browser_public_key`, `claim_commitment` | 201: `transaction_id`, `generation`, `created_at`, `expires_at`, `qr_payload` |
| Poll/reconnect | POST `/v1/rendezvous/poll` | `transaction_id`, `generation`, `claim_secret` | 200: `state`, `expires_at`, `retry_after_ms`; no destination envelope |
| Submit challenge | POST `/v1/rendezvous/submit-challenge` | `transaction_id`, `generation`, `qr_capability`, `envelope_digest`, `key_id` | 200: one-time `challenge_id`, `challenge`, `client_data`, original `expires_at` |
| Submit | POST `/v1/rendezvous/submit` | `transaction_id`, `generation`, `qr_capability`, `destination_envelope`, `challenge_id`, `key_id`, `client_data`, App Attest `assertion` | 202: `accepted: true`, operation_id; no browser secret |
| Consume | POST `/v1/rendezvous/consume` | `transaction_id`, `generation`, `claim_secret` | 200: `state: consumed`, `destination_envelope`, `expires_at` |
| Cancel | POST `/v1/rendezvous/cancel` | `transaction_id`, `generation`, `claim_secret` | 200: `state: cancelled` |

Secrets never occur in HTTP paths/query strings. QR framing must keep capability
material out of server request logs, referrers and browser history; the exact
native scanner representation awaits Apple/receiver review. QR carries version,
canonical service identity, transaction ID, original deadline, generation,
browser-key binding and redeem capability; never HA URL, claim secret or bearer.
Strong browser claim secret: 256 random bits generated by the browser, held
only in that window's memory. A commitment is stored, not the raw secret.
Window reload loses authority and starts fresh; another tab never inherits it.

Destination plaintext may contain only approved HTTPS entry URL and binding
context: version, transaction ID, generation, original expiry, browser-key
thumbprint, bootstrap origin, selected installation reference and sender
approval context. Exact signed/encrypted serialization awaits TRUST-1/2.
No HA credentials, Profile token, Session bearer or user profile is allowed.
The service cannot inspect an end-to-end encrypted URL; Apple and the browser
must enforce the same reviewed URL policy. Envelope validity is not HA admission.

## Proposed state and race semantics

`pending -> ready -> consumed`; `pending|ready -> cancelled|expired`.
Only authenticated valid submission can transition pending to ready. First
valid submission wins; subsequent submissions return conflict, never overwrite.
Poll never releases ciphertext. Consume atomically removes ciphertext before
returning it. Two concurrent consumes yield at most one envelope. If that
response is lost, reconnect reports consumed; start a fresh QR rather than
releasing the envelope again. This UX tradeoff requires WIRE-1 review.

Cancel and consume compete within the same storage transaction: whichever
commits first wins. Repeated authenticated cancel on cancelled is idempotent;
cancel after consume returns conflict. Rotation requires confirmed cancellation
of the old generation before a new create; if cancellation is unavailable,
clear local keys and wait until the old absolute deadline before new creation.
No API claims atomicity across different Durable Objects.

Server `created_at + 120000` is the proposed fixed deadline. Every operation
checks the original deadline before mutation and again inside the committing
transaction after cryptographic awaits. Equality with expiry is expired.
Client clocks are advisory. Poll, retry and reconnect never extend expiry.
Use persisted state and transactional compare-and-transition; input-gate
serialization alone is insufficient across asynchronous validation.

An alarm removes payloads/secrets at expiry; request-time deadline checks remain
authoritative if alarm delivery is late. Terminal state retains only capability
commitments and deadline until expiry, then all application rows are deleted.
Missing state always fails closed and never reinitializes through poll/submit.
Unknown IDs must be rejected before allocating durable state where possible.
Physical storage deletion/backup retention must be qualified separately; an
alarm is not a promise of immediate erasure from provider backups.

## Proposed validation and abuse bounds

Browser calls require exact Origin `https://vibecast.tv` and no cookies;
missing, `null`, preview, suffix matches and arbitrary reflected origins fail.
Native submit without Origin requires the reviewed App Attest/request proof; missing
Origin is never authorization. Restrict preflight to specified methods/headers,
emit `Vary: Origin`, never wildcard or credentialed CORS. All responses use
no-store, no-referrer and nosniff. Receiver CSP/connect-src changes remain
receiver-owned and require that lane's artifact qualification.

Proposed application budgets, **not Cloudflare platform limits**:
Endpoint-specific streamed ceilings in WIRE_PROFILE_V1.md,8KiB envelope ceiling,
one in-flight poll per transaction, minimum poll interval 2 seconds, at most
60 polls/transaction, 5 invalid authorized attempts/transaction and 5 creates
per trusted edge IP/minute. Reject compressed request bodies and enforce limits
before expensive crypto/DO allocation. Trust only Cloudflare's connection IP,
not caller-controlled forwarding headers. Hash abuse keys with a rotating
server-side secret; short-lived counters must not become persistent identity.

An exact strongly enforced namespace/global allocation budget and kill switch
remain OPS-1: per-IP limits alone do not bound distributed abuse or spend.
Edge rate-limiter/WAF semantics and concurrency tests need actual config proof;
in-memory Worker counters cannot establish a global hard limit.

URL policy must reject HTTP, userinfo, fragments, unexpected query/port/path,
encoded separators/dot segments, ambiguous IDNA, local/private/link-local/IP
literals and arbitrary redirect parameters. Core's review profile proposes only
canonical public ASCII non-IDNA DNS, implicit443 and exact
`/djconnect/vibecast/display`, without query/fragment/trailing slash. Validate the
original authenticated string before URL normalization; no consumer-side repair.
Its forty lexical cases are not actual DNS/TLS/direct200 qualification. Native
Apple verifies the configured selected installation over its existing pairing;
the Worker never resolves or fetches the destination, checks TLS or probes HA.
A TV navigation or redirect cannot be validated by a central fetch workaround.
Once navigation starts the selected HA/proxy controls subsequent HTTP/content/
service-worker navigation. No downstream-origin containment is promised. Before
handoff bootstrap reports its own failures; afterward browser error UI can appear
before HA loads. Only HA can report its B-admission state.

## Errors and user experience for review

Error object proposal: `{v, error, retry_after_ms?}` with fixed machine codes;
no echoed tokens, IDs, URLs or parser/crypto internals. Detailed authentication
failures coalesce to `401 invalid_capability` without revealing existence.

| HTTP | Code | Consumer action |
| --- | --- | --- |
| 400 | invalid_request / unsupported_version | Explain unsupported connection and restart safely |
| 401 | invalid_capability | Clear local authority, fresh QR |
| 403 | origin_denied | Stop, no alternate-origin fallback |
| 409 | already_submitted / already_consumed / cancelled / not_ready | Respect terminal state; never overwrite/replay |
| 410 | expired | Clear keys, offer fresh QR |
| 413 / 415 | payload_too_large / unsupported_content_type | Stop current attempt |
| 429 | rate_limited | Honor Retry-After within original deadline |
| 503 | service_unavailable | Quiet bounded retry, honest unavailable message |

Consumer-only errors: `owner_pairing_required`, `external_route_missing`,
`installation_mismatch`, `destination_invalid`, `destination_unreachable`,
`browser_unsupported`, `envelope_invalid`. The central API cannot truthfully
report successful HA reachability. Apple checks its existing route; the TV
may still encounter independent DNS/TLS/navigation failure. No HTTP fallback,
manual IP requirement or certificate bypass. The separate Core HA display
confirmation follows only after rendezvous navigation; no Session grant here.

Review screen text in en/nl/de/fr/es. Show selected installation/destination for
explicit owner confirmation on iPhone. Do not add any A-only TV/comparison code.
The later HA six-digit display-admission code is the only code in this flow.
No extra login for an already paired owner. TV unsupported capability state
must replace QR if secure-context/Web Crypto/required algorithm is absent.
Actual WebKit/Chromium/native interop and older TV engines are NOT qualified.

## Privacy and review exits

No request bodies, capabilities, QR data, key material, envelopes, destinations,
installation/device identifiers or IPs in application diagnostics. Fixed route
labels and bounded status/error counters only. Existing generic route logging
must not receive raw transaction paths. Provider ingress metadata, sampling,
retention, access controls and backups need OPS-1 inventory before live traffic.
Central code-host compromise can serve hostile JS; encryption does not hide a
destination from a compromised browser/app or provide anonymity.

Required review receipts: independent technical/security/privacy findings and
resolution on exact candidate SHA; independent product/UX review; Core/Apple/
receiver acknowledgements on exact contract/fixtures. Then freeze schemas and
crypto vectors, implement runtime, execute acceptance matrix, correct findings,
protected PR/merge, separate Finalization and exact producer handoff.

## Standards checked 2026-10-16

- [DO coordination rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/)
- [DO limits](https://developers.cloudflare.com/durable-objects/platform/limits/)
- [Worker limits](https://developers.cloudflare.com/workers/platform/limits/)
- [DO pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)
- [JWE](https://www.rfc-editor.org/rfc/rfc7516), [JWA](https://www.rfc-editor.org/rfc/rfc7518)

Sources describe platform mechanisms and standards, not account entitlement,
capacity measurements, protocol review or deployment authorization.
