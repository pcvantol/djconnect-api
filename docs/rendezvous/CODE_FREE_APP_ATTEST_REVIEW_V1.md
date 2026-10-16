# Code-free rendezvous / App Attest design assessment

Assignment `DJC-API-VIBECAST-RENDEZVOUS-V1-20261016`; revision `0.2.0-draft`.
**REVIEW_CANDIDATE / NOT_FROZEN / NO_RUNTIME_GO**.
This refines [API94](https://github.com/pcvantol/djconnect-api/pull/94), retaining
the sole API writer and unchanged APNs/D1/operator/runtime configuration.

## Authority and fresh continuation

Owner explicitly selected QR -> already paired iPhone chooses/confirms existing
HA external URL -> TV top-level navigation -> existing HA six-digit admission.
No additional TV secret, comparison code, PAKE, account or new pairing is allowed.
Authoritative corrections: [API90/6224544182](https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6224544182)
and [API90/6224667994](https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6224667994).
Fresh readback: remote main `3bb5f2b01401827e8a1072e1668fbb4a2223f26f`, own clean
branch `codex/vibecast-rendezvous-v1-contract` at `cf85081c`; one worktree,
no competing visible API process/chat or source change. Core1197 current pin
`da9a08c0968fc914a9b1d1cf99ccff075cc78aa6` is still draft, not a delivered route.

## Proposed trust claim and explicit exclusions

App Attest is a candidate trusted Apple root for **app-instance authenticity**.
The iPhone uses existing paired transport to check the chosen installation and
its configured route, rechecking after awaits and immediately before release.
The Worker receives no HA device bearer, Profile token, Session grant or relay
install token. It never contacts HA to test the pairing.

If selected, the exact defensible central claim is: "the configured genuine
DJConnect app key signed this transaction-bound request; the app reports it
validated and explicitly confirmed this paired route." That is **not** an
independent central cryptographic verification of HA ownership, physical TV
presence or the TV user's identity. A real app with its own different paired HA
can obtain app-valid assertions. A stolen QR may allow that app to win the first
submission race. B's later six digits do not repair phishing to a wrong A origin.

| Threat | Available control | Remaining decision |
| --- | --- | --- |
| Arbitrary script or counterfeit app submits URL | Verified App Attest identity, fresh payload-bound assertion | Exact verifier/library and supported-device policy |
| Genuine different owner scans copied QR | Short secret QR, one accepted submission, explicit iPhone route confirmation | Cannot identify intended TV owner from those facts; independent risk disposition required |
| Destination changed after confirmation | Sign exact ciphertext/context; browser checks decrypted context and raw URL | App Attest attests app request, not HA pairing semantics |
| Malicious/compromised relay or code host | TLS, browser claim/key binding, minimum exposure | No independent TV root for selected HA; trust scope must explicitly include service/code host |
| Pairing revoked during flow | Core/Apple current-authority checks before release | Already disclosed destination cannot be recalled; B checks current authority |
| Later proxy redirects/phishing | Authenticated strict initial URL; selected HA direct200 configuration tests | No bootstrap containment of later HTTP/scripts/service workers |

The alternative stronger claim needs a QR-bound HA issuer whose verification
root the API/TV already trusts. Self-supplied HA JWKs and present APNs/bootstrap
proofs do not establish it. No such root is delivered. Do not build a central
paired-owner registry to manufacture one. Owner's no-extra-code decision does
not itself accept the residual risks above or authorize weakening TRUST-1.

## Concrete candidate exchange for joint review

1. Browser creates fresh 256-bit claim secret and an ephemeral encryption key.
   API creates the temporary transaction with an immutable120s deadline. QR is
   an opaque lookup/redeem capability bound to version, browser key/generation
   and deadline; no destination, claim secret or credentials.
2. iPhone validates service identity, retrieves that exact transaction context,
   explicitly chooses/confirms a currently paired installation and validates
   its existing canonical external HTTPS route through ordinary HA transport.
3. iPhone encrypts only the destination and exact context to the browser key.
   A standard JWE profile/library must be selected and interoperably tested;
   no raw custom ECDH/KDF/nonce construction. App Attest does not encrypt it.
4. New `POST /v1/rendezvous/submit-challenge` binds a fresh one-time nonce to
   transaction, generation, browser-key thumbprint, original expiry, action,
   attested key ID and digest of the exact serialized envelope. No reservation
   of the winner occurs merely by asking for a challenge. Bound challenge count
   and verification cost per transaction/key/IP/global admission budget.
5. Apple rechecks selected pairing/generation/consent and calls App Attest to
   assert the exact request bytes. The proposed `clientData` must include every
   field above plus fixed protocol/service identity and challenge ID/nonce.
   Canonical serialization is a joint wire-review item, not implicit JSON order.
6. API verifies configured app identity/environment, attested key and assertion,
   exact clientData/challenge/context, fresh counter and unexpired transaction.
   Only the first fully valid submission commits ready. Invalid attempts cannot
   lock in a destination; no "first challenge wins" authority rule.
7. Browser alone consumes once, decrypts and checks original context/expiry plus
   the authenticated raw URL. It then navigates to exactly that initial URL.
   API ready, consumed or navigation initiated never means HA admitted.

Candidate extra fields: submit-challenge request `envelope_digest,key_id`;
response `challenge_id,challenge,expires_at`; submit adds `challenge_id,assertion`.
The server must obtain verified key evidence through a separately reviewed
attestation lifecycle; an arbitrary submitted public key is rejected.
This is an endpoint sketch. Exact JSON schemas, byte framing, limits, key lifecycle
and crypto vectors are not frozen and no consumer should implement against it.

## App Attest server verification and implementation feasibility

Apple's [server validation specification](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
requires server challenges, Apple-root certificate validation, attestation
nonce/key-ID/app-ID/environment checks and assertion signature/counter checks.
Strict CBOR/DER parsing and bounded lengths apply before expensive verification.
Use actual configured App ID prefix and bundle identity, not an assumed Team ID
or client-declared production setting. Keep development/production keys separate.
The challenge match belongs to our application, even if a library verifies the
signature. Never treat a library's signature-only success as submit approval.

Current Apple [WWDC26 guidance](https://developer.apple.com/videos/play/wwdc2026/201/)
also describes new validation-category and bundle-version signals. Pin applicable
OS/distribution policy and fixtures; do not assume an older verifier handles
those extensions. App Attest availability is checked through `isSupported`;
do not claim all Macs are categorically unsupported. No unsupported device,
attestation outage or unknown key falls back to unauthenticated submission.

Workers already uses `nodejs_compat`. Its
[Node crypto API](https://developers.cloudflare.com/workers/runtime-apis/nodejs/crypto/)
provides a plausible implementation surface; no workerd compatibility, certificate
path-validation completeness or CPU/memory result has yet been measured here.

Concrete verifier inspected: `uebelack/node-app-attest`, package1.0.1 at
`f16c4bb71b737466872bc8b8a7dfd215364eaa83` (MIT; not archived; last push
2026-03-16). It uses Node crypto/X509, CBOR, ASN.1 and PKI dependencies.
This is an investigation candidate, **not selected or independently audited**.
Source-review questions include complete certificate validity/path constraints,
strict single-object CBOR handling, unsigned counter parsing, current Apple
extensions and caller-side challenge checks. These are qualification questions,
not a claim of an exploitable vendor vulnerability.

No installation or dependency change was made. Exact worker/native fixtures,
Apple validation-guide cases, independent implementation comparison and review
are required before choosing or fixing a verifier. Do not copy example logging
of requests/attestation bodies or its development-allow setting into production.

## State ownership and the unresolved privacy/lifecycle decision

The Apple guidance expects server-side public-key and last-counter state. It is
not enough to store only a transaction-local counter and forget it at QR expiry
while continuing to accept the same reusable device key. Fresh challenges help
replay protection but do not implement monotonic cross-transaction counters.

Required state would be a pseudonymous app-key security record: verified public
key, key ID, environment, app policy, highest accepted counter and lifecycle
status. No HA URL, owner/Profile/Session identity or pairing mapping belongs in
it. Even without a user name it is a linkable device identifier and requires
explicit privacy/retention review; it is not anonymous transient transaction data.

**Do not add it silently to D1 or to an enduring DO registry.** The assignment
forbids permanent central user-data storage. Key/counter retention duration,
deletion/recovery, re-attestation and App Attest key-generation cadence must be
jointly resolved before this candidate is runnable. Neither a new key for every
QR nor a stateless re-enrollment ticket is a qualified workaround. No exact
retention duration or new identity service is selected by this draft.

Cross-object atomicity is another concrete design requirement. An attested-key
coordinator would serialize the counter update while a transaction DO owns
the first accepted envelope. Workers/DOs do not supply one transaction across
those objects. A reviewed fail-closed design could burn a counter on an ambiguous
submit, then require a fresh assertion; it must not advance ready without valid
counter authorization. Define crash/lost-reply/retry ordering before code.
Also serialize assertions on the app per key so network reordering does not
become an accidental downgrade or unexplained cross-device acceptance.

App attest keys are separate from browser encryption keys. Apple describes
device/install-bound keys and reinstall/restore invalidation in its
[app-integrity guidance](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity).
No HA pairing is created by re-enrolling such a key. Account association, receipt
fraud-metric requests and Apple server-side credentials are not implicitly
authorized; no existing APNs signing secret is reused.

## Route, privacy and errors

Adopt Core da9a08c's proposed exact raw-route corpus for joint review:
canonical HTTPS ASCII non-IDNA DNS, implicit443, exact
`/djconnect/vibecast/display`, no query/fragment/userinfo/percent encoding,
backslash/dot aliases/IP/trailing slash. Parse only after raw validation.
The destination in the encrypted envelope must match the confirmed HA route;
API cannot independently inspect the plaintext. A destination digest can leak
guessable information and is not anonymization; prefer the ciphertext digest
in central clientData and keep plaintext route/installation context encrypted.

Service origins are fixed and native calls require proof; missing Origin is not
authentication. Browser CORS stays exact. No tokens, key IDs, assertion/cert
bodies, QR values, destinations, install IDs or counters in application logs.
Provider metadata and retention are separately qualified. Rate-limit registration
as well as assertions before spending certificate-verification work.

Proposed fixed errors add `attestation_required`, `attestation_unavailable`,
`app_not_supported` and generic `invalid_sender_proof`. Do not expose internal
chain/counter/parser failure details. Unknown or invalid key fails closed.
Retry only within original deadline; explicit restart after expiry/cancel/lost
consume. Existing en/nl/de/fr/es errors need native/receiver review.

## Required evidence and decision exits

No App Attest, ciphertext or HA E2E vectors were fabricated in this checkpoint.
The existing regression suite qualifies only unchanged API behavior.

| Gate | Required outcome before implementation |
| --- | --- |
| TRUST-1 | Joint disposition of app-reported paired route versus independent HA-owner verification, including genuine wrong-owner scan and malicious relay |
| TRUST-2 | Exact verified App Attest parser/verifier and JWE library/profile, pinned compatibility, independent positive/negative crypto vectors |
| KEY-STATE | Privacy-approved nonpermanent key/counter lifecycle and crash-safe ownership/retry semantics |
| WIRE-1 | Exact code-free scanner/clientData/request schemas and error/failure UX acknowledged by Apple/receiver |
| ROUTE-1 | Initial-route trust handoff adopted; actual selected HA/proxy/direct200/redirect/error behavior qualified in its owning lane |
| Independent review | Technical/security/privacy and product/UX review of exact revised candidate and disposition of every finding |

Cases must include bad/untrusted/expired certificates, wrong app/env/category,
malformed/trailing CBOR, wrong nonce/digest/generation/browser key, equal/lower
counter, parallel submissions across two transactions for one key, crash between
counter authorization and envelope commit, cancelled/expired challenge, genuine
different paired scanner, unsupported app/device, Apple outage and post-navigation
redirect/login errors. Synthetic fixtures are not actual Apple-device acceptance.

The original stronger claim is not marked delivered merely by selecting the
code-free UX. Runtime, contractfreeze, protected product merge, Finalization,
Cloudflare changes, live rendezvous and joint Apple/HA/TV acceptance remain open.

## Inspected implementation sources

- [Verifier package at exact pin](https://github.com/uebelack/node-app-attest/blob/f16c4bb71b737466872bc8b8a7dfd215364eaa83/package.json)
- [Attestation implementation](https://github.com/uebelack/node-app-attest/blob/f16c4bb71b737466872bc8b8a7dfd215364eaa83/src/verifyAttestation.js)
- [Assertion implementation](https://github.com/uebelack/node-app-attest/blob/f16c4bb71b737466872bc8b8a7dfd215364eaa83/src/verifyAssertion.js)

Sources checked 2026-10-16. No external implementation was installed or executed.
