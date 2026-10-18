# DJConnect API Handoff

## Active assignment — VibeCast rendezvous (2026-10-18)

`DJC-API-VIBECAST-RENDEZVOUS-V1-20261016` is owner-selected; execution ACK:
https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6222484621.
One admitted API writer, fresh baseline
`3bb5f2b01401827e8a1072e1668fbb4a2223f26f`.

Status: **BLOCKED_CONTRACT_REVIEW before runtime implementation**. The
[review candidate](docs/rendezvous/CONTRACT_REVIEW_V1.md) names the unresolved
finite key/counter lifecycle, exact verifier/wire/crypto interoperability and
qualification of the explicitly limited paired-app reported route. The canonical predecessor requires independent design
review before implementation; these are substantive security decisions.
[Qualification/deployment preparation](docs/rendezvous/QUALIFICATION_AND_DEPLOYMENT_V1.md)
records the required scenarios and deployment/rollback boundaries. Revision
`0.4.0-draft` incorporates the owner's code-free route-A correction and API's
acknowledgement of Core ROUTE-1 `da9a08c`. The
[App Attest design assessment](docs/rendezvous/CODE_FREE_APP_ATTEST_REVIEW_V1.md)
records actual app-authenticity limits, paired-route trust, replay-state/privacy
decisions and verifier qualification. No extra PAKE/comparison/TV code is selected.
The owner limited-A choice is resolved at API94/6226306251; the original human
exchange was independently read. Do not repeat that question.
[KEY-STATE](docs/rendezvous/KEY_STATE_V1.md) and
[wire/profile](docs/rendezvous/WIRE_PROFILE_V1.md) specify the new finite-state,
crash/replay, request/clientData and JWE review candidate. None is a frozen
consumer wire contract or production configuration.

[Transaction qualification design](docs/rendezvous/TRANSACTION_QUALIFICATION_DESIGN_V1.md)
records the next API-owned state boundary and independent scoped design reviews,
not an implemented transaction DO. Review corrected terminal recovery: a consumed
transaction may start a fresh QR after authenticated status without impossible
cancel-after-consume. Live pending/ready rotation still requires confirmed cancel;
unknown outcome waits for original expiry. No qualified reusable server JWE parser
is claimed by that design. Public runtime remains behind the joint exact contract/security gate.

Protected source PR94 merged to `e67f402b5f9d1a3099850dd2f6d9edd42a004aa0`;
candidate/main tree equality and all six post-merge workflows were verified,
including artifact and POST_MERGE_RELEASE_EVIDENCE_QUALIFIED. That closes the
source increment, not the assignment or separate Finalization/deployment.
[Local framing qualification](docs/rendezvous/WORKER_FRAMING_QUALIFICATION_V1.md)
adds92 actual workerd cases+isolated TypeScript for closed JWE/header/JWK shapes,
exact-byte digest and copied thumbprint input. Structurally accepted ciphertext
can still be cryptographically invalid; no AEAD/plaintext/sender or transaction
acceptance is inferred. API retains state/controller/admission implementation.

[Local transaction composition](docs/rendezvous/WORKER_TRANSACTION_QUALIFICATION_V1.md)
now adds322 actual workerd cases+strict types:93 transaction,92 framing and137
public registration/storage/assertion cases. Actual software assertions/counters,
private coordinator lease and SQLite winner/consume/cancel compose with standard
JOSE encryption/decryption; initial enrollment remains explicitly software.
Immutable120s allocator descriptors/object binding, purge/restart replay, races,
counter burns and historical retries are tested. Public immutable allocator/
controller/global admission and genuine native/fullservice proof remain open;
this does not make the deployment/service ready. Product bindings/config unchanged.

[Local HTTP and allocation-budget qualification](docs/rendezvous/WORKER_INGRESS_QUALIFICATION_V1.md)
adds265 actual workerd cases+strict types: eleven bounded/versioned POST routes,
closed requests/responses, exact Origin/CORS, streamed limits and a private atomic
10,000/day transaction /500/day key /5-per-IP-minute allocation policy candidate.
Default harness remains disabled; enabled dispatcher responses are transport QA.
Additional raw JSON syntax restrictions are proposed, not frozen consumer wire.
This does not qualify full public controller/unknown-ID allocation coverage,
trusted edge IP provenance, complete abuse/cost containment or production.
API retains that integration and operational work; consumer boundaries remain.

The0.3.0 supplied-text technical/privacy and UX design reviews returned GO after
twoP2 corrections; these do not constitute implementation or live qualification.
[Verifier investigation](docs/rendezvous/VERIFIER_REFERENCE_AUDIT_V1.md) adds15
synthetic observations on two Node runtimes; the unmodified reference is rejected
for runtime. Full certificate/CBOR validation, current extension/receipt policy
and native interop remain concrete open gates.
Receiver profile0.4 consumer ACK is delivered (API94/6231693523; receiver16/6233688083);
unchanged browser wire retains that bounded ACK. Existing Core/Apple/receiver
owners retain their owned interop/acceptance; API qualifies the full verifier.
[Enrollment recovery](docs/rendezvous/ENROLLMENT_RECOVERY_V1.md) incorporates
Apple's reported Mac/Chromium checks and physical capability-only readback,
and defines bounded uncertain-registration recovery without a key-generation
loop. Apple has now delivered actual app-bound development fixtures and ACK0.4.
[Genuine fixture qualification](docs/rendezvous/GENUINE_APP_ATTEST_QUALIFICATION_V1.md)
records independently executed141 offline observations plus12 parser controls,
two attestations/ten real assertions, nonce/key/receipt binding, SDK31-byte
input behavior and preserved failed native assumption. Strict OpenSSL path mode
rejects missing leaf AKI while standard validation passes. The subsequent
[leaf-AKI policy](docs/rendezvous/LEAF_AKI_POLICY_V1.md) has independent policy GO
and16 executed strict OpenSSL cases: one leaf-only exception, all other errors
fatal, fixed root/exact chain, context-local state. This specific design blocker
is resolved. [Local workerd path qualification](docs/rendezvous/WORKER_PATH_QUALIFICATION_V1.md)
now executes a closed PKIJS3.4.1/ASN1js3.1.0 candidate:72 private-fixture /56
public-only tests PASS. One independent P2 (non-CA leaf path length) corrected
and re-reviewed; scoped path and UX/privacy GO. Full PKI/CMS/composed verifier,
revocation/receipt production policy and actual runtime remain open; no product
imports/dependencies or public service added.
[Core workerd qualification](docs/rendezvous/WORKER_CORE_QUALIFICATION_V1.md)
now adds93 private-fixture /44 public-only tests for original raw Apple proof
binding/signatures and strict parser/counter predicates. An actual public DER
failure was corrected with explicit short headers and a regression below the
payload ceiling; failed history is retained. Receipt is still UNVERIFIED in
that candidate. [Finite initial-receipt policy](docs/rendezvous/INITIAL_RECEIPT_POLICY_V1.md)
has scoped proposal reviews GO. [Receipt workerd qualification](docs/rendezvous/WORKER_RECEIPT_QUALIFICATION_V1.md)
now adds83 private-fixture /44 public-only actual CMS/signature/path/field tests,
including real Apple BER/unsorted authenticated payload and strict freshness
denial. Diagnostic revocation bypass is explicit, NO_ENROLLMENT; full status
policy/key operations/composed-verifier review remain required.
[Local SQLite receipt storage](docs/rendezvous/WORKER_STORAGE_QUALIFICATION_V1.md)
now has39 actual DO tests+isolated types PASS. CleanupP2 fixed by confirmed
alarm before sensitive commit, including no-client-retry tests; scoped storage GO.
[Revocation policy candidate](docs/rendezvous/REVOCATION_POLICY_CANDIDATE_V1.md)
has corrected scoped policy GO: explicit offline pinned App Attest profile and
hard-fail receipt status direction. [Common certificate status qualification](docs/rendezvous/WORKER_STATUS_QUALIFICATION_V1.md)
now adds68 actual local workerd/34 public-only OCSP/CRL cases, exact tuple
nonrenewing cache and separately verified common Apple status responses. CRL-entry
extensionP2 corrected and scoped component GO. [Fixed status egress](docs/rendezvous/WORKER_STATUS_EGRESS_QUALIFICATION_V1.md)
now adds101/35 local cases including4s timeouts/64KiB streams/2s attempt bounds,
with corrected tuple-concurrencyP2 and scoped egress GO. Mock-adapter proof is
not fresh live/provider proof. Production egress/cache/propagation/
operator proof and full verifier/action composition remain gates. No public enrollment. Archived receipts now fail freshness; no old proof is enrollable. Supplied-text
technical/security and UX/privacy reviews GO for this evidence scope only.
Receiver16/6241859224 now reports actual isolated Mac JOSESwift3.0.0↔Chromium/
WebKit jose6.2.12 with28 profile-oracle denials; no signed-iOS or production-parser
GO. The requested [API public-input JWE generator](docs/rendezvous/JWE_VECTOR_GENERATOR_V1.md)
is now implemented with52 Node/CLI tests and scoped reviews GO, exact pinned
artifact, reserved synthetic destinations and no private-key transfer/storage.
Existing receiver owner can invoke it synchronously while its nonextractable
browser key is alive; no stale public-key comment or new device capture required.
[Concrete generator crossrun](docs/rendezvous/RECEIVER_GENERATOR_CROSSRUN_INTAKE_V1.md)
is now delivered by receiver16/6244059388: Chromium/WebKit,48 combined denials.
API read receipt/artifact hashes; no independent reexecution. Actual signed-iOS/
full action/service gates remain; no repeat of the unchanged generator test.
[Local assertion/key-state composition](docs/rendezvous/WORKER_ASSERTION_STATE_QUALIFICATION_V1.md)
now adds75 actual SQLiteDO+types/73 public-only cases:39 storage regressions,
34 software-signed action/state cases and2 optional genuine diagnostic signatures.
Exact saved clientData, nonce/counter/receipt atomic commit, current-policy/key
rechecks, fixed5s internal leases, bounded unknown-key challenges and finite cleanup
are exercised. Trusted fixture enrollment and diagnostic SQL seeds are explicit;
no new native-wire/enrollment/transaction-DO/private-RPC/global-admission GO.
Independent supplied-design/implementation GO is supplemented by full supplied
coordinator/store/test text review at9e9a76f, no P1/P2; reviewer did not independently
read Git or run tests. UX reviewer read both exact qualification/wire documents.
No full enrollment/runtime security approval. Exact9e9a76f CI13SUCCESS/1cleanupSKIP.
[Local composed enrollment evidence](docs/rendezvous/WORKER_ENROLLMENT_EVIDENCE_QUALIFICATION_V1.md)
now adds95/87 workerd cases plus a typed declaration consumer: default exactnonce32,
core->freshCMS->authenticated common issuerCRL/signerOCSP, original policy/challenge,
path/status/receipt deadlines checked across awaits. Positive orchestration uses
explicit software stubs; eight old diagnostic tests do not prove fresh enrollment.
Core93/CMS83/API40 regressions pass after internal authenticated metadata additions.
No atomic registration, private RPC, fresh genuine positive or public runtime GO.
[Local atomic registration/private facade](docs/rendezvous/WORKER_REGISTRATION_QUALIFICATION_V1.md)
now adds141/137 actual workerd cases+isolated TypeScript, including all75/73 prior
storage/assertion regressions. Key/ciphertext and original nonce consumption share
one SQL commit, with immutable retries, current/original policy guards and finite
cleanup. Actual RPC denies20 helper methods/four private properties. Initial
positive enrollment uses a separately constructed software fixture; default real
verifier rejects fake/old proofs. No fresh genuine/native or global routing/
admission/transaction/public-runtime GO. Scoped independent source/design and
UX/privacy reviews GO;40 API regressions/roottypes/projection PASS.
No new lanewriters or cross-repository source writes. Runtime, public wire vectors,
new-service CI/E2E, protected product merge and separate Finalization remain
pending. Production deployment remains separately unauthorized. The existing
APNs/D1/operator runtime is unchanged; historical state below is retained.

## Current State

- Repository: `pcvantol/djconnect-api`.
- Runtime: Cloudflare Worker.
- Current release: `1.0.14`.
- Purpose: central APNs push relay for DJConnect Apple clients.
- Public API target: `https://api.djconnect.dev`.
- D1 database: `djconnect_api`.
- D1 binding: `DB`.
- Worker source: `src/`.
- D1 migrations: `migrations/`.

This repository is intended to be public/open-source. Treat all code, docs,
tests and fixtures as public material.

## Cross-Repo Source Of Truth

Do not copy these files into this repository:

- `/Users/pcvantol/Documents/GitHub/djconnect/SYNC_PROMPTS.md`
- `/Users/pcvantol/Documents/GitHub/djconnect/API_CONTRACT.md`
- `/Users/pcvantol/Documents/GitHub/djconnect/PRODUCT_ROADMAP.md`

The Home Assistant integration remains the source of truth for client-facing HA
API contracts. This API repository owns only the central relay API surface under
`/v1/push/*`.

## Architecture

```text
Home Assistant DJConnect integration
  -> authenticated privacy-safe relay event
  -> DJConnect API Worker
  -> D1 registration lookup/audit
  -> APNs provider-token authenticated push
  -> iOS/macOS/watchOS client opens
  -> client syncs with its own Home Assistant instance
```

The APNs private key stays only in Cloudflare secrets/configuration. Home
Assistant, HACS integrations and clients must never receive the APNs provider
private key.

## Endpoint Contract

Public health:

- `GET /health`

Relay endpoints:

- `POST /v1/install/token`
- `POST /v1/install/rotate`
- `POST /v1/push/register`
- `POST /v1/push/unregister`
- `POST /v1/push/event`

Admin endpoints:

- `GET /v1/admin/registrations`

`POST /v1/install/bootstrap-proof` requires bootstrap/operator auth using
`DJCONNECT_RELAY_SECRET` through bearer auth or HMAC signature and returns a
short-lived one-time `djcboot_...` proof for an existing pairing context.
Public Home Assistant/HACS installations must not receive that bootstrap
secret.

`POST /v1/pairing/bootstrap-proof` is the trusted Apple pairing issuer
endpoint. It does not require Apple apps to embed backend secrets; it validates
known DJConnect Apple bundle IDs, matching client types, a non-empty
`pairing_session_id`, push environment and stable Apple client device IDs, then
returns a central-issued one-time proof for the Apple client to pass to HA
during push registration. Apple clients and HA/HACS must not receive relay,
pairing issuer or APNs provider secrets.

`POST /v1/install/token` is proof-only. It consumes a valid `djcboot_...` proof
previously issued/registered by the central API, bound to `ha_install_id`,
`client_type` and `device_id`, then returns a per-install `djci_...` token.
Locally generated HA or Apple client proofs are rejected. Proofs are stored
hashed and consumption is rate-limited by hashed IP/install/device keys in D1.

`/v1/push/*` and `/v1/install/rotate` require a per-install `djci_...` token
scoped to the request `ha_install_id`.

`GET /v1/admin/registrations` requires bootstrap/operator auth, rejects
per-install tokens and returns only privacy-safe metadata for the admin website.

The Home Assistant/HACS side now handles per-install token provisioning
automatically during setup. It creates/persists `ha_install_id`, obtains a
`djci_...` token, stores it in Home Assistant config entry options and uses it
as bearer auth for central calls. Manual token/API URL controls are support-only
override/rotation tools, not the normal user flow.
The admin website must use this endpoint rather than reading D1 directly.

## Privacy Boundaries

The Worker must not log, store or relay:

- Raw prompts.
- Raw assistant responses.
- Full chat history.
- DJ Memory.
- Home Assistant tokens.
- Spotify tokens.
- APNs provider private key.
- Relay secret.
- Production user, device or install identifiers in tests/fixtures.
- Raw production install IDs or device IDs in admin responses.

APNs payloads are generic wake/sync hints. Clients must always sync through
their own Home Assistant instance after opening, especially
`/api/djconnect/ask_dj/history`.

## Current Decisions

- D1 stores `apns_token_hash` for lookup/audit and encrypted APNs token
  material for relay delivery. The nullable `apns_token` column remains only as
  a legacy migration fallback for old rows.
- `OPERATOR_RUNBOOK.md` documents the APNs token encryption key rotation and
  backfill procedure. The current Worker runtime still uses one active
  `APNS_TOKEN_ENCRYPTION_KEY`; planned zero-downtime rotation requires a
  temporary dual-key/backfill implementation before replacing the secret.
- APNs endpoint selection is per registration: sandbox or production.
- `BadDeviceToken`, `Unregistered` and HTTP 410 mark a registration
  disabled/invalid.
- Audit rows are intentionally minimal and do not contain prompts, responses,
  secrets or full history.
- Per-install relay tokens are stored only as SHA-256 hashes in D1.
- Tests use example fixture values only.

## Historical Validation Notes

Initial `v1.0.0` validation passed:

- `npx wrangler types`
- `npx tsc --noEmit`
- `npm test`
- `npx wrangler d1 migrations apply djconnect_api --local`
- Public repository secret scan

Initial `v1.0.0` release validation was previously blocked by external
Cloudflare auth:

- Remote D1 migration returned account authorization error `7403`.
- Worker deploy returned Wrangler authentication error `10000`.

These blockers are resolved as of `v1.0.2`; the explicit production deployment
workflow can deploy a qualified internal-release candidate successfully.

## Cloudflare And CI/CD Status

Cloudflare production setup is active:

- `APNS_PRIVATE_KEY` is installed as a Cloudflare Worker secret.
- `DJCONNECT_RELAY_SECRET` is installed as a Cloudflare Worker secret.
- `DJCONNECT_PAIRING_ISSUER_SECRET` must be installed as a Cloudflare Worker
  secret before the trusted Apple pairing issuer endpoint can mint proofs.
- `APNS_TOKEN_ENCRYPTION_KEY` must be installed as a Cloudflare Worker secret
  before encrypted APNs registrations are accepted.
- `DJCONNECT_SMOKE_TEST_MODE=enabled` is installed as a Cloudflare Worker
  secret so CI can run proof -> token -> register -> event smoke coverage using
  only `example-...` APNs tokens without contacting APNs.
- Remote D1 contains `install_tokens`, `registrations` and `relay_events`.
- Worker deploy succeeded.
- `https://api.djconnect.dev/health` returns `{"ok":true,"service":"djconnect-api"}`.

GitHub Actions CI/CD is configured in `.github/workflows/ci-cd.yml`:

- `Validate` runs on pull requests and pushes to `main`.
- `Validate` runs the fast Worker/Vitest suite and the focused local E2E
  contract smoke command `npm run test:e2e`.
- `Validate` never deploys. It produces CI and exact-main-SHA coverage
  evidence only.
- `.github/workflows/deploy-production.yml` runs only through an explicit,
  bounded internal-release dispatch. It performs remote migration, deployment,
  health validation and the optional staging-safe smoke.
- GitHub secret `CLOUDFLARE_API_TOKEN` is configured with Workers deploy, D1
  migration and Workers Routes edit permissions for `djconnect.dev`.
- GitHub secret `DJCONNECT_RELAY_SECRET` is mapped only to
  `DJCONNECT_RELAY_SECRET_VALUE` for `scripts/smoke_e2e.sh`; do not log it.
- The latest `main` CI/CD run is green.

Manual/operator provisioning remains available with:

```sh
npm run provision:cloudflare -- --dry-run --all
```

Expected response:

```json
{"ok":true,"service":"djconnect-api"}
```

Do not print or commit the APNs `.p8` key, relay secret, Cloudflare token or
any real APNs device token while operating or debugging the deployment.

## Release Checklist

Before every release:

- Review canonical cross-repo docs in the Home Assistant integration repo.
- Update `CHANGELOG.md`.
- Update docs when behavior, setup, security posture or release flow changes.
- Review translations in all five supported languages: `en`, `nl`, `de`, `fr`
  and `es`.
- Run tests/typecheck/local migration validation.
- Run the public repository secret scan.
- Attempt remote D1 migration and Worker deploy when Cloudflare credentials are
  available.
- Verify the release commit is based on `origin/main` before publishing.
- Push the current release commit explicitly to the intended release branch
  instead of relying on a locally up-to-date branch name.
- Use only the matching `CHANGELOG.md` version section as the GitHub Release
  body.
- Run `./cleanup_old_releases.sh --keep 1` dry-run before publishing, then
  `./cleanup_old_releases.sh --keep 1 --execute` by default after the new
  GitHub Release is published and verified. This also removes old completed
  GitHub Actions workflow runs unless `--skip-workflow-runs` is passed.

## Next Actions

- Validate the encrypted APNs token migration in remote D1 after deployment.
- Build a temporary dual-key/backfill implementation before the first planned
  `APNS_TOKEN_ENCRYPTION_KEY` rotation.
- Keep GitHub Actions `DJCONNECT_RELAY_SECRET` configured so the staging-safe
  smoke E2E job can cover proof issuance, token exchange, push register/event
  and unregister using only `example-smoke-...` values.
