> Surface purpose issuer successor: [exact source contract and scope](docs/push/SURFACE_ISSUER_SOURCE_V1.md). Internal operator-delegation/challenge/issue/status/withdraw plus grant/source/binding fences; no real approval/credentials/root/provider/native effects. Existing source PRs preserved, interim merge/deploy hold.

> Surface provider authorizer successor: [source scope and evidence](docs/push/SURFACE_PROVIDER_SOURCE_V1.md). ES256/cached JWT plus local WidgetKit/iPhone update/end composition; no real credentials/provider traffic/root admission. PR132/a0ff403 and maintenancePR131 preserved.

> Typed surface-push source candidate: [contract and boundaries](docs/push/SURFACE_PUSH_SOURCE_V1.md). Internal local-D1 register/revoke/event/status component; no public-root routing, capability issuance, real provider adapter, actual Apple content profile or native acceptance. Existing appalerts and PR131 remain unchanged; no deployment/install.

> Fixed QA app/profile source PR129 is protected as `93fdd71a3093ce37d85f92ed55474990aa88775f`; eight actual own-main release workflows and ordinary+QA/formal/durable readbacks passed.
> [Separate source Finalization](docs/rendezvous/FIXED_QA_APP_PROFILE_FINALIZATION_V1.md) awaits its own fresh reviews and delivery. Historical40408 expired; profile/admission null, guardfalse, all22 gates OPEN, no provider/native effects.

> Fixed closed QA source125 and Git-replacement correction127 protected; latest main3daeb9a has eight complete own-main SUCCESS workflows and actual ordinary+QA readbacks.
> [Cumulative separate Finalization](docs/rendezvous/FIXED_QA_BUILD_FINALIZATION_V1.md) awaits own delivery; old docs126 closed unmerged. QAguardfalse/all22gatesOPEN/no effects.

> Selected QA Git replacement guard: real disposable A→B counterproof reproduces wrong source stamp/blob; fixed global --no-replace-objects refuses both.
> Source patch/reviews/delivery required; earlier docs-only Finalization126 held/superseded. Runtime guard stays false, all22 gates OPEN, no effects.

> Selected fixed isolated QA build: [source and qualification](docs/rendezvous/FIXED_QA_BUILD_V1.md).
> Compiled closed; current Apple/admission null; own reviews/delivery/Finalization pending. No deployment or native effects; all22 gates OPEN.

> Point-digest source PR123 protected asdfdab07 with own-main CI and actual artifact/formal/durable readbacks PASS.
> [Separate Finalization](docs/rendezvous/ENROLLMENT_POINT_DIGEST_FINALIZATION_V1.md) awaits its own protected delivery. Full taxonomy/all22 gates OPEN; no deploy; timer PAUSED.

> Fixed enrollment point-digest exception preservation is locally qualified: [scope/evidence](docs/rendezvous/ENROLLMENT_POINT_DIGEST_FAILURES_V1.md).
> Protected delivery/reviews and separate Finalization remain pending. Full taxonomy/all22 gates OPEN; no deploy or native effect; timer PAUSED.

> Sharp maintenance source PR121 is protected and qualified; [separate Finalization](docs/rendezvous/SHARP_0355_FINALIZATION_V1.md) is pending delivery.
> Patched lock/archive verified; GitHub alert39/SBOM still report the old version at readback. No deploy; all22 gates OPEN; timer PAUSED.

> Sharp-only maintenance: exact override/allowScripts0.35.5 and closed package-input rebind.
> [Scope and evidence](docs/rendezvous/SHARP_0355_MAINTENANCE_V1.md). Protected delivery/reviews and separate Finalization pending; no deploy, timer PAUSED.

> Assertion crypto source PR119 delivered as030d225; all7own-main workflows and actual artifact/formal/durable readbacks PASS.
> [Separate Finalization candidate](docs/rendezvous/ASSERTION_CRYPTO_FINALIZATION_V1.md) needs fresh exact reviews and protected delivery.
> Full assignment/22 gates OPEN; no deploy; timer PAUSED.

> Assertion fixed-WebCrypto failure correction: locally qualified candidate; protected delivery/reviews/Finalization pending.
> [Bounded source and actual evidence](docs/rendezvous/ASSERTION_CRYPTO_FAILURES_V1.md); full taxonomy/22 gates OPEN, no deploy, timer PAUSED.

> Enrollment callback source PR116 delivered as f88f237; own-main CI/artifact/formal/durable readbacks PASS.
> [Separate Finalization candidate](docs/rendezvous/ENROLLMENT_CALLBACK_FINALIZATION_V1.md) requires fresh exact reviews and protected delivery.
> Entire assignment and22 activation gates remain OPEN; no deploy; timer PAUSED.

> Current [enrollment callback failure correction](docs/rendezvous/ENROLLMENT_CALLBACK_FAILURES_V1.md)
> preserves coordinator-owned saved-state exceptions instead of labelling transient
> server faults as invalid proof. Local1485 shared cases pass; independent reviews,
> exact protected delivery and separate Finalization remain pending. Public service
> stays compiledOFF/all22full-service gatesOPEN.
>
# DJConnect API TODO Backlog

## Production Hardening

- Keep `scripts/provision_cloudflare.sh --dry-run --all` as the operator
  preflight before manual `--execute` provisioning runs.
- Build temporary dual-key/backfill tooling before the first planned
  `APNS_TOKEN_ENCRYPTION_KEY` rotation.
- Add structured redacted logging helpers if more observability is needed.
- Re-run the public repository secret scan before every release.
- Confirm no request-body logging is enabled in Cloudflare observability/tail
  workflows.

## Security / Privacy

- Keep `DJCONNECT_RELAY_SECRET` as an operator/bootstrap secret only; never ship
  it in HACS/client code.
- Keep per-install `djci_...` tokens scoped to one `ha_install_id`.
- Keep `APNS_TOKEN_ENCRYPTION_KEY` only in Cloudflare Worker secrets and never
  in GitHub Actions, local env files or fixtures.
- Keep tests and fixtures on example values only.

## API / Contracts

- Keep `/v1/push/*` aligned with the Home Assistant integration relay contract
  as the integration uses this central API.
- Keep `API_CONTRACT.md` aligned with
  `/Users/pcvantol/Documents/GitHub/djconnect/API_CONTRACT.md`.
- Add a compatibility note if HA integration versions require a specific API
  release line.
- Keep the HACS token provisioning docs aligned with the implemented automatic
  setup flow. Manual token/API URL controls are support-only, not the normal
  onboarding path.

## Testing

- Keep the local E2E contract smoke command (`npm run test:e2e`) in PR
  validation.
- Keep the staging-safe E2E smoke test enabled in CI by setting GitHub Actions
  secret `DJCONNECT_RELAY_SECRET` to the same value as the Cloudflare Worker
  secret. `DJCONNECT_SMOKE_TEST_MODE=enabled` is already required on the Worker
  side.

## Documentation

- Keep `README.md`, `API_CONTRACT.md`, `SECURITY.md`, `CHANGELOG.md`,
  `HANDOFF.md`, `ISSUES.md`, `TECHNICAL_DESIGN_DECISIONS.md`,
  `DEVELOPMENT_ENVIRONMENT.md`, `THIRD_PARTY_NOTICES.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `CHAT_BOOTSTRAP.md` and `AGENTS.md` current.
- Keep cross-repo sync prompts and product roadmap only in
  `/Users/pcvantol/Documents/GitHub/djconnect`.

## Release Workflow

- Run `npx wrangler types`.
- Run `npx tsc --noEmit`.
- Run `npm test`.
- Run `npx wrangler d1 migrations apply djconnect_api --local`.
- Attempt remote migration/deploy when credentials are available.
- Review translations in all five supported languages: `en`, `nl`, `de`, `fr`
  and `es`.
- Use `CHANGELOG.md` for GitHub Release notes.
- Run `./cleanup_old_releases.sh --keep 1` as a dry-run before publishing.
- Run `./cleanup_old_releases.sh --keep 1 --execute` by default after the new
  GitHub Release is published and verified; this also removes old completed
  GitHub Actions workflow runs.
