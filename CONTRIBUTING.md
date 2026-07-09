# Contributing to DJConnect API

Thanks for helping improve DJConnect.

This repository contains the MIT-licensed Cloudflare Worker API for DJConnect
APNs push relay. Related DJConnect repositories are also MIT-licensed unless
their own repository files state otherwise.

Please follow `CODE_OF_CONDUCT.md` when participating in DJConnect project
spaces. Report suspected security vulnerabilities privately through
`SECURITY.md`, not in public GitHub issues.

## What Belongs Here

Good contributions for this repository include:

- Cloudflare Worker endpoints under `src/`.
- D1 schema and migration changes under `migrations/`.
- APNs relay, auth, privacy, logging and test improvements.
- API, security, release and development documentation.

Please do not add Apple private keys, relay secrets, APNs device tokens, Home
Assistant tokens, Spotify tokens, production install IDs, raw prompts, raw
assistant responses, full chat history or private release artifacts.

## Development Setup

See `DEVELOPMENT_ENVIRONMENT.md` for the local setup and validation commands.

Run the core checks before opening a PR:

```sh
npx wrangler types
npx tsc --noEmit
npm test
npx wrangler d1 migrations apply djconnect_api --local
```

Run the public repository scan before publishing or requesting review:

```sh
rg -n "BEGIN PRIVATE KEY|AuthKey|DJCONNECT_RELAY_SECRET|DJCONNECT_PAIRING_ISSUER_SECRET|APNS_PRIVATE_KEY|Bearer [A-Za-z0-9]|sk-|xox|ghp_|spotify_refresh|refresh_token|device_token" .
```

Hits for environment variable names, placeholders, generated type comments or
source code that parses PEM headers are expected. Real secrets are not.

## Contribution Guidelines

- Keep changes focused and scoped to the requested behavior.
- Preserve the trust boundary: APNs provider credentials stay only in
  Cloudflare secrets/configuration and are never sent to Home Assistant or HACS.
- Keep APNs payloads generic wake/sync hints. Do not include raw prompts, raw
  assistant responses, full history, memory, Home Assistant tokens or Spotify
  tokens.
- Add user-facing API error messages and APNs notification text through
  `src/messages.ts`, using stable language-neutral error codes and translations
  for every supported language: `en`, `nl`, `de`, `fr` and `es`. Do not localize
  JSON keys, endpoint paths, token prefixes, `client_type` values or APNs
  payload keys.
- Use example fixture values such as `example-ha-install`,
  `example-user-hash`, `example-apns-token` and `dev.djconnect.ios`.
- Update tests when endpoint behavior, D1 writes, APNs payloads, auth or error
  handling changes.
- Update `README.md`, `API_CONTRACT.md`, `SECURITY.md`, `HANDOFF.md`,
  `TECHNICAL_DESIGN_DECISIONS.md` and `CHANGELOG.md` when public behavior,
  setup, release flow or security posture changes.
- Keep cross-repo source of truth in the Home Assistant integration repo:
  `/Users/pcvantol/Documents/GitHub/djconnect/SYNC_PROMPTS.md` and
  `/Users/pcvantol/Documents/GitHub/djconnect/API_CONTRACT.md`.

## AI-Assisted Development

DJConnect is developed and maintained with AI-assisted and agentic engineering
workflows, including Codex. Accepted changes remain maintainer-reviewed.
Contributors are responsible for ensuring their changes are correct, testable,
license-compatible and free of secrets or private data.

Do not include tokens, passwords, private URLs, personal data or proprietary
third-party material in prompts, issues, logs, screenshots or test fixtures.

## Pull Requests

Before opening a PR:

1. Run the core checks above.
2. Run `git diff --check`.
3. Run the public repository secret scan.
4. Check `git status` and make sure only intended files are changed.
5. Include a clear summary and test evidence.

For larger changes, include compatibility impact for Home Assistant, iOS, macOS,
watchOS and future Raspberry Pi clients.

## Releases

Maintainer releases should follow the shared DJConnect release hygiene in
`/Users/pcvantol/Documents/GitHub/djconnect/SYNC_PROMPTS.md`.

For this repo, release validation includes:

- Review canonical cross-repo contract docs.
- Review the `DJ Announcement Output Sync` section in
  `/Users/pcvantol/Documents/GitHub/djconnect/SYNC_PROMPTS.md`. For the central
  API, confirm push payloads remain wake/sync only and carry only safe
  announcement hints such as delivery, audio availability and speaker delivery,
  never generated text, prompts, history, TTS audio or temporary `audio_url`
  values.
- Review translations in all five supported languages: `en`, `nl`, `de`, `fr`
  and `es`.
- Review and update third-party packages, dependency lockfiles and developer
  tools before cutting a release. Use `npm outdated`, update intentionally with
  targeted `npm install -D <package>@latest` or `npm update --save-dev`, then
  commit the resulting `package.json`/`package-lock.json` changes.
- Update `THIRD_PARTY_NOTICES.md` when declared third-party tooling changes.
- Update `CHANGELOG.md`.
- Run type generation, typecheck, tests, local D1 migration validation and the
  public repository secret scan.
- Attempt remote D1 migration and Worker deploy when Cloudflare credentials are
  available.
- Verify the release commit is based on `origin/main` before publishing.
- Push the current release commit explicitly to the intended release branch
  instead of relying on a locally up-to-date branch name.
- Create/push a semver tag such as `v1.0.0`.
- Publish a GitHub Release using the matching `CHANGELOG.md` section.
- Run `./cleanup_old_releases.sh --keep 1` as a dry-run before publishing.
- After the new GitHub Release is published and verified, run
  `./cleanup_old_releases.sh --keep 1 --execute` by default unless multiple old
  releases/tags are intentionally retained.

## Licensing

By contributing to this repository, you agree that your contribution is licensed
under the MIT License in `LICENSE`.

Spotify is a trademark of Spotify AB. Apple, iOS, macOS, watchOS and APNs are
trademarks or services of Apple Inc. DJConnect is not affiliated with, endorsed
by, or sponsored by Spotify AB or Apple Inc.
