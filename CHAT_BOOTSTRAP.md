# DJConnect API Chat Bootstrap

Work in `/Users/pcvantol/Documents/GitHub/djconnect-api`.

This repository is the central Cloudflare Worker API for DJConnect APNs push relay. Treat it as public/open-source: never commit APNs private keys, relay secrets, APNs device tokens, Home Assistant tokens, Spotify tokens, production install IDs, raw prompts, raw assistant responses or chat history.

Cross-repo source of truth:

- `/Users/pcvantol/Documents/GitHub/djconnect/SYNC_PROMPTS.md`
- `/Users/pcvantol/Documents/GitHub/djconnect/API_CONTRACT.md`

Before release work:

- Run `git status --short`.
- Run `npx tsc --noEmit`.
- Run `npm test`.
- Run the public repository secret scan from the current release checklist.
- Keep release notes in `CHANGELOG.md`.

Cloudflare secrets must be set only through Cloudflare secrets/configuration, never in source, docs, tests or fixtures.
