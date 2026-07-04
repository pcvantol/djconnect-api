# Third-Party Notices

DJConnect API is a Cloudflare Worker that relays privacy-safe DJConnect push
events to Apple Push Notification service (APNs). This file summarizes
third-party projects, APIs and trademarks referenced by the repository.

For code-level dependency decisions and the maintained dependency inventory, see
`TECHNICAL_DESIGN_DECISIONS.md`.

## Cloudflare

This repository uses Cloudflare Workers, Wrangler, D1 and Worker runtime APIs.
Cloudflare platform services and their documentation remain the property of
Cloudflare and their respective contributors.

## Apple Push Notification Service

DJConnect API sends notifications through Apple Push Notification service using
provider-token authentication.

Apple, APNs, iOS, macOS and watchOS are trademarks or services of Apple Inc.
References to Apple services are API usage only and do not imply endorsement,
sponsorship, partnership or official support by Apple Inc.

## Node.js And npm Packages

Development and test tooling is installed through npm and recorded in
`package-lock.json`. Release validation includes an explicit dependency and
tool freshness review (`npm outdated`, `npm run deps:report`, Node.js, npm and
Wrangler versions). Declared development dependencies include:

- `wrangler`
- `typescript`
- `vitest`
- `@cloudflare/vitest-pool-workers`
- `@types/node`

Their licenses and copyrights remain with their respective authors and
contributors.

## Spotify Trademark Notice

DJConnect repositories may reference Spotify playback concepts through the Home
Assistant integration and clients.

Spotify is a trademark of Spotify AB. DJConnect is not affiliated with,
endorsed by, or sponsored by Spotify AB.

## DJConnect

Copyright (c) 2026 Peter van Tol.

DJConnect repositories are MIT-licensed unless a specific repository or
third-party dependency states otherwise. See `LICENSE`.
