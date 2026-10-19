# Default-disabled product perimeter

This increment integrates only the unavailable transport boundary into the existing `src/index.ts` Worker. It does not implement an enabled service or promote the qualified five-DO/auth package. The released implementation interface remains `djc-rendezvous/1-implementation.1` / wire `djc-rendezvous/1`.

## Exact behavior

`src/rendezvous/perimeter.ts` recognizes the URL parser's literal pathname `/v1/rendezvous` or any pathname beginning `/v1/rendezvous/`. No percent-decoding, prefix aliases or version fallback are added. Siblings such as `/v1/rendezvousx`, encoded separators such as `/v1/rendezvous%2Fcreate`, uppercase names and `/v2/rendezvous` continue through existing root routing. Query strings do not alter the namespace decision and are never reflected.

Every reserved request receives status503 with exactly `{ "v": "djc-rendezvous/1", "error": "service_unavailable" }`. This includes unknown descendants, wrong methods, HEAD and OPTIONS. The compiled-disabled check precedes origin/proof/body validation, matching the qualified ingress's disabled-ready-first behavior. A503 is neither successful CORS preflight nor origin/proof acceptance. There is no Retry-After hint or permission to retry creation. Existing finite receiver unavailable behavior remains required; no QR, connected claim or additional user step is introduced.

All responses set `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, JSON Content-Type and `Vary: Origin`. Only the single exact `Origin: https://vibecast.tv` receives Access-Control-Allow-Origin. No credentials, allowed-method/header or successful-preflight promise is returned. Foreign/null/combined Origins receive no CORS permission; none is reflected.

The root dispatch occurs before environment access, body/clone/JSON reading, DB or namespace calls, context diagnostics, provider work and console output. Disabled rendezvous data therefore does not enter the existing D1 diagnostic sink. There is deliberately no env/header/query toggle, verifier dependency, software harness import or hidden enabled fallback. Enabling requires separately reviewed source with qualified product coordinators, identity, budgets and real verifier configuration.

Existing health/APNs/pairing/install/operator routes and their redacted diagnostics retain their behavior. No binding, migration, dependency, workflow, secret, route configuration or Cloudflare resource changes. The existing source artifact will contain this perimeter after normal delivery; it will still not contain an integrated rendezvous service.

## Executed local evidence

[Actual local source/bundle observations](product-perimeter-observations-v1.json) pin the tested source and dry-run bytes. Root TypeScript and **78/78 Worker tests PASS**:40 existing API regressions plus38 new product-boundary tests. These exercise all11 contract paths through the actual exported root handler with throwing body/env/context dependencies and console spies; all methods including OPTIONS/HEAD; exact/foreign/null/combined Origin handling; fixed privacy headers; bare namespace/descendants/query/encoded paths/sibling/version boundaries; and actual root404/health responses with fixed diagnostic labels. Untrusted activation headers cannot enable anything. No proof/crypto/DO/provider/live acceptance is inferred from these tests. No mutation or deployment was performed to generate this local evidence.

The unchanged1208-case private workerd proof remains pinned to its original source and scope; it is not relabelled as a test of this product adapter. Candidate review, own protected CI/main and bundle readback still apply before delivery. New independent source/security and UX reviews must confirm this exact increment.

## Operations, rollback and next work

The short response does not prove platform logging, edge budget/WAF behavior, physical erasure, cost or service availability. Platform processing still occurs; no public capacity/SLA claim follows. User-facing translations are unchanged: the response carries only the existing stable wire error code, while consumers own their existing five-language message presentation.

Rollback uses the existing exact qualified API artifact through its applicable authorization gate; a prior source returns ordinary404 for these paths. This increment creates no new namespaces, state, keys or migration, so there is no new state to renew/drain/delete. Never bypass the protected artifact/deployment gate or deploy as part of this source step.

API still owns product-only five-DO/class/build integration, reviewed trusted-edge identity and admission, real default verifier/provider composition and exact production app/environment policy. A fresh specific server-bound signed-native experiment gates authenablement, not writing this always-off source. Receiver adoption, native key lifecycle, actual HA/proxy/separate B, physicalTV, account/spend/retention/rollback and explicit deployment authorization remain separate. Timer OFF; assignment OPEN.
