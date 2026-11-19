# Current operational preparation

Protected supplying source `a7806a9c65b7b1971c558eee238ad26fbc536a08` (PR101),
wire/source implementation **djc-rendezvous/1-implementation.1 RELEASED**.
This document and the [offline manifest](deployment-preparation-v1.json) prepare
deployment; they neither authorize it nor claim the complete assignment finished.
The validator verifies102 tracked source pins from three immutable proofs, with
32 explicitly prefixed installed dependency inputs excluded from Gitblob checks.
Closed proposed config/secret names/migration are not actual Cloudflare settings.

## Configuration and target preparation

Preserve the existing Worker, APNs relay, pairing issuer, D1 registrations,
operator flows, secrets, routes and release gates. Use the same five private
product classes and proposed SQLite migration tag in the manifest. The tag and
account-wide namespace collision status remain unverified. No legacy/software
binding is proposed. The IP-HMAC and receipt encryption key names are listed,
but actual values must remain operator secrets. Policy deadline/revision are
null until reviewed for the exact target; a dev qualification profile is not
production app/build/environment acceptance.

The [readonly known-version inventory](known-worker-version50-readonly-v1.json)
records version `d7f38154-51ca-4066-9d61-f64e0df0dda5`/#50, its12 binding names/types,
zero DO bindings and no rendezvous secret names. Its runtime usage model
`standard` is not account billing-plan/shared-usage approval. This version-only
query proves no current deployment split, routing, WAF/transform, global namespace,
retention/backups, secret rotation or physical cleanup property. No values or
credentials are exported. No Cloudflare write was made.

Before any dispatch, obtain exact account/target/deployment split and artifact
binding; preserve current API settings; verify all five namespace/class/tag
collisions and actual secret presence/rotation. Inventory custom domains/routes,
workers.dev/preview/service bindings and Worker forwarding. Verify Pseudo IPv4,
visitor-IP transforms and WAF `cf.worker.upstream_zone` policy with direct IPv4/
IPv6 and same/cross-zone/alternate-ingress negatives. Fixture cf/IP tests are
not that evidence. Public root remains compiled503 regardless of proposed config.

The existing protected deployment workflow consumes the central RC2 operational
manifest, not this preparation. An applicable centrally approved exact manifest
and readiness/production-environment gates must precede dispatch. No workflow,
status, account setting or authorization is bypassed by this package.

## Capacity and conditional cost component

This is source arithmetic, not an account quote, throughput promise, complete
bill or spend authorization. Current selected limits remain10,000 allocations/
day,5/IP-minute,500 registration attempts/day,50,000 key calls/day, HTTP total
10,000/minute and1,000,000/day with regular/terminal reserves. IP-minute partitions
remain256poll/16create/64native/16terminal. Applications share these ceilings;
registration retries consume attempts, and OPTIONS/denied/attack work adds cost.

For60polls plus create/inspect/submit-challenge/submit/consume, the existing source
decomposition is65 HTTP/201 DO calls before first enrollment, retries or OPTIONS.
The current request gate explicitly upserts4 counters for each ordinary admission,
adds2 terminal counters for consume/cancel, and schedules an alarm. Thus64 ordinary
plus1 terminal admission produce327 such gate write/alarm operations per flow.
Cleanup deletes/index amplification/other DOs/provider status/CPU/active duration/
retained data/logs are additional and require actual measurement.

Illustrative30-day arithmetic, assuming a Paid plan and entirely unused included
pools: at1,000 flows/day this scenario gives1.95m HTTP,6.03m DO calls and9.81m gate
write/alarm operations; at10,000/day,19.5m/60.3m/98.1m respectively. Current
[Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
lists10m monthly requests then$0.30/million; [DO pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)
lists1m monthly requests then$0.15/million,50m SQLite row writes then$1/million,
with alarms/deletes counted as writes. Under a one-row-per-counted-operation
assumption and published DO request rounding, request plus this gate-only write
component is$0.90/month at1,000 flows/day and$59.95 at10,000/day. Both exclude base
fees and all omitted components above; neither is an expected total bill or cap.
Prices were re-read2026-10-19; account applicability is unverified.

The10,000/day scenario assumes POST-only, no first enrollment and no other demand.
Worst preflight adds62 requests/flow, reaching1.27m recognized/day and exceeding
the source1m/day cap. No successful10k worst-case-flow claim follows. One normalized
IP HMAC per recognized request adds CPU; no genuine crypto latency or capacity
has been measured on the intended account. Use the official
[Workers limits](https://developers.cloudflare.com/workers/platform/limits/) and
[DO limits](https://developers.cloudflare.com/durable-objects/platform/limits/)
for actual plan ceilings. The historical [partial model](COST_CAPACITY_MODEL_V1.md)
retains its own old source assumptions rather than silently representing this one.

Measure p50/p95/p99/CPU/GB-s/SQL reads/writes/storage/cleanup under allowed and denied
mixes, multiple NAT screens, minute boundaries, provider stalls and distributed
bursts. Account-edge rejected traffic also costs resources. Establish approved
maximum spend, alerts and admission stop policy; application counters cannot cap
the provider bill. These remain actual operational gates, not source test failures.

## Authorized smoke and privacy receipts

After exact authorized artifact/config deployment, first verify ordinary APNs/
pairing/operator/D1 regressions and actual artifact/version/binding readback.
Then verify the full eleven-route rendezvous path, actual approved-Origin CORS/
preflight, unknown routes, wrong/absent metadata, rate limits/reserved terminal
headroom, invalid proofs and provider outages without fail-open behavior. A health
response or503 proves no successful rendezvous. Record scope/artifact/result and
bounded timings, never raw IP/capabilities/keys/nonces/receipts/assertions/HA URLs.

The genuine positive experiment needs the supported signed Apple build and an
API-owned saved32-byte server nonce/original120s deadline, fresh Apple attestation/
CMS/status, atomic enrollment/counter0, exact native signed action bytes and
JOSE-bound destination, one consume and replay/race/tamper/cancel/expiry negatives.
Provider status is fetched only from fixed common authenticated-certificate
endpoints, never a destination/HA URL. No HA credentials or Profile/Session bearer
may enter the service. Reusing old captures or software enrollment is not positive
native evidence; do not start an unchanged capture/key loop.

Existing receiver ownership then verifies real browser lifecycle/crypto/disposal
and TV QR→scan→owner approval→separate HA screen admission→active rendering.
Core's route/context and HA/proxy/direct200 must match the paired installation;
rendezvous does not authenticate HA ownership or grant screen/session rights.
Apple PR144 delivered process-wide key FIFO, while scanner/transport/SDK lifecycle/
exact JOSE integration remains separate source work per Apple87. No new writer,
extra user code/manual IP step, replacement website or automatic session admission.

## Rollback and finalization

Known version#50 inventory has no fiveDO bindings and does not establish required
class/schema rollback compatibility after a future migration. The compiled503/five-DO source
can be a proposed admission-blocking fallback only after exact target bindings,
schema, receipt-key versions, cleanup alarms and expiry behavior are verified.
Retain class/schema/keys while stopping new admission; preserve original deadlines.
Never delete namespaces, reset counters, wipe D1, renew QR/key lifetimes or remove
receipt keys as rollback. Actual compatible rollback/readback and physical cleanup
remain OPEN. A protected source revert is not installed rollback evidence.

Prepare and independently review the exact central manifest/artifact/rollback
receipt before asking for the separate deployment authorization. Protected source
delivery and separate bounded source Finalization do not close full-service gates.
All22 preparation gates remain OPEN/null/false; timer OFF. No deploy/remote migration,
secret/WAF/route/tunnel/control-plane mutation is performed by this preparation.
