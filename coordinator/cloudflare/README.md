# Cloudflare coordinator source increment

This is one source-only composition for the preferred existing-account Cloudflare
service: one Durable Object SQL transaction domain and one separate Node executor
intended for a Container. The public production factory and Container start method
always reject before accessing configuration, storage, Container, secrets or a
provider. Nothing imports this package from the root Worker. Root routes, bindings,
migrations, dependencies, existing coordinator package and production are unchanged.

## Actual source boundaries

`state.ts` uses real `DurableObjectStorage.sql.exec`, `transactionSync` and `sync`.
SQL cursors are consumed synchronously. SQL internals use JavaScript private methods,
not TypeScript-only privacy that would disappear when compiled. One closed, capped
source RPC envelope records expected failures as negative DATA. A persistence failure
or lost ACK never means that a completed transaction was undone. The executor retires
locally on any such ambiguity and cannot recreate a lost in-process handle.

The disposable fixture journal holds parent registration DATA, immutable original
job/role/context/epoch/key references, five ordered stage claims, global operation and
nonce namespaces, and global per-key monotonic uint32 counters. Stage, claim, nonce,
operation and counter changes share one SQL transaction. Counter scope and revision
survive new parents/principal epochs. Parent retirement and Container-generation
changes invalidate existing work. Fixture job-count/lifetime limits are synthetic,
not an accepted production policy. Only existing-key positive counter DATA is modeled;
new-key attestation and every real native validator remain unimplemented here.

`rpc.ts` implements the concrete DO RPC client and fixed Container virtual-host client.
`outbound.ts` is a real loopback `WorkerEntrypoint`; its owning DO selects its own ID
in props. Requests cannot select a DO ID through body, path or headers. It accepts only
the capped source transaction endpoint, refuses every other host/path/method and never
forwards to an Internet destination. Request bytes are capped while streaming and
decoded as strict UTF-8; responses are capped too. Redirects are manual and non-200
responses fail closed. This is private source wiring, not a registration authority.

The source interception method uses the actual `ctx.container.interceptAllOutboundHttp`
API. No call starts a Container. A future reviewed start must keep `enableInternet:false`;
the interception method alone does not block other protocols or configure a live VM.
The loopback export shape asserted in that source method corresponds to the named
export actually exercised by local tests. The root Worker has no such export/binding.

`executor.ts` retains the original immutable synthetic admission and consumes an
executor-local handle before final validation/construction. All remote state work
finishes before the last synchronous construction and local clock check. There is
no provider/SDK/signing callback, provider RPC hop or production sender. Observations
are source DATA only. Concurrent remote retirement after the last state read is not
claimed solved by a distributed atomic provider operation; that integration remains
closed. The journal's restore epoch check detects mismatched inputs, not an actual
Cloudflare rollback to an older matching journal. Actual restore/nonrollback evidence
is a separate unresolved gate.

## Reproducible free local conformance

Use the already locked dependencies, Node 26 and explicit external scratch storage:

```sh
node_modules/.bin/tsc -p coordinator/cloudflare/qualification/tsconfig.json --noEmit
node_modules/.bin/vitest run --config coordinator/cloudflare/qualification/vitest.config.mts
node coordinator/cloudflare/qualification/node-loopback.mjs "$TMPDIR/cloudflare-node-source"
```

The workerd tests exercise actual local SQLite DO storage and real RPC/loopback
entrypoints. Only the lost-ACK and cancel transport faults are explicit test shims;
the commits underneath remain real. A real SQL trigger aborts after counter update
to prove joint rollback. No Source161 native-SQLite result is transferred to this
new store boundary. The standalone Node test uses an actual separate local workerd
server on 127.0.0.1 and maps only the fixed virtual host to that server. It tests
Node's advancing `process.hrtime.bigint()` through CPU-only construction. UTC is
explicitly synthetic. A local Mac/CI source run is not a qualified Linux Container,
continuous-clock/suspend/UTC bound, physical persistence or native/provider test.
The HTTP bridge is a separate qualification-only module, excluded from the package
Worker, whose public fetch always returns 503.

`build-source.mjs` verifies the locked dependency hash, actual installed Wrangler
version/schema, and source manifest, bundles the two source executors, copies the
Dockerfile and validates source configuration with the actual Wrangler parser. It
does not invoke Docker or any cloud API. The official Node Linux/amd64 base digest
was obtained from actual public registry metadata on 2026-10-28. This is a base-image
pin, not an application-image digest. The application image is unbuilt/unpublished
and explicitly null. The packaged Node entry exits 78; it opens no listener.

The installed Wrangler parser accepts the named `durable_object` images/export
configuration but rejects `max_instances` for this scheduling policy, even though
that field exists in the general schema. No unsupported singleton or billing cap
is claimed. Current generated runtime types do not expose the newer named image
start options; no cast fabricates support and no positive start is implemented.

## Actual account blocker and remaining activation

The normal already authenticated CLI's read-only `containers list --json` on
2026-10-28 returned: "Unauthorized: You do not have access to Cloudflare Containers.
Deploying containers requires the Workers Paid plan." No login, account upgrade,
key search, secret read/injection or provisioning was performed. Account identifiers
and credentials are deliberately absent from `inputs.json`. This denial blocks a
live Container and does not imply the existing Worker API is offline.

Before live operation: exact-source independent review and normal protected source
delivery; separate production image build/registry pin; actual account entitlement
and approved cost/resource/lifetime limits; real registrar/principal verification,
trusted registry bootstrap and Core/install binding; original native role/policy
admission; qualified Container generation/clock and store restore; scoped APNs
custody/injection and separate activation/device/provider acceptance. No unverified
B receipt, ordinary pairing token or public JWK establishes registration authority.
APNs send custody stays service-side; HA/iPhone private identity keys stay with
their owning components. This source increment changes none of those authorities.
