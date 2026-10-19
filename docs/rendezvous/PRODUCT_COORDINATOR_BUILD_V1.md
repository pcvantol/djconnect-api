# Private coordinator product build

Assignment `DJC-API-VIBECAST-RENDEZVOUS-V1-20261016`; sole API writer. Base protected
main `aab76f7efc3e56faed186369ff7419bea2c96aa2`, fresh
[admission](https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6272805766).
This is a source candidate, pending its own reviews and protected delivery.
Wire `djc-rendezvous/1` / released source interface `djc-rendezvous/1-implementation.1`
are unchanged. This package does not authorize deployment or public/native activation.

## Implemented boundary

The actual root Worker exports `RequestAdmission`, `AllocationBudget`,
`AllocationIndex`, `EnrollmentCoordinator` and `BudgetedTransactionCoordinator`,
alongside its existing default and test-token helper. Each product class composes
a private engine using only the runtime context and environment. Explicit RPC
allowlists are in [the build manifest](../../rendezvous-build-inputs.json).
Internal install/evidence/advance/revoke/rotate/lookupSubmit, storage, context,
environment and verifier-injection seams are not exported RPC methods or getters.
The composition prevents inheritance from unintentionally widening this surface.

Existing reviewed state machines, SQL, expiry, counters, budgets and crypto policy
are reused directly. Their shared-candidate headers clarify that `qualification/`
is a source location rather than a security boundary. No runtime algorithm or
App Attest application/build allowlist is changed. The dev-profile verifier is
compiled; no production-profile or fresh native-positive acceptance is implied.

Wrangler, TypeScript and Vitest resolve the same closed four aliases. Real
`cbor`10.0.12, `asn1js`3.1.0 and `pkijs`3.4.1 and their transitive lock integrities
match the previous qualification provenance. Fixed Apple DER literals are compared
byte for byte with the pinned public certificates. No downloaded roots, temporary
aliases, software enrollment, fixtures or harnesses enter the product graph.
[Licence texts](THIRD_PARTY_LICENSES_V1.md) accompany these bundled dependencies.
Package-artifact matching is not a reproducible source-build claim.

The root compiled503 perimeter is unchanged. No environment/header setting can
enable it. Root Wrangler changes only the build aliases: no new DO bindings,
migrations, routes, secrets, account changes or Cloudflare writes. Existing APNs,
pairing, D1 and operator behavior remains covered by API regressions.

## Executed local qualification

`npm run test:rendezvous-product` dry-builds the actual root Worker, checks its
metafile and exact exports, hashes real inputs, and rejects software/harness/fixture
imports. A temporary QA-only driver loads that actual bundle into local workerd
with five isolated SQLite namespaces. No test driver is bundled in the product.
128 assertions include100 rejected forbidden RPC/getter attempts, explicit
configured/wrong-object-name/missing-policy distinctions, real default verifier
rejection of malformed enrollment, preservation of the original challenge and
deadline, rejected unknown-key management proof, zero installed key rows,
extra-argument rejection and zero product egress. The ephemeral test receipt key
is deterministic synthetic material and never a deployment secret.

The runner uses the locked Wrangler-selected Miniflare via its supported V4
options converter, with an explicit temporary modulesRoot. Miniflare's loopback
Origin guard is independent of product CORS. The QA driver therefore constructs
the exact Origin-bearing request inside workerd before calling the actual root
default. This proves the compiled503 path with and without private configuration;
it is not a public-edge CORS proof. Host-side local storage inspection only checks
the rejected registration left zero key rows; it adds no remotely callable seam.

Root types and78 Worker tests pass (40 existing API +38 perimeter); all five
supported language tables remain complete, with no message changes. Re-run of
the isolated shared-key suite passes1208 cases plus strict types with the new
source headers. Its software-positive transaction flows remain distinct from the
actual product's default-genuine-negative tests. Production dependency audit:
zero known vulnerabilities at qualification time; existing dev-tool advisories
are not fixed or concealed by this package. No platform capacity/live cost claim.

See [actual bundle/RPC observations](product-coordinator-build-observations-v1.json)
and [current shared-source proof](product-coordinator-shared-source-proof-v1.json).
Earlier PR96/97/98 receipts and their proof files remain immutable historical
evidence. The old deployment-preparation validator intentionally rejects changed
working bytes against its old source pin; it is not reinterpreted as approval for
this product bundle. A separately reviewed exact-source preparation rebind remains
necessary before deployment.

## Next owned work and operational boundary

API retains trusted-edge identity resolution, fixed default provider/public
composition, full-product qualification, operational preparation/rollback and
exact artifact/authorization gates. This compiled-disabled build can be reviewed
and protected-delivered before fresh native evidence. Enabling genuine app auth
requires a new server-bound32-byte nonce, fresh Apple receipt/status verification,
atomic counter0 enrollment and exact native action proofs through the composed
path; old diagnostic captures do not satisfy it. No weakened verifier, stale
receipt exception or widened app-build allowlist is authorized.

Existing Core/Apple/receiver owners retain consumer adoption and their own
native/HA/physical-TV evidence. Rendezvous only conveys a paired-app reported,
validated encrypted HTTPS destination. It authenticates neither HA ownership nor
screen/session rights; separate HA screen admission remains mandatory. Timer OFF.

Rollback for this source increment is a normal protected revert of the exports,
aliases/dependencies and build test, preserving the already-disabled perimeter.
There is no deployed DO migration or runtime state to roll back from this local
qualification. Actual deployment/DO migration rollback requires its own reviewed
manifest and exact authorization; no deployment command is executed here.
