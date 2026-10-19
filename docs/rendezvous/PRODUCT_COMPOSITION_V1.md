# Internal product composition

Assignment `DJC-API-VIBECAST-RENDEZVOUS-V1-20261016`. Base protected main
`5f08e05de7e0d8e4e100ba289bc9c5d71437e973`; sole-writer
[fresh admission](https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6273479066).
Both independent reviewers accepted the [bounded design](PRODUCT_COMPOSITION_DESIGN_V1.md)
before runtime source changes. Exact-source reviews/protected delivery of this
candidate remain separate. Wire/source interface
`djc-rendezvous/1-implementation.1` is unchanged; no consumer ACK is reopened.

## Source behavior and exposure

`src/rendezvous/composition.ts` supplies an ordinary internal
`createProductRendezvousHandler(env)` factory. Its only argument is server env;
extra factory arguments fail closed. Resolver, provider, namespace choice,
verifier/trust and crypto policy cannot be selected by a caller options argument.
It reuses the existing eleven routes, schemas, CORS, limits, retries, allocation,
key routing and five private product DOs with their real default verifier.
No alternative grants or software enrollment enter this module.

There is no root import/re-export, WorkerEntrypoint, exported fetch object, new
RPC or activation branch. The actual product root keeps its seven exports and
unconditional503 perimeter. Local module tests run the source module in workerd
with the five real product facades selected by test-only bindings. This evidence
is distinct from the actual root-bundle/RPC qualification and proves no reachable
public HTTP service. Activation still requires separately reviewed source and
actual operational/native evidence, not an environment/header toggle.

Each invocation validates fixed current budget/composition/dev-auth policies,
policy deadline/revision, canonical32-byte IP-HMAC/receipt material and presence of
the five namespace methods. It snapshots relevant server configuration again
after asynchronous HMAC derivation before the first namespace call/body read.
Clock rollback and admission-minute changes fail closed. Unknown routes retain
the existing cheap400 invalid_request path without namespace calls.

For recognized routes, the fixed resolver requires the canonical effective HTTPS
API URL without query/fragment/credentials/nondefault port, object `request.cf`,
absence of every CF-Worker header, and exactly one strictly normalizable
CF-Connecting-IP. It rejects cross-zone sentinel `2a06:98c0:3600::103`, IPv4
Class-E pseudo addresses and their IPv4-mapped IPv6 forms after normalization.
There is no XFF, x-real-ip, True-Client-IP or CF-Connecting-IPv6 fallback.
The existing HMAC-SHA256 identity derives once per recognized invocation and
minute. Module code does not persist, return or log raw IP or full metadata;
actual platform logging remains an operational qualification gate.

These checks are defense in depth, not cryptographic proof of direct ingress.
[Cloudflare documents](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
same-zone Worker IP influence, cross-zone sentinel behavior, Pseudo IPv4 header
overwrite, and Worker-subrequest headers. WAF uses
[cf.worker.upstream_zone](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/cf.worker.upstream_zone/)
rather than treating CF-Worker as a WAF-authenticated client header.

## Shared source changes

Existing IP normalization is extracted once as `normalizeBudgetIp` and reused by
the existing derivation and product resolver; normalization and HMAC encoding are
unchanged. No custom cryptographic protocol is introduced.

`TransactionDependencies` separates required enrollment from the legacy optional
constructor default-namespace form. Overloads require an explicit namespace for
the composed dependency form, preserving the original emitted constructor
default `env.TRANSACTION_STATE` for legacy callers. The composed subclass always
passes COMPOSED_TRANSACTIONS. No fake legacy binding, runtime fallback, extra DO,
SQL/TTL/counter/budget or crypto-policy change is introduced. All1208 shared
regressions and strict types are rerun with current source pins.

## Executed local evidence

`npm run test:rendezvous-composition` runs strict types for module and tests plus
49 workerd cases: fixed config/secret rejection, missing/malformed/duplicate IP
and metadata, no forwarded-header fallback, normalized sentinel/Class-E variants,
IPv6 HMAC equivalence, per-invocation validation, changed-config/time rechecks,
extra-argument refusal and one HMAC for an actual create invocation. Poison body
and namespace spies prove invalid configuration/identity does not reach them.

Actual private product DO flows create a secure120s QR, inspect it, poll across
fresh handler invocations, reject consume-before-ready/wrong-browser, cancel and
reject later consume. Genuine-default malformed registration rejects without an
installed key and preserves the original challenge/deadline. Wrong-Origin403,
safe preflight, no credentials, canonical URL/unknown route negatives retain
the existing dispatcher behavior. A positive test of the local network guard is
separated from zero product egress for all cases. No fresh native positive or
full encrypted destination handoff is claimed by these tests.

Root types/78 API-perimeter tests and128 actual root-bundle/private-RPC assertions
also pass; the latter still rejects100 internal calls/getters. The isolated
1208 shared-key regression/type suite passes with current66 source pins.
The current proofs are separate from historical PR99/100 evidence:

- [Module observations](product-composition-observations-v1.json).
- [Actual root-build observations](product-composition-root-build-observations-v1.json).
- [Current shared-source proof](product-composition-shared-source-proof-v1.json).

## Remaining enablement and operations

Before activation, API/operator must obtain exact route/custom-domain/workers.dev/
preview/service-binding/Worker-forwarding inventory, Pseudo IPv4 and visitor-IP
transform readbacks, WAF upstream-Worker enforcement, direct IPv4/IPv6 and same/
cross-zone/alternative ingress negatives on the exact deployed artifact, matching
secrets/version and approved cost/log-retention/cleanup policy. Fixture cf/IP
objects do not close these gates. Old operational preparation remains pinned to
its own historical source and rejects changed working bytes; a separately
reviewed current preparation rebind is still required.

Genuine auth enablement needs a fresh server-bound32-byte nonce/Apple attestation,
fresh receipt/status, atomic counter0 and exact native action assertions through
the composed flow. Old captures, software signatures or a public health response
cannot replace it. Existing Apple/Core/receiver owners retain their adoption,
separate HA display admission and physical chain evidence. Rendezvous grants no
HA-owner, screen or session rights and stores no HA credentials or plaintext destinations.

Rollback is normal protected source revert of this unmounted module, narrow
shared refactor and test wiring. No new deployment, migration or live state exists
from this slice. Complete-product Finalization remains separate, assignment OPEN,
timer OFF. No Cloudflare mutation or deployment authorization is implied.
