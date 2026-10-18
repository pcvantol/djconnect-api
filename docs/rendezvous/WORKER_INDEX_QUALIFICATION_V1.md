# Local private allocation index and transaction routing

Profile `0.4.0-draft`, wire `djc-rendezvous/1`, isolated policy
`djc-index-qualification/1`. **LOCAL PRIVATE TRANSACTION ROUTING /
NOT_FROZEN / NO_PUBLIC_KEY_NAMESPACE_OR_EDGE_GO.** Continuation of the same
sole writer/draft PR96 from072a6f9; protected main remains e67f402.

[Allocation index and router](../../qualification/rendezvous/allocation-index.ts)
compose the existing allocation budget and actual transaction coordinator through
private RPC. Unknown transaction IDs are looked up in one fixed private index
before any child namespace ID/stub is obtained. The default harness returns503;
no public Worker route, product binding/configuration/dependency/D1, APNs/pairing,
consumer source or Cloudflare resource has changed. This is not service enablement.

## Admission and immutable routing

`AllocationIndex` contains a plain engine in a JS private field, exposing only
allocate/lookup/alarm. Its fixed object name is `djc-rendezvous-index/1`, with
namespace identity and exact enable-policy checks. Private allocate takes only
`{identity:{minute,key}}`: the previously qualified pseudonym from a trusted
server. It is not a client-provided identity or proof of actual edge provenance.
Closed fields, bounds and a copied input are checked before awaits/RPC.

The index calls the existing fixed-name budget exactly once for transaction
allocation. A public controller must **not** independently charge ingress and
index for the same create. Budget success precedes server UUIDv4 generation and
original `{id,createdAt,expiresAt=createdAt+120000}`. The original identity minute
is rechecked after budget RPC and inside final SQL after alarm awaits. A delayed
reply crossing minute/UTC-day boundary fails closed without refund or child
allocation. Policy is rechecked across those awaits too.

The earliest cleanup alarm is confirmed before index insertion. One synchronous
SQL transaction removes expired rows, bounds live cardinality at10,000 and inserts
the new immutable descriptor. Collision/SQL failure cannot overwrite another row;
there is no upsert, caller timestamp, caller descriptor or re-creation operation.
One allocation is in flight per engine, with overload returning a temporary
failure. No refund follows alarm/SQL failure or an uncertain budget/child reply.
The state is a bounded routing index, not a transaction capability registry.

The trusted router copies and bounds inputs and validates create's public key
before allocation. Its namespace/index/enable choices are constructor-only server
seams. Other operations use the fixed inspect/submit/poll/consume/cancel allowlist,
look up a valid UUID and verify the exact returned descriptor before namespace
access. Missing/expired/purged/changed/malformed lookup or disabled policy obtains
no child stub. Deadline/enable checks across awaits prevent late routing/results;
child state still enforces the original deadline at its final synchronous commit.

Membership grants **routing only**. Wrong browser secret/QR/generation/sender
proof remains denied by the child. No index lookup authenticates HA ownership,
selects a destination, decrypts an envelope or grants screen access. The router
returns internal typed results; public HTTP response mapping and all public route
coverage still need separate integration. Key namespaces are not covered here.

## Retention and uncertain outcomes

Index rows contain only UUID, original creation time and original expiry. These
are linkable routing metadata, not anonymous data. No browser key/secret, QR
capability, Apple key ID/proof, raw IP/pseudonym, destination or HA credential is
persisted in this index. No fetch or request/ID/body logging is introduced.

The alarm erases all expired rows and preserves the next earliest deadline,
even while admission policy is disabled. A failed cleanup throws for retry;
provider retry scheduling, monitoring, physical deletion/backups and data
processing terms remain unqualified. Request-time expiry is authoritative.
Restart preserves the original row/deadline; purge does not make an old ID a
valid lookup again. There is no permanent marker or mathematical guarantee
against a future trusted generator reusing a UUID; it must always use fresh
CSPRNG UUIDv4 and cannot accept a caller-selected replacement descriptor.

Lost child-create response leaves its original index entry until expiry. It does
not renew, retry create, generate another QR or authorize browser recovery.
Independent UX design review corrected the initial suggestion of an immediate
fresh allocation: if a QR may have been shown, existing confirmed-cancel/terminal/
original-expiry rules remain. If ID/deadline were lost, this increment cannot
authorize recovery or guess a server deadline. Any future exception for a proven
never-published QR and retired browser key/capability needs its own exact consumer
review; none is selected here. No extra user step is introduced.

## Executed evidence and failures

[Final source-bound observations](workerd-index-observations-v1.json):
**436/436 actual local workerd + isolated strict TypeScript PASS**:
68 index/router cases,46 budget regressions and322 transaction/framing/public
registration/assertion/storage regressions. The existing dedicated signed
software/JOSE flow is rerun unchanged, with software initial enrollment explicitly
named. New actual private index/budget/transaction RPC covers create/inspect/poll/
cancel and original binding, with injected namespace counters proving zero child
access for all five operations on unknown IDs. No synthetic readiness is reported
as a genuine native or complete HTTP rendezvous positive.

Coverage includes minute/midnight rollover during budget/alarm awaits, disabled
policy across awaits, exact one-charge point, copied inputs, quota/cardinality,
collision, lost budget and child replies, first/early/failed alarms, SQL rollback,
disabled cleanup/repaired retry, restart/purge/expiry equality, private RPC
containment, malformed lookup/allocation outcomes, wrong browser/QR and fixed
namespace/method selection. Provider operations and actual edge identity are not
exercised. Existing40 product regressions/root types, offline projection and107
schema cases/two clientData byte examples PASS.

Failures remain recorded: `a`435/436 had an input-copy mutation test aliasing the
shared public fixture JWK; each create test now clones that fixture. `b` had436/436
assertions but process exit1, therefore **not PASS**. A separate diagnostic run
identified four unhandled rejections from a new RPC-probe test that read a method
property and then separately called it. The corrected probes use the existing
separate direct-method-call versus awaited-property patterns; nothing is
suppressed or ignored. Run `c`436/436, zero pending and successful process exit. A final evidence
refinement removed dynamic synthetic UUID/timestamps from two parameterized test
names, using fixed case indices without changing predicates. Final `d`436/436+
strict types/process exit0 binds the committed sources and sanitized observations.

Reproduce with the existing pinned external dependency and JOSE directories:

```sh
node qualification/rendezvous/run_index_workerd.mjs /private/tmp/pinned-pki-deps /private/tmp/new-index-results /private/tmp/pinned-jose-package
```

The runner checks cbor10.0.12/PKIJS3.4.1/ASN1js3.1.0, both Apple public roots and
the existing JOSE6.2.12 file manifest, records source/toolchain hashes, blocks
fetch, disables telemetry/observability and uses eight temporary local SQLite
bindings only. Sequential files isolate the fixed global index/budget. Output
is0700, runner-owned files0600; committed observations contain fixed case names,
versions and hashes, not keys/capabilities/receipts/destinations. No dependency
install or private device diagnostic input was used. Root type generation is
unchanged because no root binding changed.

## Reviews, capacity and remaining gates

Independent design reviews preceded source. Security required original-minute
checks after both async boundaries and one clear budget charge point. UX required
unchanged fail-closed recovery after unknown create outcome. Full supplied-source
security and actual-file UX/privacy reviews, corrections and final exact-head CI
receipts are registered separately in API90/PR96; design approval alone is not
source acceptance. No complete-service/security or native approval follows.

One fixed index introduces a coordination bottleneck and additional RPC on each
routed request, plus budget RPC for create. The earlier capacity model's roughly
64 child calls/attempt omits those extra index/admission calls and is no longer a
complete model for this composition. Actual latency/throughput, SQL operations,
request/active-duration/storage costs and acceptable spend remain unmeasured.
No plan/quota/free-tier/SLA claim is made. Fixed index lookups bound transaction
namespace creation for the routed operations only; they do not bound arbitrary
edge request cost, key-namespace creation or bypasses through a future controller.

API retains complete public HTTP/state integration, response mapping, key namespace
and challenge/invalid-attempt admission, trustworthy edge IP, numerical cost and
operational retention review, full independent integration review and deployment
preparation. Joint exact consumer/security freeze remains required. Apple retains
fresh supported signed-iOS action/nonce/genuine composed-positive proof, with its
original diagnostic capture/ACK delivered. Receiver generator crossrun is delivered
and needs no unchanged repeat. Core owns actual HA/proxy and separate screen
admission; physical HA/iPhone/TV acceptance stays separate.

Rollback of this increment is a reviewed source revert; no deployed namespace,
migration or provider operation exists. Any future rollout requires its exact
reviewed artifact/manifest/private bindings and retention/cleanup monitoring;
source delivery and separate Finalization are not production authorization.

References: [DO coordination rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/)
and [SQLite synchronous transactions](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).
