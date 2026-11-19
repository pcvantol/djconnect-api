# Local HTTP ingress and allocation-budget qualification

Profile `0.4.0-draft`, wire `djc-rendezvous/1`, policy candidate
`djc-allocation-qualification/1`. **LOCAL COMPONENT QUALIFICATION / NOT_FROZEN /
NO_PUBLIC_CONTROLLER_OR_EDGE_PROVENANCE_GO.** Continuation on the existing sole
API writer and draft PR96; protected main remains `e67f402`.

[HTTP boundary](../../qualification/rendezvous/http-ingress.ts) and
[private SQLite budget](../../qualification/rendezvous/allocation-budget.ts)
are isolated components. The default harness and ingress factory are disabled;
they return503 before reading a body or invoking callbacks. Enabled tests supply
trusted constructor callbacks. Successful transport responses are schema-shaped
QA fixtures, not actual transaction/coordinator dispatch or sender authorization.
Production source, root bindings/configuration, dependencies, D1, APNs/pairing,
secrets, workflows and consumer sources are unchanged. No provider mutation.

## Transport candidate

The eleven existing POST routes under `https://api.djconnect.dev/v1/rendezvous`
use unchanged canonical request/response schemas. Create accepts4096 raw bytes;
register65536; submit32768; delete/recover16384; other requests1024. Streaming
byte counts enforce these bounds before decoding and before admission/dispatch;
Content-Length is checked but never trusted as the actual count. Absolute body
read deadline is5s, including stalled streams; cancellation cannot hold the
failure response open. Decoding is fatal UTF8, rejecting BOM. Closed shapes,
version, canonical base64/key/envelope encodings are checked before callbacks.
This is structural validation, not JWE authentication, App Attest or HA authority.

The candidate raw JSON parser accepts objects, strings and safe integer literals,
with JSON whitespace, depth<=8 and<=256 values. It rejects decoded duplicate keys
(including escaped duplicates), arrays, booleans, null, fractions/exponents,
unsafe integers and trailing input. These restrictions fit the current request
shapes and all eleven encoded positive fixtures. **They are additional proposed
transport syntax restrictions, not consequences of JSON Schema or a frozen
consumer compatibility promise.** Joint wire review must explicitly accept them
and actual consumer encoders before public integration. The schema helper is a
closed implementation of the currently used keyword subset, not a general JSON
Schema implementation; all107 existing schema cases pass, unknown keywords deny.

Content-Type accepts case-insensitive `application/json` optionally followed by
ASCII space/tab, semicolon, ASCII space/tab and `charset=utf-8`. Other parameters,
quoted charset and Content-Encoding (including identity) deny. Cookie and
Authorization headers deny. The exact visible URL must match a known route,
without query/fragment. These are checks on the URL/Headers exposed by Workers;
no raw request-target or raw duplicate-header detection beyond that API is claimed.

Only exact present Origin `https://vibecast.tv` is accepted. Browser create,
poll, consume and cancel require it. Native routes may omit Origin, which does
not supply any authorization: their eventual controller still verifies the
operation's proof/capability. OPTIONS allows exact Origin, POST and no requested
header or Content-Type alone, without admission/dispatch. Responses use no-store,
no-referrer, nosniff, Vary:Origin and exact ACAO only; no credentials, Location or
Set-Cookie. Dispatcher output is cloned and validated against a closed response
schema and fixed status map, preventing redirect/private-field passthrough.
Exceptions become fixed redacted errors; no request/body/ID/destination logging
or outbound fetch occurs. Enable state is rechecked across callback awaits.

## Allocation policy candidate and privacy

One private fixed-name DO `djc-rendezvous-budget/1`, guarded by its own namespace
identity and explicit policy switch, atomically counts selected allocation calls:

| Application policy | Candidate bound |
| --- | --- |
| Transaction allocations | 10,000 per UTC day |
| Key allocations | 500 per UTC day |
| Transaction allocations per IP pseudonym | 5 per minute |
| Live IP bucket cardinality | 10,000 |
| IP bucket application expiry | minute start+120s |
| Aggregate counter application expiry | next UTC midnight |

These are proposed application caps, not Cloudflare quotas, a load result or an
approved spend limit. Denial cannot allocate a new bucket or increment a daily
count. Counter and bucket writes are one synchronous SQL transaction. DO time
chooses windows and is rechecked after alarm awaits. The earliest alarm is armed
before writes and preserved; failed alarm/SQL work fails closed. No refund occurs
for downstream failure or a lost reply. Cleanup runs while admission is disabled;
SQL cleanup failure throws for retry. Actual provider retry/monitoring/physical
retention, backups and capacity remain unqualified.

The trusted server helper canonicalizes an already trusted edge IP and computes
standard HMAC-SHA256 with a separate32-byte server secret over the exact JSON
array `["djc-rendezvous-edge-ip/1", minute, canonicalIP]`. DO rows contain only
minute pseudonym/count/expiry or aggregate day counts. The secret and raw IP are
not persisted there. Pseudonyms are linkable within the minute, not anonymous;
with access to the secret they can be recomputed. Minute-dependent input is not
proof of secret rotation. Secret provisioning/rotation/retirement and trustworthy
real edge IP provenance require separate operational review. Never use a client
X-Forwarded-For value or reuse an APNs/pairing secret as authority.

The admitted private caller must invoke this budget before allocating persistent
transaction/key state. **This component does not establish coverage of every
public route or unknown DO ID.** A naive controller can still instantiate arbitrary
namespace objects before admission. Trusted immutable allocator/index/routing,
coverage of missing IDs, challenge/invalid-attempt budgets, global edge controls
and request-cost containment remain API-owned work before public runtime. No
unsigned-app fallback or HTTP field may manufacture a private admission grant.

## Executed evidence and review scope

[Source-bound observations](workerd-ingress-observations-v1.json):265/265 actual
local workerd cases plus isolated strict TypeScript PASS. Includes107 canonical
schema fixtures, all11 route bounds, origin/preflight/version/encoding/parser
failures before callbacks, stalled-stream timeout, redacted failures, fixed
response validation, disable races, actual private budget RPC with transport QA,
HMAC against an independent Node standard-library computation, atomic global/IP
ceilings, concurrent writers, rollback, restarts, retention and alarm failures.
A future logical clock and sequential test files isolate the single global DO.

Initial run `a`:247/251, retained locally. Two alarm expectations used a past
logical time while parallel files shared the fixed global object; the runner now
uses sequential files and tests use a future logical clock. Those changes were
made together, so the individual framework contributions were not isolated.
One cleanup fault test referenced a misspelled local variable. A parser node-limit
probe exceeded the poll route's byte limit and correctly got413; moving it to the
larger register route exercises parser400. Final `b`:251/251. No security predicate
was weakened. Existing product API40/40, root TypeScript, offline projection and
107 schema cases+2 clientData byte examples also PASS. Prior322 transaction-suite
results remain their separately source-bound evidence; they were not rerun for
these additive files. No native/private input or dependency install was required.

Independent source security review found P2: the stream reader did not recheck
absolute deadline/abort immediately after its await, allowing a late final read
to beat timer processing. Both conditions are now checked after every read and
before returning the body. Four actual-workerd regressions exercise data/final
read crossed with exact deadline equality/abort, all before admission/dispatch.
Final `c`:255/255+strict types PASS supersedes current source/result hashes;
the earlier251 results remain historical. Concrete correction re-review is a
separate receipt, not inferred from the design review.

The final targeted security check found that variable base64 fields allow
alphabet-only strings whose length is1 modulo4 in the structural schema. Native
atob would throw, previously falling through to a503. The canonical encoding
guard now rejects that length before decoding as invalid_request400. Ten new
cases cover attestation/assertion/clientData and JWE header/ciphertext at lengths1
and5, explicitly proving schema acceptance followed by400 with zero callbacks.
Final `d`:265/265+strict types PASS; unchanged prior255 evidence is historical.

Independent design review preceded source implementation. Full supplied-source
security review and actual-file UX/privacy review, concrete findings and any
corrections are registered separately in API90/PR96. Supplied-source review is
not independent Git/hash readback or test execution. No full-service/native or
production approval follows from these component reviews.

Reproduce with existing repository dependencies and a new isolated output path:

```sh
node qualification/rendezvous/run_ingress_workerd.mjs /private/tmp/new-ingress-results
```

The runner copies exact source/schema/helper inputs and records hashes/toolchain,
uses one temporary SQLite binding and local-only migration, blocks fetch, disables
telemetry/observability and stores diagnostics locally. Output directory0700;
runner-owned files0600. Committed observations contain fixed test names, source
hashes and versions, never keys, capabilities, user IPs, destinations or ciphertext.
No production binding was changed, so root type regeneration is unnecessary.

## Operations, rollback and remaining owners

This increment cannot be enabled in production. A future operational manifest
must bind exact artifact/classes/migrations, a private ADMISSION_STATE binding,
separate justified abuse secret, trusted ingress identity, enable policies,
expiry/cleanup alerts and numerical capacity/cost evidence. Rollback here is a
reviewed source revert; no deployed namespace or provider rollback exists.
Future rollout must preserve compatible cleanup classes and never infer that
Worker rollback reverses namespace migrations. See the existing
[deployment preparation](QUALIFICATION_AND_DEPLOYMENT_V1.md).

API retains actual public controller/state integration, trusted immutable create
allocation and response mapping, unknown-ID coverage, complete abuse/operations
review and deployment preparation. Joint exact contract freeze remains open.
Apple retains fresh supported signed-iOS nonce/action/genuine composed-positive
proof; the prior diagnostic capture and ACK0.4 are delivered, no new key/capture
request. Receiver's exact-generator crossrun remains delivered, no unchanged
repeat. Core retains real HA/proxy route and separate display admission; physical
HA/iPhone/TV acceptance remains separate. Address sent/ready/consumed/navigation
initiated never means display admitted or VibeCast connected. Temporary failure
permits only bounded retry within the original deadline; it does not add a login,
manual IP, new pairing/key, or session-ending authority.

References: [Workers Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/),
[SQLite storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/),
[DO coordination](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/).
