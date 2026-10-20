# Rendezvous deployment preparation, not authorization

Current preparation is rebound to immutable supplying source
`6d730476e378ba62c77de8213564c683343a3e43` (source-disabled root integration;
protected delivery and separate Finalization require their own exact evidence).
The supplying SHA is protected main, not an intermediate PR commit: main-only
checkouts must retain the proof after squash and automatic branch cleanup. All
proof and runtime hashes are unchanged by this provenance-only correction. The
new regression executes the validator in a depth-one checkout with the old
intermediate object absent; there is no lazy fetch, fallback or weaker check.
Historical PR101/102 proofs and prior supplying source remain unchanged.
The released SOURCE/WIRE
interface remains **djc-rendezvous/1-implementation.1**; no consumer ACK reopens.
Operational profile `0.4.0-draft` is not production/activation approval. The current
[preparation manifest](deployment-preparation-v1.json) merges three independently
reviewed immutable proofs:66 shared,19 current module/qualification and85
current root-build input records, producing exactly106 unique tracked source
pins after canonical overlap checks. The new root/module proof files are distinct
from the historical product-composition observations; changed root/dispatcher
bytes do not rewrite earlier evidence. The four new unique pins are the dispatcher
and three local qualification files. The private native host reads this current
root proof so it cannot silently overwrite the new index pin with an older hash.
Only32 explicitly prefixed node_modules inputs are excluded from Gitblob checks;
package/lock/provenance remain pinned. This does not verify installed packagebytes
or prove reproducible dependency source builds.

The same existing validator preserves offline Git/no lazy fetch/prompts/replacements,
closed JSON, size and symlink/path controls. Supplying SHA and all three proof
digests are independently hardcoded; mutable preparation cannot define its own
truth. Additional references pin current workflows, released contract and complete
licence documents. [Source/module context](PRODUCT_COMPOSITION_V1.md) and
[current operational procedure](CURRENT_OPERATIONS_PREPARATION_V1.md) distinguish
source delivery from real edge/native/HA/TV and authorization evidence.

All22 full-service operational gates remain OPEN and account/plan/artifact/approval/
central manifest/public entrypoint remain null; activation false. In particular,
`joint_contract_freeze` here means full-service/profile/activation acceptance,
**not** another source-wire implementation HOLD. Proposed fiveDO bindings,
SQLite tag and closed policy configuration are preparation only; deadline/revision
remain null, secret values absent. No proposed flags can activate the current root503.
[Known version50 inventory](known-worker-version50-readonly-v1.json) is readonly,
not current-deployment-split/routing/WAF/billing/migration collision proof.

Run offline checks:

```sh
python3 scripts/validate_rendezvous_deployment_plan.py
python3 scripts/test_rendezvous_deployment_plan.py
```

The first reports only `PREPARATION_CONSISTENT_BLOCKED_NOT_AUTHORIZED`; exit0
means preparation consistency, never deployment readiness. There is no execute,
approve, fetch, upload or dispatch mode.27 negative/consistency tests cover false
authorization/artifact/gate promotion, source/hash/config drift, unknown fields,
software/legacy bindings, duplicate JSON/nonfinite values, oversize, lexical and
actual symlink escape, and --execute refusal. Immutable Git blobs and a separately
hardcoded supplying SHA/proof hash prevent a modified plan defining its own truth.
Current working bytes must match that baseline. Error output is fixed/redacted.
Independent security review found that Git could lazily fetch missing objects in
a partial clone. The validator now forces GIT_NO_LAZY_FETCH=1, disables prompts,
optional locks and replacement objects, clears inherited Git overrides, and fails
closed on missing local blobs. Two additional tests cover these controls and an
actual absent blob; the initial19 tests passed before this review correction.
[Git documents these offline controls](https://git-scm.com/docs/git#Documentation/git.txt-GITNOLAZYFETCH).

## Historical preparation receipts

The source history below does not override the current102-pin preparation.

The original74926a4 preparation pinned49ec and53 source hashes. The previous
b1dee17 rebind pinned86c80fa's961-case proof and56 hashes. The historical supplying083ddb2
contains the independently reviewed transaction4-attempt cap,28/2/2management
slots and controlled enrollment receipt-config503;1002local cases/58source hashes.
The old86c80fa validator correctly rejected those changed bytes before this
separate rebind. Its new proof SHA256 is
28c978c070d77b5c7dae726935b562e1aa048c26948dbb8d96112370a46df3b6.
Only validator constants/count and generated plan pins change; Git offline controls,
validation control flow and22OPEN/null/false gates remain unchanged. Old961 and
provider/cost receipts remain historical, not rerun or relabeled by this package.
The request RPC graph is unchanged; charged submit-challenge reservation adds one
SQL write, not an extra RPC, and is not included in the old partial cost estimate.
[Exact contract readiness](CONTRACT_READINESS_V1.md) distinguishes concrete
CREATE-RECOVERY/POLL-NAT/APP-RECOVERY/EXACT-RELEASE HOLDs from operational/live gates.
Independent source/security and actual-file UX/evidence review and exact-head CI
receipts belong on API90/PR96. Neither offline consistency nor CI closes an operational gate.

## Read-only existing-service readback, 2026-10-19

[Redacted provider inventory](cloudflare-readonly-readback-20261019.json) records
successful existing Wrangler authentication and GET-only deployment/version reads.
The list is ascending: select newest by created_on, not array position. Deployment
35f47d4e-11fe-48cc-a8fe-82f770e260d2 from2026-10-01 selects version
d7f38154-51ca-4066-9d61-f64e0df0dda5 at100%. Its DB identifier matches the existing
root D1 configuration. None of the five proposed bindings or three proposed secret
names is present on that version; secret values were neither printed nor stored.
This is evidence about this existing service/version, not a live rendezvous,
domain/route-health, account-plan/billing or complete namespace inventory result.
The earlier first array entry was historical and is not represented as current.
No resource was changed. All22 full-service/operational gates remain OPEN.

## Exact proposed component inventory

| Private binding | Selected contained class | Original state lifetime |
| --- | --- | --- |
| REQUEST_ADMISSION | RequestAdmission | Minute/IP counters minuteStart+120s; day aggregates UTC midnight |
| ADMISSION_STATE | AllocationBudget | IP counters minuteStart+120s; daily allocation/key-call aggregates UTC midnight |
| ALLOCATION_INDEX | AllocationIndex | UUID/creation/expiry only, original120s |
| COMPOSED_TRANSACTIONS | BudgetedTransactionCoordinator | Original120s; consume/cancel erases ciphertext |
| ENROLLMENT_COORDINATOR | EnrollmentCoordinator | Active key maximum30days; tombstone original key expiry+120s |

EnrollmentCoordinator contains assertion/receipt storage; separately exposed
ReceiptKeyStore/AssertionKeyState/TransactionCoordinator and Software* bindings
are QA fixtures, not this product proposal. The eleven local-test bindings are
not an eleven-class production migration. Constructor-only namespace seams still
need exact public-adapter/build/type qualification; this inventory is not a bundle.

The proposed SQLite migration tag `djc-rendezvous-sqlite-v1` is unreserved and
collision-UNVERIFIED. Before an approved deploy, read back existing account,
service/version, namespaces, class/tag history, routes and bindings. Record exact
hashes/IDs without token values. Reject collisions or divergent class/storage
state; do not delete/rename existing resources to force admission. Existing D1,
APNs relay, pairing issuer, operator routes and secrets must stay intact.

Service/browser origins stay https://api.djconnect.dev and https://vibecast.tv.
No new site or domain is selected. An eventual isolated router in the existing
Worker must import only selected genuine paths; every relevant route/OPTIONS/
error must exercise admission. The old private QA factories are not public
entrypoints. Missing bindings/config/provider support must fail503. Root config
and generated types have not changed; no migration/type-generation/deploy run.

## Public edge and abuse readiness

API must qualify the actual request path: direct edge, same-zone Worker,
cross-zone Worker, alternate workers.dev/preview/service bindings and any proxy.
A caller-provided header or a locally constructed request.cf is not proof of
edge provenance. Reject ambiguous/missing identity; no arbitrary X-Forwarded-For
fallback. Cloudflare documents altered same-zone x-real-ip semantics and Pseudo
IPv4 header replacement; these settings need real readback and negative probes.
[Cloudflare header reference](https://developers.cloudflare.com/fundamentals/reference/http-headers/).

A local injected identity only establishes the downstream HMAC/counter contract.
Select and review an applicable edge policy for Worker forwarding and IP removal/
normalization; test IPv4/IPv6/equivalent forms, shared NAT, forged headers and
alternate ingress. Never use IP as HA/app-owner authentication. Preserve exact
Origin/CORS, streamed payload/deadline limits and response redaction on all paths.

Apply reviewed edge WAF/rate/request-cost controls before Worker/DO admission;
then test actual account-plan behavior, bursts and distributed rejected traffic.
The fixed global DO is an unqualified bottleneck and admitted counters do not
cap rejected Worker/DO charges. Candidate1m/day,10k/minute,120total-IP-minute,
20native-IP-minute,10kallocations/day,500registrationATTEMPTS/day and50kkeycalls/day
require joint consumer/operations approval and load evidence. No automatic threshold
raise, fail-open fallback or silent retry when the fixed coordinator overloads.

## Secrets, logging and provider operations

Only secret NAMES appear in preparation: RENDEZVOUS_IP_HASH_KEY is a proposed
32-byte HMAC secret, RECEIPT_ACTIVE_KEY the existing encryption key input and
RECEIPT_PREVIOUS_KEY optional rotation material. Their provider presence/ownership
and separation from APNs credentials are unverified. No values are generated,
read, printed or installed. Never store HA/Profile/Session bearers.

A hash-key rollout must not split one minute across inconsistent secrets and
silently multiply per-IP allowance; review boundary/version consistency across
running versions. Receipt-key rotation must preserve old encrypted receipt access
until records are re-encrypted or naturally expire; the existing one-previous-key
mechanism must not be discarded by a second premature rotation. Recovery must
not require new device keys or pairing merely because operators rotated secrets.

Root observability currently samples existing Worker requests. Qualify actual
platform logs, headers/URL metadata, tails, exceptions, exports, retention,
backups and DPA/access policy before adding a rendezvous route. No bodies, proofs,
QR/claim capabilities, keyIDs, decrypted destinations or user-IP identifiers in
application logs. Diagnostics may use fixed route/code/count/latency labels;
aggregate overload, provider unavailable, cleanup/alarm failures and retained-row
age must be observable without sensitive labels. Platform collection and physical
erasure require evidence, not a no-console.log source claim.
[Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/).

Prove configured Apple path/CMS/status egress, bounded provider timeout/no redirects,
receipt freshness/revocation and provider-versus-invalid-proof taxonomy with genuine
supported signed-iOS input. Local software enrollment and prior diagnostic captures
are distinct; no unchanged capture or receiver crypto crossrun is requested.

## Protected artifact and deployment sequence

1. Joint exact contract/security/operations review closes relevant producer gates.
   Public integration/build and supported native proof must then be qualified on
   exact source. Existing scoped source/consumer ACKs remain preserved.
2. Obtain normal protected source delivery and separately bound Finalization.
   Build immutable product artifact with actual handler/class exports, dependencies,
   closed schemas/vectors, configuration/migration and rollback-compatible cleanup.
   The current root artifact bundles the existing API; this preparation is not proof
   it contains rendezvous code or that its hash authorizes these components.
3. Publish/review an applicable CENTRAL operational manifest, exact artifact ID/
   SHA256/source SHA, account/namespace/config, approved spend and rollback pins.
   Existing deploy-api-worker.yml is hardcoded to PLATFORM_4_0_RC2_API_OPERATIONAL_MANIFEST;
   it does not consume this preparation and is NOT a rendezvous authorization.
   Any future consumer change uses normal review/CI; no bypass or dispatch here.
4. Obtain explicit exact production-deployment authorization. Read back the prior
   deployed artifact/version/config, private bindings and migration state. Apply only
   the approved artifact/binding/migration set through the applicable protected path.
5. Perform authorized synthetic smoke, provider/config/log readback and existing
   APNs/pairing/operator regressions. Separate genuine Apple/HA and physical TV
   acceptance determines user-facing connected claims, not source merge or HTTP200.

## Rollback and smoke matrix

Before deployment, preserve prior version/artifact hashes, binding/class/migration
readbacks and compatible cleanup code. On trouble, block new creation and unsafe
admission, fail closed, and drain original transaction/key deadlines. Do not renew
QRs, re-enroll devices, delete namespaces, wipe D1 or remove receipt keys. A prior
Worker may not export new classes or implement their alarms: rollback must retain
compatible classes/bindings and cleanup until all original retention windows end.
No verified rollback artifact exists yet; a Worker version rollback does not prove
state-migration reversal or physical deletion. Namespace removal is a separate
explicitly reviewed irreversible operation.

| Authorized smoke | Required readback; never log proof material |
| --- | --- |
| Version/config | Exact source/artifact/config, selected bindings/classes/tags; no preview bypass |
| Transport | Every route, OPTIONS/CORS/wrong Origin, body/time limits and no-store errors |
| Rendezvous | Synthetic120s original expiry, wrong browser/QR, competing submissions, one consume/replay/cancel |
| Quotas/outages | Edge+DO limits, bounded Retry-After, missing hint fallback, provider/gate failures without new QR/key |
| Lifecycle | Restart, alarm failure/retry, disabled cleanup, physical retention/backup/log policy evidence |
| Existing service | Separate APNs relay/pairing/operator/D1 health, with redacted evidence |
| HA/native/TV | Supported iOS -> selected external HA -> independent screen admission -> physical browser; separate result |

Missing external HA route is a clear app-side no-route outcome; unreachable HA
after navigation remains unreachable, not rendezvous failure mislabeled as pairing
or screen permission. Browser must keep original context/expiry checks and validated
HTTPS path before navigation. No central destination fetch or speculative HTTP/IP
fallback. Receiver adapter stays contract-gated; timer stays stopped.

[Cost/capacity scenarios](COST_CAPACITY_MODEL_V1.md) correct the old64-call estimate.
All22 gates remain OPEN. Account, migration collision, exact product bundle,
full edge/provider/native proof, approved spend/retention and rollback/live smoke
remain actual missing evidence; no deployment permission is requested by this check.

## Subsequent capacity evidence, same runtime pin

[Shared-NAT qualification](CAPACITY_QUALIFICATION_V1.md) adds test/evidence only.
Current runtime58pins still match083ddb2; the22OPEN/null/false plan is not rebound
or promoted. Receiver numerical reviews6266032306 are received. API's four-screen
functional target remains HOLD on measured/replayed capacity outcomes, distinct
from provider/account/load/spend/retention and later production authorization.


## Historical separate partition-source preparation rebind

Old083ddb2 preparation correctly rejected changed /2 admission bytes before S1.
Only after independently reviewed immutable supplying source **98e755091a51671b2ad7ced87fad504064f7290d**
was committed, this separate S2 rebind pins its compact1118-case/62source proof
SHA256337a5fa855ea370ec5cc991d8e73298e2ceb1a4999c0043ea92a1b6aa365a35e.
The [compact proof](workerd-partition-source-proof-v1.json) is derived from final
c execution, carrying all test cases/source pins and66hashed observation receipts,
with full proof hash2e558c8dea4c506442d622e305fedac5369d69ab647f0e7ff7b87ac2b6644a07.
It is not another execution. The independently reviewed full3.13MB observation
file remains immutable S1 evidence. The offline validator reads the compact proof
and its62source blobs; it does NOT read/reparse the full observation file. This
preserves the existing1MiBJSON/2MiBblob guards, Git offline controls and all other
validation control flow; only supplying/proof constants and62count change.
All22gates stayOPEN, activationfalse and account/approval/artifact/entrypointnull.
Policy/2 requires route partitions and two extra bounded SQL tables; old unexpired
IP rows without partitions fail503 until originalexpiry, never reset. Terminal
quota is no executionpriority guarantee, and current partial cost models are
historical because SQL work and admitted IP ceilings changed. Deployment/rollback
needs separate exact artifact and bindings authorization; no public activation.
[Current local qualification](ADMISSION_PARTITIONS_QUALIFICATION_V1.md) is
54/54target scenarios/126consumed, no native/public/load/SLA/contractfreeze claim.
API retains lost-create recovery and joint exact release; timer staysoff.


## Historical separate pre-QR reference proof rebind

The historical supplying source **ff9ff5778f698fc206d7953b9f407752d7dde840** includes
the reviewed proposed recovery contract/reference, current-main tools and65source
pins/1184local checks. No APIserverruntime/endpoint/schema/crypto/binding changes.
Old98preparation remained valid for its older unmodified runtime scope; no false
rejection is claimed. This separate S2 selects the new compact proof
SHA25623404d85009af067941fe7b6621f66aa9beb623946feddfea5ae3bf63903a6db.
[Qualification](CREATE_RECOVERY_QUALIFICATION_V1.md) explains final b evidence and
the known-non201 deadline race independently found and fixed before acceptance.
The compact is derived metadata/testreceipts/65pins/72observationhashes, NOT a
new execution; full3.14MB proof hash
c754a344ecfa4a23467d402feffca33bed52d73be52568810fa4617b5ca05e97
is immutable independently reviewed evidence, not read/parsed by this validator.
Only supplying/proof/count constants and generatedplan change:1MiBJSON/2MiBblob
limits, Git offline controls and all validation control flow remain unchanged.
All22gates OPEN, activationfalse and account/approval/artifact/entrypointnull.
The proposed preQR exception requires NEW exact receiverACK/adoption before
freeze; this package activates no receiver, timer, public router or deployment.
Existing true Apple/HA/physicalTV/provider/load/cost/retention/security gates remain.


## Separate shared app-key evidence rebind

Current supplying source **cf749619c9d3d101e7f7bc5fb7ae48ec71512f8a** adds only
shared-key tests/runner/evidence/docs, no server/consumer runtime/schema/policy.
Oldff9ff57preparation remains valid for its older unchangedruntime scope; no false
rejection is claimed. This separate S2 selects66source/1208case compact proof
SHA256571165023527302d5fdbb3873a02c3614992a44a20d6fc8866631a2d92da4106.
[Shared-key qualification](SHARED_APP_KEY_QUALIFICATION_V1.md) separates24assertion
targets from22deliverycases/58consumes and2expected expiryrefusals. The96hashed
observations/1208case metadata are derived from final c, NOT another execution.
Full3.20MB proof hash1710c49918c66ff3c7302cf422f00fd37477ebb9f8505122e31d0b398919bc83
is independently reviewed immutable evidence, not parsed/read by this validator.
Only supplying/proof/count constants/generatedplan change; existing offlineGit,
1MiBJSON/2MiBblob limits/control flow and22OPEN/null/false gates are unchanged.
No nativequeue/24h/twohandle/day27replacement policy or per-installation identity
is qualified; NEWpreQR exception acceptance6269829702 is still required before
freeze. No repeatedrequest/newwriter/publicactivation/deployment; timer staysOFF.
