# Local SQLite DO encrypted receipt storage qualification v1

Same API94 writer; profile0.4.0-draft/wire djc-rendezvous/1 NOT_FROZEN.
**Scoped internal storage qualification only — no public enrollment, proof,
certificate-status, complete-verifier or runtime-admission GO.**

[Typed component](../../qualification/rendezvous/receipt-key-store.ts),
[tests](../../qualification/rendezvous/receipt-key-store.check.ts),
[sanitized executed results](workerd-storage-observations-v1.json): **39/39 PASS**
under actual local workerd/SQLite Durable Objects, plus isolated TypeScript7.0.2
check of component/harness/existing crypto helper. This is persisted local DO
execution, not an in-memory map or modeled counter. It is not a provider deployment.

## Boundary and storage format

The test class ReceiptKeyStore isolates part of the eventual private per-key
AttestedKeyState coordinator. It is **not** a second production namespace or
another source of key/counter authority. Adoption must integrate with the single
coordinator and qualify its complete verifier/action/lease/recovery contract.
The local Worker export returns503 for every public request. Only temporary
config creates a local binding/SQLite migration; root product config is untouched.

Material is explicitly trusted internal test input, not App Attest/CMS verification
or a `verified:true` public claim. Synthetic public data/keys exercise storage;
no actual device capture or raw user data is used in these tests. Bounds/fixed
qualification app/environment, canonical key-address/digest/operation identifiers,
receipt age<=5min, original challenge<=120s and current deadline are checked.
The public point receives storage shape checks only, not a substitute for the
qualified cryptographic point/credential binding. No destination/HA credentials.

The exact existing src/crypto.ts helper is copied and imported by the local
harness, with its source hash recorded. Standard WebCrypto AES256GCM uses random
96-bit nonce/full default128-bit tag; no new encryption protocol/helper fork.
Separate receipt-key configuration is synthetic and never uses APNs/relay keys.
Authenticated plaintext binds DO identity, key address, app/environment/policy,
public point, original created/expiry, receipt creation and key version to the
receipt. Decryption requires exact context and the owning DO, including when an
entire row is transplanted and its visible DO ID is rewritten.

One SQL row atomically owns encrypted receipt+public key+counter+revision. Original
key expiry is at most30days; retries, counter changes, reads and rotation never
extend it. Enrollment operation ID/digest/challenge deadline are removed at their
original120s deadline, not kept for the key lifetime. Expiry/revoke removes all
sensitive row fields, leaving only version/status/key-address/original expiry/
purge_at. The tombstone is erased at original key expiry+120s, including early
revocation. No permanent device ban/index, owner registry or receipt digest index.

## Async ordering, atomicity, rotation and cleanup

Crypto runs outside the synchronous SQL transaction. Before storing sensitive
state, the DO confirms a durable cleanup alarm. An instance-local queue serializes
alarm writes/precommit sections; a pre-existing earlier alarm is never postponed
by install. Inside SQL, recheck current time/material/record/deadlines and prevent
existing-key overwrite, counter reset or new expiry. Record+receipt commit together.
The queue is no durable authority: a precommit crash leaves no sensitive row;
a postcommit crash already has the confirmed persistent alarm.

An independent review found oneP2 in the first design: postcommit first-alarm
failure could otherwise leave data without cleanup if no client retried. Corrected
order is **confirmed alarm first, sensitive SQL second**. Tests show first-alarm
failure creates no sensitive row; later rearm failure leaves the confirmed alarm,
and cleanup completes through alarm callbacks without install/recover/read retry.
Manual local alarm execution proves that trigger/callback path, not real provider
scheduling, global durability/failover or the15min operational cleanup target.

Read checks active/owning DO/deadline, decrypts by allowed current/previous key,
verifies context, then rechecks revision/state/deadline after awaits. Rotation
changes encryption key/nonce only and uses revision/state comparison after crypto;
concurrent revocation cannot resurrect evidence. Counter advancement is an actual
atomic unsigned monotone storage primitive, **not assertion authorization**.
Known policy/operator admission checks remain in the future complete coordinator.

Expected RPC denials return one typed generic error without exposing exception
messages/body/key existence to a public caller. Alarm failures still throw a
fixed cleanup error for provider retry semantics. SQL cleanup failure denies
access; a manually retried local alarm removes sensitive fields after repair.
Provider retry timing/incident monitoring is not qualified by this test.

## Executed cases and preserved failures

39 actual tests include ciphertext/plaintext absence; wrong/missing/current/
previous key, rotation and failed old-key rollback; every authenticated context
field and full-row cross-DO transplantation; SQL-trigger abort/registration rollback;
duplicate installs and same-counter concurrency; original operation expiry;
revocation/expiry equality/tombstone purge; local DO memory restart preserving
SQLite/counter/ciphertext/expiry; rotation versus revoke; first/postcommit alarm
failures without client retry; cleanup failure and manual retry. Deadline clocks
are explicit local fault injection, never a caller-selectable server clock.

Initial runner setup failed against an unsupported compiler package subpath and
removed baseUrl option; corrected for the actually installed TypeScript7 CLI.
Two33-case runs passed assertions but failed whole-process execution because
expected RPC exceptions were reported as uncaught. Typed denials fixed this;
those runs are not successful qualification. A later37-case run had36PASS/1FAIL:
a test set receipt creation only1ms ahead of RPC dispatch, but arrival legitimately
occurred after that time. A farther-future fixture fixes the test without changing
server time enforcement. Security review's cleanupP2 then added the no-retry
paths. Final39-test/typecheck pipeline passes; failed artifacts remain retained.

Installed Node26.12.0, pool0.22.0/Miniflare5.20260815.0-alpha/workerd1.20260815.1;
compatibility date2026-06-20/nodejs_compat. Exact component/test/runner/helper
hashes bind results. No optional library installation or product dependency change.

## Reproduce and remaining review gates

```sh
node qualification/rendezvous/run_store_workerd.mjs /private/tmp/new-receipt-store-results
```

Requires the existing repository test/compiler dependencies only. Output directory
must not exist; created0700, generated files0600. No private fixtures, real secrets,
network status lookup, Cloudflare account/binding mutation or deployment. The
runner's local binding/migration cannot be used as an authorized production manifest.
No product bindings changed, so product wrangler type generation is not needed.

Supplied-guards/results independent technical review initially withheld finite
retention GO for cleanupP2, then confirmed corrected **scoped storage GO**, no
remainingP1/P2 in supplied scope. UX/privacy/evidence scoped GO. Reviewers did not
independently inspect files/libraries/SQLite state or execute tests. No complete
storage/privacy/runtime/deployment approval is inferred.

[Revocation policy candidate](REVOCATION_POLICY_CANDIDATE_V1.md) now distinguishes
explicit offline pinned App Attest trust from required authenticated receipt status.
It had scoped design reviews at this storage checkpoint. The later
[status component](WORKER_STATUS_QUALIFICATION_V1.md) adds local OCSP/CRL/cache
evidence; production egress/cache/propagation remains unqualified.
The dated public CRL sample is no live status cache or signer-status proof.

Still required: complete verifier/status/action composition; production receipt-key
provisioning/rotation/retirement/rollback; actual provider alarm/cleanup monitoring/
incident response and backup retention; full race/recovery/revoke/admission review;
consumer freeze and physical HA/iPhone/TV chain. No physical erasure from SQLite
pages/provider backups or hardware key deletion is promised. Existing APNs/D1/
operator and consumer source remain unchanged. Protected delivery, Finalization
and production deployment remain separate.

Primary implementation guidance:
[Cloudflare DO rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/),
[SQLite storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).

Current existing API verification:40/40 regressions,107 structural schema cases
plus2 clientData byte examples, typecheck, offline projection, whitespace and93
local links PASS. Secret scan102 unchanged baseline lines/no new matches. No
user-facing translations changed; language review remains an eventual release
gate. Normal CI is separate from these optional local DO qualification tests.
