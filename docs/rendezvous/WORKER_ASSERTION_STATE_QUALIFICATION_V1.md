# Local SQLite assertion, challenge and counter composition v1

Same API94 writer, profile0.4.0-draft/djc-rendezvous/1 **NOT_FROZEN**.
**Trusted fixture enrollment; no complete enrollment, native wire or runtime GO.**

[Typed coordinator](../../qualification/rendezvous/assertion-key-state.ts),
[actual tests](../../qualification/rendezvous/assertion-key-state.check.mjs):
[75/75 local workerd cases + isolated types PASS](workerd-assertion-state-observations-v1.json),
[73/73 public-only + types PASS](workerd-assertion-state-public-observations-v1.json).
These comprise39 original encrypted-storage regressions,34 new software action/
state tests, and two optional genuine diagnostic Apple-signature tests. Current
source/helper/runner hashes bind results. No product source/dependency/config/
binding/secret/D1/workflow or consumer source changed. All QA HTTP requests return503.

## One SQLite authority, qualified assertion crypto and exact bytes

AssertionKeyState extends the existing ReceiptKeyStore, using its same key row,
encrypted receipt, public point, counter and original30day lifetime. It is not
a second production registry/namespace or a public enrollment endpoint. Both
classes are exported solely in temporary local test bindings so the original39
regressions and composed class run together. Protected/no-op lifecycle hooks
share cleanup scheduling and erase operations inside the key's tombstone SQL
transaction. The original AES helper and qualified assertion verifier are reused
unchanged; no hand-written signature conversion, KDF or new token protocol.

This test component starts from **trusted fixture enrollment**, not verified
AppAttest/CMS/status enrollment. Direct install/advance/evidence fixture methods
are disabled on the composed class. Tests seed the inherited store through
runInDurableObject/base prototype only. TypeScript protected/private helpers
are not an untrusted RPC security boundary; inherited QA hooks/helpers and
private routing/least-privilege surfaces still require production integration
and full review. No hardened product RPC/admission claim is made.

Fixed ios-dev-qualification/1/development policy and its server-configured expiry
are checked on issue, authorization, retry and private lease lookup. Key address
is SHA256 of the exact JSON array [development,policy,canonical key ID]. Public
keyID uses canonical padded32-byte standard base64; challenge ID/nonce use
separate random32-byte base64url43 values, matching wire schemas. The earlier
storage-only enrollment fixture's UUID operation ID is test metadata, not a
qualified registration-wire adapter; that full integration remains open.

Management challenges coalesce one unconsumed operation per key/action for
known and unknown keys without a new key row or renewed deadline. Server creates
the exact closed recover-key/delete-key clientData. Submit additionally saves
the internally supplied authoritative transaction/generation/browser thumbprint/
envelope digest/original expiry, never a URL/ciphertext/QR capability. A new
candidate ID collision denies rather than overwriting an existing operation.
All operations together are limited to32 unexpired rows per object, each<=120s.
Private routing to the correct global per-key object, transaction authority and
aggregate/edge admission limits remain integration preconditions, not test proof.

Canonical bounded request bytes must exactly match the server-saved bytes/action/
key/operation. There is no request JSON reserialization before signature checking.
The unchanged AppAttest core verifier checks its measured development app/profile,
signature/hash layering and strictly higher unsigned32 counter. One active
authorize call per object rejects overlapping work without an unbounded crypto
queue. This is not general/global CPU or allocation control.

## Atomic commit, immutable retries and finite cleanup

After asynchronous digest/signature work, one synchronous SQLite transaction
rechecks current policy, active key/public point, original key timestamps,
operation/action/exact bytes, original deadline and counter>current counter.
Counter advance, nonce consumption and immutable operation receipt commit together.
SQL failure rolls back all three. Successful receipts contain binding/digest/
counter/times/result only: remove raw clientData, nonce and proof; no destinations,
credentials or owner/Profile/Session index. Database state remains the trusted
counter authority; this is not tamper/rollback resistance against a compromised
provider/operator or physical storage access.

Recover-key returns only original key expiry and its internal counter result.
An identical exact-request retry can recover that same receipt before the
original deadline while key/policy remain active. It never resets a counter or
key/operation expiry. A changed proof, action or bytes conflicts. New higher
counters can safely make older in-flight assertions fail; never lower the counter.
The public error mapping remains the existing wire contract, not this QA RPC's
generic proof_rejected result. No public key-status oracle or proof of absence
of timing differences is claimed.

Submit returns a **private internal** authorization capped at5s, original
transaction/operation/key deadline and known policy expiry. Lookup/retry returns
the same still-valid lease only. Equality is expired; after5s the counter is
burned, a new operation requires a fresh higher-counter assertion. No receipt
renews that lease. A valid lease does not commit ready or reserve a transaction.
There is no new bearer/signing protocol or cross-object atomicity. Already
returned leases may remain usable to their original deadline after revocation;
new lookups are denied, with propagation/transaction checks still separately
required. No HA or display/Session permission is granted.

Delete-key atomically creates the existing minimal finite tombstone and erases
key evidence/counter plus all operation rows. No cached receipt can resurrect
a revoked key. Subsequent independently admitted unknown-key management requests
may still allocate bounded<=120s challenges; they cannot authorize or create a
key. This is not permanent device exclusion or total physical erasure.

Before any new challenge row is committed, the object confirms a durable cleanup
alarm through the inherited serial queue. Postcommit failure cannot leave that
row without its earlier trigger. Alarm scheduling includes minimum operation
expiry even when no key exists. Manual local alarm tests erase unknown-key
challenges without client retry. Request-time checks deny expired rows even if
physical cleanup is delayed; rejected transactions may roll back incidental
cleanup, so actual alarms/monitoring remain necessary. Revocation/expiry use the
same in-transaction erase hook. Alarm errors remain fixed exceptions for retry.
No provider scheduling/backup retention/15min cleanup-monitoring proof is implied.

After commit, rearm and final key/policy/receipt checks prevent returning fresh
authority after intervening termination. A simulated postcommit alarm failure
returns a generic unknown outcome with counter/receipt already committed; exact
retry recovers only the original still-valid lease, never a second counter/lease.

## Actual cases, distinct genuine fixtures and preserved failures

Tests run actual SQLite/DO persistence and the real qualified signature verifier:
new software-signed exact management/submit bytes; known/unknown coalescing,
parallel issue/authorize calls,32-row bounds, CSPRNG collision rejection; unknown
key denial; wrong bytes/action/operation/proof with unburned nonce; immutable
exact retry and changed valid signature conflict; two operations/counters,
unsigned maximum; original5s equality/lost replies/known-policy/key/transaction
caps; SQL receipt/delete failures and repair; revoke/expiry/policy/point/counter
changes during real crypto; deletion erasure, revoked receipt/lookup denial;
first/postcommit alarm failures and unknown-key cleanup; actual local instance
abort/reopen preserving SQL/counter/receipt. Fault clocks and direct test SQL
are explicit controls, not caller-selectable production behavior.

Two old real Apple signatures additionally verify against their original public
points and advance/recover counters atomically. For those tests ONLY, the original
captured input bytes replace clientData in an internal test SQL challenge. They
bypass normal action issuance deliberately and **do not prove Apple signed the
new wire action**, original challenge freshness or successful current enrollment.
Their state begins at test counter0, not the device's real historical server state.
No new device capture/AppAttest key is requested, generated or uploaded.

Initial typecheck failed because the reused base64 helper accepts ArrayBuffer/
string rather than typed-array arguments; calls now use that interface without
forking the helper. First73-case run had72PASS/1FAIL: restart used an aborted old
stub. A new namespace.get(sameID), with identical QA environment restored and no
key/state reinstall, fixes that test. Subsequent73 passed; final fault/collision
controls yield75/73. Failed artifacts remain retained privately, not reclassified
as successful runs or signature vulnerabilities.

Independent supplied-design and implementation security reviews: scoped
coordinator-candidate GO, no P1/P2 in supplied guards/results. UX/privacy scoped
GO. Reviewers did not independently inspect source/storage or execute tests.
These are not full enrollment/verifier, private RPC, transaction DO or runtime
approvals. Existing40 API regressions/107schema+2bytes/types/projection pass
separately; unchanged user-facing translations. Normal CI remains separate.

## Reproduce and remaining producer obligations

```sh
node qualification/rendezvous/run_assertion_state_workerd.mjs /private/tmp/isolated-pki-deps /private/tmp/new-assertion-state-results
```

Optional third argument is the already authorized private diagnostic capture
root used by the earlier core qualifier. No new device data is needed. Output
is a new0700 directory; runner-owned files0600, fixed console labels and sanitized
source/case/version results only. Existing private-derived-evidence review/delete
deadline2026-11-16 remains; no automatic/hardware erasure promise. Dependencies
remain cbor10.0.12/PKIJS3.4.1/ASN1js3.1.0, existing test/compiler artifacts; runner
installs/deploys nothing. Full source/helper hashes and actual Node/workerd/pool/
compiler versions are recorded. Temporary bindings/migrations are QA-only.

Still required: complete initial AppAttest/CMS/authenticated-status/encrypted-store
enrollment, actual native action bytes, hardened private routing/RPC and global
admission, transaction-DO atomic winner/consume/cancel with lease/capability/expiry
checks, operational keys/cleanup and independent full review. Unchanged browser
wire and JWE generator retain existing receiver ACK/pin; its actual consumer
crossrun, supported signed-iOS integration and real HA/proxy/display chain remain
separate. Joint freeze, protected product delivery, distinct Finalization and
authorized production deployment remain open.

Primary guidance: [Cloudflare DO rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/),
[SQLite storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/).
