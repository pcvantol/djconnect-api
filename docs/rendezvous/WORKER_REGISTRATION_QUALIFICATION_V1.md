# Local atomic registration and private RPC containment v1

Profile0.4.0-draft/djc-rendezvous/1 **NOT_FROZEN / NO_FRESH_NATIVE_ENROLLMENT /
NO_PUBLIC_RUNTIME_GO**, same API94 writer. This qualifies local SQL composition,
not the complete provider/native/HA service.

[State/facade](../../qualification/rendezvous/enrollment-key-state.ts),
[actual tests](../../qualification/rendezvous/enrollment-key-state.check.mjs),
[separate software harness](../../qualification/rendezvous/enrollment-state-harness.ts):
[141/141 local workerd cases + isolated TypeScript PASS](workerd-registration-observations-v1.json),
[137/137 without private fixtures + types PASS](workerd-registration-public-observations-v1.json).
Combined counts include all39 original storage tests,34 software assertion cases,
two old diagnostic assertions,64 new public registration/RPC cases and two old
attestation replays. New TypeScript state/facade/harness/base implementations are
compiled; the unchanged JavaScript verifier still uses its previously qualified
implementation and declaration contract. Positive **initial enrollment** uses
explicit software stubs, not genuine App Attest/CMS/status proof.

## One SQL authority and a bounded original challenge

EnrollmentKeyState extends the existing assertion/receipt state, using the same
key row, ciphertext/context and counter. One enrollment_operation row per object
contains opaque32-byte wire ID, separate internal UUID for the existing store,
key-address hash, created/deadline, policyrevision/deadline and pending nonce.
No raw Apple key ID, attestation, receipt, URL, owner/Profile/Session or HA index
is persisted in that row. Raw key ID and verified receipt exist only in the
private in-memory operation while verification/encryption is active.

Challenge issue validates canonical key ID, confirms a durable alarm before SQL
and coalesces an existing pending operation without nonce/deadline renewal.
Different keys cannot displace it. A registered result cannot be evicted by
another challenge before its original deadline. Challenge lifetime is at most120s,
capped by known policy expiry; current policy is rechecked after the alarm await.
One enrollment row plus the inherited maximum32 proof-operation rows is the local
bound. Global object routing, allocation/admission and capacity remain unqualified.

The default verifier receives only server-saved **decoded nonce32**, original
key/challenge/time and current fixed policy. This is the unchanged register /
SHA256(raw nonce) contract, not a new JSON-clientData wire. No request-supplied
verified evidence, app/environment, root, clock or good-status selector. The
[existing composed verifier](WORKER_ENROLLMENT_EVIDENCE_QUALIFICATION_V1.md) binds
real core/CMS/common certificate status and all original deadlines. Owned
Uint8Array copies precede asynchronous work, including Buffer inputs. One active
registration per instance keeps its private intent isolated; no global CPU budget
or general backpressure claim follows.

## Atomic key, encrypted receipt and nonce consumption

The existing store has two default no-op lifecycle hooks inside its synchronous
SQL transaction. No AES helper or encryption format changed. Registration uses
that existing standard AES-256-GCM helper and its context binding, separate
receipt key, random nonce, key version and original at-most30-day lifetime.
The store confirms a durable alarm before any sensitive key SQL commit.

Immediately before key write, the hook rechecks the actual pending operation,
exact nonce and original timestamps, internal/wire IDs, key address, current and
original policyrevision/deadline, verified evidence identity/expiry, receipt
freshness and exact normalized key/receipt material. The operator encryption key
must still equal the one selected for this operation. Existing active or
tombstoned keys cannot be replaced. No cached evidence alone creates a key.

Key/ciphertext insert and operation conversion to a minimal registered-result
receipt occur in **one SQL transaction**. The latter removes the nonce. Either
half may fail and roll both back; tests inject failures before key insert and
before registered-result update after key insert. Crypto failure similarly leaves
no key and the original pending operation. Cancellation/nonce replacement, policy
change, original challenge expiry, evidence expiry and encryption-key change
during real AES await all deny commit. These are software-controlled faults,
not platform crash or provider-compromise/physical rollback resistance.

No ciphertext/plaintext receipt or proof is returned over the facade. Success
is only the private typed result v/key_expires_at. The local error is a fixed
registration_rejected; eventual public HTTP/error mapping remains a separate
validated controller. Request identity is the SHA256 of a fixed internal tuple
(version, register, challenge ID, canonical key ID, canonical base64 proof bytes).
It binds exact values/proof bytes; no raw HTTP JSON canonicalization is claimed.

## Lost replies, recovery, deletion and finite cleanup

Exact retries require the same request digest, original operation, active same
key, original expiry and unchanged active policy. They return the original result,
without crypto reauthorization, another key insert, counter reset or renewed
lifetime. A still-valid historical acknowledgment does not require initial status
to remain fresh after the key already committed; it creates no new authority.
A changed proof/key/operation conflicts. Concurrent RPC calls may serialize into
valid identical retries; an SQL audit trigger proves one key insert, and a separate
direct-overlap test exercises the busy guard.

After original enrollment expiry, registration retries fail. A new challenge
still cannot overwrite an active key; uncertain enrollment recovery instead uses
the existing fresh recover-key assertion. The software flow enrolls then signs
real cryptographic assertion bytes and checks the unchanged verifier/counter path;
this is software crypto, not native App Attest. Registration retry after that
recovery preserves the incremented counter and original ciphertext/deadline.

Postcommit alarm-ack failure returns an unknown outcome with the key/result
already committed. The earlier trigger remains acknowledged. Exact retry recovers
only the original result. Pending and committed local abort/reopen tests retain
SQL/nonce/receipt/counter without state reinstall; identical QA environment settings
are restored, not regenerated as a new policy.

Authenticated key deletion uses the inherited tombstone transaction and a cleanup
hook to erase both enrollment and assertion operations alongside key evidence.
Expiry is logically enforced even if physical cleanup is delayed. Alarm scheduling
includes enrollment expiry for unknown keys; manual local alarm execution erases
pending data without client retry. Key expiry and original key expiry+120s purge
are also exercised. Provider scheduling/retry/backoff/15min monitoring and backup
retention are not proved. The test SDK deletes its alarm before calling the handler
and does not model provider retries: a fault/repair test explicitly invokes the
handler again after repair. It is not a measured provider retry.

## Actual RPC containment and fixture boundary

EnrollmentCoordinator extends DurableObject and contains its engine in JS #state.
Only issueEnrollment/enroll/issueAction/authorize/lookupSubmit and the alarm handler
are on its prototype. It does not inherit the storage/verification helpers.
Actual workerd RPC tests reject20 inherited/private helper names and four
properties including env/ctx/#state. Raw install, evidence, counter advance,
rotation, revoke, SQL hooks and verification cannot be invoked through this facade.
No engine, callback, callable function or storage reference is returned.

This closes that **local facade exposure** gap; it does not qualify the surrounding
Worker/controller's capability validation, correct per-key namespace routing,
submit-context authority or global admission. Only the facade may be a future
candidate DO export. The internal engine and existing QA-only test bindings must
not be re-exported as production DO classes.

The third constructor argument is a trusted constructor-only test seam, not a
request/RPC/environment selector. The separate SoftwareEnrollmentCoordinator is
exported only by the temporary harness and uses the distinct software-stub
verification scope. It must never be part of a product entrypoint/binding. Default
facade rejects that fake initial proof; two existing real attestations also fail
against a newly issued nonce32, leaving no key. Old diagnostic signature tests
remain distinct. No new device capture/key, status refresh or owner proof occurs.

## Tests, failures and review scope

Initial isolated typecheck failed because the generated Worker types require
ignoreBOM on the fixture TextDecoder options; supplied explicitly. First131-case
run129PASS/2FAIL: wrong assumption that eight parallel RPC calls must give one
success (they may serialize into exact successful retries), and a test assuming
the SDK reschedules a failed manual alarm. Replaced these with SQL insert-count
proof/direct-overlap test and explicit handler retry. Then132 passed; nine final
nonce/policy/property/purge controls yield141/137. All failed artifacts remain
private; no result is relabeled PASS. Existing40 API regressions/root types and
offline projection pass separately. Root source/config/dependencies/bindings,
D1, secrets, release workflows and user-facing translations are unchanged.

Independent design/security review and complete-supplied-source review: scoped
QA GO/no P1/P2. Review covers state, harness, tests and storage-hook diff, not
reviewer Git-readback/testexecution. Separate reviewer actually read those files
and runner/declarations: UX/privacy scoped GO/no P1/P2. These are not full service,
provider, genuine-native or production security approvals.

## Reproduce, deployment and remaining work

```sh
node qualification/rendezvous/run_registration_workerd.mjs /private/tmp/isolated-pki-deps /private/tmp/new-registration-results
```

Optional third argument reuses the already-authorized private diagnostic root.
Runner installs/deploys nothing; pins existing cbor10.0.12/PKIJS3.4.1/ASN1js3.1.0
and records root/source/helper/compiler/workerd hashes/versions. Temporary
wrangler bindings/migrations/vars are local-only, not approved product config.
Global fetch is explicitly disabled in test setup; the HTTP harness always503/
no-store. No existing remote namespace, D1 migration or production secret is
created or changed. New output0700, runner-owned files0600, child diagnostics
inside that directory; sanitized results contain fixed case names/hashes only.
Existing private-diagnostic custody review/delete deadline2026-11-16 is unchanged,
without automatic hardware/physical erasure promises.

Source rollback is a normal reviewed revert to parentdb50dc5; no provider rollback
was performed or required for these local-only migrations. Future deployment must
exclude QA bindings/software exports and qualify real receipt keys/rotation,
private routing/admission/cleanup/costs and protected manifests independently.

API still owns transaction winner/ready/consume/cancel and HTTP/controller/global
admission integration. Fresh genuine enrollment/nonce/action integration, full
independent review and jointfreeze remain gates before publicruntime. Receiver's
unchanged generator crossrun is already delivered. Core real HA route/proxy and
separate display admission, physical HA/iPhone/TV, protected product merge,
separate Finalization and explicitly authorized deployment remain open.

Primary references: [Cloudflare RPC visibility](https://developers.cloudflare.com/workers/runtime-apis/rpc/visibility/),
[DO coordination rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/),
[platform limits](https://developers.cloudflare.com/workers/platform/limits/).
The local application bounds above are not measured provider quotas.
