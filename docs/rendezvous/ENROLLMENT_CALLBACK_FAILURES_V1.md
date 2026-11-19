# Enrollment saved-state callback failures

This bounded correction preserves failures from the coordinator-owned saved-state
callback invoked by the enrollment evidence verifier. Previously its blanket
catch converted transient SQLite reads and unavailable enrollment policy into
`enrollment_rejected`. A successful later outer snapshot then reported
`invalid_sender_proof`/401 for the server failure. Persistent faults could instead
be caught by that outer read, concealing the transient boundary in older tests.

A module-private wrapper now carries only exceptions thrown by `readState()`.
The verifier rethrows the identical original value before its existing proof/status
mapping; its finally still releases the busy guard. The owning coordinator keeps
its existing typed context/config/internal classification and copied original
window. No error message or object shape selects classification. Returned state
validation, core/CMS/status results, cryptography, successful evidence, wire,
HTTP mapper, grants, counters, retention and configuration are unchanged.

A live unexpected callback fault or unavailable server policy returns the existing
redacted503. Typed saved-context replacement remains401. Known original challenge
expiry/equality or wall-clock rollback remains401, without catch-time SQL.
Healthy malformed proof remains401. An explicit repaired request retains the old
nonce/deadline and spends another request/registration attempt. A503 grants no
retry, refund, replacement key or renewed expiry and reveals no callback details.

## Executed local evidence

The final full shared workerd qualification passes1485 cases/strict types, including
44 added cases. Thirty-two software composition controls throw four different
values at each of eight reached callback reads; exact thrown identity is retained
and a second explicit verification proves the same busy guard was released.
These are orchestration fixtures, not genuine Apple acceptance.

Six real default-verifier/coordinator controls inject SQLite read or transient
policy faults at the initial snapshot, precrypto recheck and postcore await.
Each proves the fault was reached once, no key/receipt was installed, the original
operation stayed identical, and repaired default parsing still rejects the
software proof. Three more cases preserve known original live/expiry/rollback
precedence and require zero SQL after the fault. A separate valid policy-revision
replacement retains the actual private typed context401 classification.

Two guarded HTTP cases use that default verifier through the existing trusted
constructor-only namespace seam. Each proves exact503/no Retry-After, unchanged
pending state and request/registration charge1. Explicit original-proof repair
then reaches genuine parsing and returns401/charge2. No positive enrollment is
manufactured and there is no request/environment verifier selector.

The standalone affected run passes1171 cases/strict types before adding the two
HTTP controls. A controlled paired run of that exact1171-test set with only the
verifier module restored from protected3458ad603350ab9481073277c7dbe561433b4453
returns1132PASS/39FAIL. The failures are32 callback identity,6 transient default
callback classification and1 live original-window/no-fallback control. This is a
single-module causal counterproof, not a whole-tree baseline qualification.

The original two-case counterproof returned1129PASS/2FAIL. An older standalone
registration runner first stopped at types because its old include list omits the
current wire declaration; no tests ran. A sandbox attempt then stopped at local
loopback EPERM. The actual native composed runner supplied the executed evidence.
An initial product dry-run built the Worker but its provenance guard rejected the
external dependency symlink; dependencies were copied into the isolated worktree
for actual product qualification. The real product qualification then passes128
checks including100 forbidden private-RPC calls, with no egress or activation.
API regressions78, product composition49, strict root types and34 offline
preparation checks also pass. None of the preliminary failures is a green
product or installed result.

## Delivery and remaining gates

Independent security/UX review, exact protected CI/Owner Authorization, normal
merge, actual own-main artifact/formal/durable readback and separate Finalization
are still required. Preparation is rebound to immutable protected3458 plus a
fixed five-source delta, complete66 shared/85 root proof maps,106 tracked inputs,
32 installed hashes and13 references. The old preparation correctly rejected
the changed inputs before this rebind. Historical proofs remain unchanged; no
HEAD fallback, lazy fetch or generic delta chain is introduced.

Core/CMS/status component catch behavior and complete provider/internal taxonomy
remain separate open work. This change closes only the saved-state callback
boundary. Root remains compiledOFF/public503, all22 full-service gatesOPEN.
No native/device/Keychain, provider, HA, Cloudflare, D1, publicQR or deployment
mutation occurs. Rollback is a normal reviewed source revert; no state migration,
key deletion, counter reset or lifetime extension is involved.
