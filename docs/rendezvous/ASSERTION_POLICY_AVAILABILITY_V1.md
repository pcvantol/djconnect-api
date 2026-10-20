# Assertion server-policy availability

This bounded correction distinguishes unusable server-owned assertion policy from
invalid sender proof. Missing/wrong/disabled policy ID or missing/malformed/
noninteger/unsafe/nonfinite/expired policy deadline throws a new private
`AssertionConfigUnavailable`. The existing issue/authorize/lookupSubmit mappers
already return redacted `service_unavailable`/503 for that type. The exact accepted
predicate, Number conversion, guard order and returned deadline are unchanged.
No configuration, schema, body, hint, selector, verifier or success grant is added.
Enrollment server-policy availability was qualified separately in PR111.

Healthy malformed/invalid proof/context still401. A valid shorter current policy
that refuses an existing immutable submit lease also remains401. No enrollment
revision-binding semantics are invented for assertion policy. If policy blocks an
original context read, its old deadline is unknown and is never guessed;503 does
not imply a bad iPhone or Apple outage. Previously copied, fully bound original
operation/key or acknowledged-receipt time windows retain expiry/rollback401
priority without catch-time SQL. No original lifetime is extended.

Policy loss during actual proof verification can stop before commit503, leaving
counter0 and the original challenge. Explicit repair restores exactly the original
settings and request; it does not issue a new key/nonce or refund attempts. After
acknowledged recovery/submit commit, policy loss during the alarm await can cause
a final-read503 while counter1 and the original receipt/lease already exist.
Explicit exact-proof repair returns that original result only within its original
bounds. These503 outcomes are not rollback confirmation or automatic retry rights.
DELETE retains its existing successful result after tombstone commit and arm;
there is no new after-commit policy reread or deletion-state change. A later proof
against its erased operation remains401 under healthy settings.

Actual local affected qualification passes1235 workerd cases/strict types. The
final shared qualification includes those cases and206 additional shared/capacity
cases:1441 PASS/strict types. One equivalent test-only ternary was simplified
between the standalone and final shared run; the published full shared source
hashes bind the final exact bytes. A controlled paired old-runtime run uses only
protected c8 assertion runtime with the same final1235-test set:1186PASS/49FAIL,
all classification expectations. This is not a whole-tree baseline delivery.
Actual product checks pass128 including100 forbidden private-RPC calls. None is
native-positive or provider/edge/HA/physical acceptance.

Thirty-three policy variants across issue/authorize/exact lookup require closed503,
no verification and unchanged key/operation state. Four reached verify-await races
separate live unavailable policy from known operation expiry, independently shorter
key expiry and rollback, requiring no fallback SQL. Three reached postcommit alarm
races distinguish recovery/submit503 from unchanged DELETE success. Healthy shorter
policy and unseen expired saved-lease tests preserve original authority boundaries.
Twelve actual composed HTTP cases cover challenge/authorization for all three
actions under disabled/expired settings, with exact503/nohint, request/key charges
for both failure and explicit repair, unchanged original context/counter/transaction
expiry and no automatic attempts. Submit challenge repair still spends another
bounded transaction challenge attempt; authorization repair uses the original one.
Shared test environment settings are restored between cases.

Preparation binds immutable protected c8 plus a fixed closed three-source delta,
complete66shared/85root maps,106 tracked inputs,32 installed hashes and13 references.
Historical proof files remain unchanged; no HEAD fallback, lazy fetch or generic
delta chain is introduced. Default verifier/builds40227/28/30, private40381 recover-
only PREPARED_ONLY_NOT_NATIVE_ADMITTED and root compiledOFF remain unchanged.

Complete provider/internal taxonomy, genuine native/key/proof/receipt qualification,
HA/B-consent/TV chain, public edge, operations and exact deployment authority remain
OPEN. All22 full-service gates stay OPEN/public serviceOFF. This increment changes
no Cloudflare/account/signing/credential/installation/device/deployment state.
Independent exact-source/package review, normal applicable Owner/CI/protected
merge, actual own-main artifact/formal/durable proof and fresh separate Finalization
remain required for bounded delivery.
