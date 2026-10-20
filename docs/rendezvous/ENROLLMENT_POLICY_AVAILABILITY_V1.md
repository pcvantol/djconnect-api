# Enrollment server-policy availability

This bounded API correction uses the existing `service_unavailable503` when the
server cannot admit enrollment because its fixed policy ID, absolute policy
expiry or revision is missing/disabled/malformed/expired. It does not diagnose
an Apple outage, a bad iPhone or a bad proof. Only the existing private
`EnrollmentConfigUnavailable` type receives this mapping; exception text and
arbitrary verifier errors do not. The accepted policy predicate is byte-for-byte
unchanged; no new policy, field, status, hint, retry or build selector is added.

A valid replacement revision/deadline still mismatches the saved original context
and returns the existing invalid-proof401. Invalid device proofs under healthy
configuration also remain401. Original challenge expiry wins at the existing
postawait guard; equality never succeeds. Repair does not create/reissue a nonce,
renew a QR/key, refund attempts or authorize automatic retries or replacement.
Registration calls still consume the existing key and registration budgets.

Before commit, unusable configuration leaves no new key and preserves the original
pending operation. **After commit**, the cleanup-arm await can lose configuration
before the result is read;503 then means an unknown outcome, not rollback. The
new test proves one existing active key with its original expiry and counter0;
restoring exactly the original settings lets the same request recover its original
receipt without reinstalling or changing that key. No after-install guard or
storage/crypto/counter/cleanup algorithm was changed.

## Actual evidence and limits

The corrected old-source counterrun reports1004PASS/27FAIL/0skip, each failure the
wrong classification. The first test attempt had twelve invalid facade-method
spies; that attempt is retained separately and is not the causal result. The
minimal source change then passes1042actual local SQLite/HTTP/crypto tests with
isolated strict types. Forty additional cases cover server policy variants,
verifier bypass, original-context repair, valid-context replacement, precise
pre/postcommit races, expiry precedence, budgets and redacted HTTP503/no hint.
The four race tests explicitly require their fault phase to be reached. They
initially failed together due shared test environment policy contamination; full
fixture settings are now restored between cases, without product guard changes.
A healthy direct/RPC software fixture calibration is included. Software enrollment
is confined to the existing trusted test harness, not the product verifier.

The full shared suite executes1248cases/strict types; the actual root bundle
passes128private-RPC/default-genuine-negative checks including100forbidden calls.
Fresh compact observations are `enrollment-policy-shared-observations-v1.json`
and `enrollment-policy-build-observations-v1.json`. The full3.2MB shared summary
is retained privately and SHA256-bound in the compact report. Each condensed
scenario digest hashes its complete original observation using UTF8 JSON with
sorted keys and comma/colon separators; the full-file digest hashes the actual
unmodified summary bytes. Historical proofs are not overwritten or relabeled.

CI runs the affected1042group through the existing local-native workflow using
locked root PKI dependencies and the already prepared pinned JOSE package. It
performs no dependency download during execution. Public/root types/API/module,
private-native and browser regressions remain their separate checks. CI and
protected-main/artifact/Finalization identities belong in exact delivery receipts.

## Squash-safe exact-source preparation

The repository permits only squash merges and automatically deletes PR branches.
An intermediate source commit therefore cannot be assumed available in a later
main-only checkout. The validator retains immutable protectedbaseline6d73047,
its original three proof digests and all106original Gitblob hashes. It separately
pins one closed `enrollment-policy-source-delta-v1.json` by a source-code SHA256
constant, allowing exactly the three named existing old→new paths. No add/delete,
noop, conflicting overlap, dependency drift, HEAD fallback or lazy fetch is allowed.
The complete new66shared and85root maps must exactly derive the106effective inputs;
the32installed dependency paths **and hashes** remain equal to baseline. All106
working inputs and fixed reference/proof bytes are verified before local runtime.

Both plan and validator output expose `source_provenance.kind` as
`BASELINE_PLUS_PINNED_DELTA`, with baseline SHA, delta digest and effective map
digest. `supplying_source_sha` names only the immutable baseline, not a false
current-source commit. Map digests use UTF8 sorted-key compact JSON. Actual final
protected source/artifact pins remain mandatory in separate delivery receipts.
A depth-one checkout with no old PR object rejects the new plan until precisely
hash-verified changed inputs and allowlisted proofs are installed; it then yields
only22OPEN/null/false. Missing/modified delta, map, proof, runtime or provenance
fails closed. No arbitrary path list or mutable Git discovery supplies truth.

This does not close the complete provider/internal taxonomy, actual provider,
edge/TLS/cost/retention/cleanup-monitoring or genuine native/HA/physical acceptance.
Root stays compiled OFF/root503, default builds40227/28/30 unchanged; the private
40381recover-only preparation remains separate and not native-admitted. No
Cloudflare, account, credentials, APNs/pairing/D1, device, deployment or public
activation changes. All22full-service gates remain OPEN. Rollback is a normal
protected source revert; there is no new migration or live state to roll back.
