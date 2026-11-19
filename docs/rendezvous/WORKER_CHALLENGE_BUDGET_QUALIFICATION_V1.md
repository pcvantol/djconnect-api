# Local challenge bounds, management slots and receipt configuration

Profile0.4.0-draft / wire djc-rendezvous/1 remains **NOT_FROZEN**. Same sole API
writer/draftPR96, continuing b1dee179; main e67f402 unchanged. Fresh ACK:
https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6265985814.
Full independent protocol/UX review found three source P2s. The minimal designs
were independently reviewed before source. [Current contract HOLD](CONTRACT_READINESS_V1.md)
separates their correction from remaining consumer decisions and later operations.

## Exact source changes

TransactionState persists submitChallengeAttempts=0 at original create. Private
reserveSubmitChallenge uses one SQL transaction after QR/generation/pending/expiry
checks to enforce/increment the shared four-attempt counter and return the existing
public-key context. The selected indexed HTTP path replaces inspect with this
method before key admission/issuance. No extra RPC, public route or wire field.
Read-only inspect stays unchanged; fifth attempt429 reaches no key RPC and exports
no new retry hint. Different keys/digests or identical issuance retries share the
same counter. Downstream refusal/lost result is charged, without refund/renewal.
Later cancel/expiry still defeats actual submit: reservation is not authorization.
Missing/corrupt stored counters fail503, never initialize/reset a live old row.
Persisted counters survive coordinator reconstruction and terminal states until
original expiry cleanup. No product state/migration has been deployed.

AssertionKeyState keeps total32 unexpired proof_operations (plus one separate
enrollment_operation row), with maximum28submit,
2recover-key and2delete-key, counting challenges AND receipts. Existing pending
management coalescing precedes quota. Submit pressure with a known key address
cannot consume management capacity. Genuine assertion/counter/key expiry/deletion
semantics stay unchanged; group denial does not evict an older receipt or renew
its deadline. Existing proof_rejected classification for key operation pressure
remains generic; full availability taxonomy is not claimed.

EnrollmentKeyState also recognizes only a private typed missing/malformed active
receipt-key configuration error. A pure helper reuses the store's canonical32-byte
base64 parser, no new cryptography. Guards run before challenge/proof work, after
relevant awaits and inside beforeInstallCommit. Original context/expiry/evidence
checks run first on late results. One stable activeKey snapshot feeds keyVersion
and encryptSecret, with synchronous continuity checks before SQLwrites. No guard
after committed install claims rollback. Healthy-config invalidproof stays401;
controlled config failure503 has no hint or secret. Attempt charges and original
nonce/deadline are preserved. Postcommit alarm failure retains the existing generic
unknown-outcome path; full provider/internal error taxonomy remains OPEN.

## Executed evidence and test corrections

Source-bound observations are recorded separately; empty genuine inputs remain
explicit. The new suite covers authenticated transaction quota/races/reconstruction,
unknown/wrong/terminal context, no key access after quota, denied/lost downstream
results, original expiry, corrupt counter, actual two-IP known-key submit pressure
followed by software-P256 authenticated recovery/deletion, two actual recovery
receipts, group isolation and original-deadline cleanup. Whitebox simulated
management receipts only test slot accounting, never genuine Apple validation.
Fifteen configuration cases cover missing/malformed keys, skipped verifier/nonce,
charged identical HTTP repair, healthy-config bad proof401, original expiry priority,
precommit alarm and pointdigest/keyVersion/encrypt awaits, plus postcommit lost
alarm outcome with exactly one original key/expiry after repair.

Initial a981/983: new late-response test expected410, but guarded HTTP correctly
returned503 when its original IP-minute context expired; fixed that test expectation
only. An existing parallel create/register identity test also returned201/503.
It does not qualify coordinator throughput: fixed budgets intentionally allow busy503.
Fixture now serializes actual allocation/budget RPCs while keeping HTTP/resolver
calls concurrent and retaining201/201 plus exact separate-IP assertions. Adapter
must invoke no-argument admitKeyCall with zero arguments. Intermediate b985/987
also exposed a cleanup fixture using only the earliest submit deadline rather than
later management deadlines; corrected it to the maximum saved original deadline.
Intermediate c986/987 still failed the no-argument test adapter; focused corrected
adapter run1PASS. No runtime success/expiry/busy predicate was weakened.

Intermediate d987/987PASS qualified the first two corrections. Additional config
tests initially polluted the shared local DO test env: e992/997 and f993/999 failed.
The fixture now restores its test key before/after each case; no provider key or
product state is changed. Run g998/999 exposed a genuine guard-order bug: generic
key-continuity rejection preceded the typed config check. Independent security
review identified the same path; moved the guard after original context/evidence
checks but before that equality. h999/999PASS did not yet cover every crypto await.
Security then found the post-pointdigest/install gaps; added the stable key snapshot,
postdigest guard and three targeted crypto-await tests. Final i below is the only
current full evidence; prior successful runs are not relabeled.

Final i: **1002/1002 actual local workerd + isolated strict TypeScript + exit0 PASS**,
41new cases +961 prior cases (including the two corrected existing fixtures),
without duplicate counting. [Source-bound observations](workerd-challenge-budget-observations-v1.json)
record58 current source hashes (proof SHA256
28c978c070d77b5c7dae726935b562e1aa048c26948dbb8d96112370a46df3b6). Exact reviewed hashes and CI are registered in API90/PR96.
This is local software/SQLite qualification, not genuine native enrollment,
provider/account/edge/load/privacy-retention or installed HA/physical-TV proof.
The existing API40tests, root types, projection and107schema/two-byte examples
are regression checks, not proof that the root product bundle contains rendezvous.

Reproduce with the same pinned cbor10.0.12/PKIJS3.4.1/ASN1js3.1.0/JOSE6.2.12:

```sh
node qualification/rendezvous/run_challenge_budget_workerd.mjs /private/tmp/pinned-pki-deps /private/tmp/new-challenge-results /private/tmp/pinned-jose-package
```

Runner retains eleven isolated test bindings, disabled egress/telemetry and
0700output/0600files; records source/tool/trust/JOSE hashes, sanitized labels/counts.
No new dependency/root config/binding/type/product entrypoint, APNs/pairing/D1,
consumer source, device, Cloudflare or timer change. Source revert needs normal
review; before any later live rollback stop new admission/drain original lifetimes
and verify compatible cleanup. An old runtime ignoring the new counter is not an
approved live rollback merely because JSON storage needs no SQL migration.

As before, changed runtime intentionally invalidates the old86c80fa offline
preparation baseline. Only after immutable reviewed source qualification can a
separate preparation commit rebind to the new source/proof/hash count.22gates stay
OPEN/null/false; historical961 evidence is not relabeled as a new execution.
