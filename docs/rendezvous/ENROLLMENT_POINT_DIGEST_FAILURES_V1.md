# Fixed enrollment public-point digest failures

This bounded correction preserves unexpected failures from the one fixed
SHA-256 digest of the post-core public point. It continues the existing enrollment
error-classification work; it does not complete the entire provider taxonomy.

The engine already requires a 65-byte point with leading 0x04 from its accepted
core result. A private wrapper catches only the actual fixed WebCrypto invocation
on that owned point. Its private failure marker causes the engine to rethrow the
identical original value to the existing coordinator mapper. No error-name or
message matching is added. Typed-array construction, invalid point/result shapes,
a healthy digest mismatch and all proof predicates retain their existing verdicts.

The owning coordinator consequently returns internal service_unavailable for a
live unexpected digest failure, while its already known original expiry/rollback
window still yields registration_rejected without catch-path SQL. The busy guard
still releases. The original nonce, policy deadlines, key/counter state, receipt
rules and explicit retry window are unchanged. No automatic retry, native key
retry, policy extension or replacement challenge is introduced.

## Reached causal evidence

The same 1558-test set ran against the protected baseline engine and corrected
engine. Baseline: 1548 PASS and 10 expected causal FAIL. Corrected: 1558 PASS,
zero failures or skips, plus isolated strict types. All 66 staged source inputs
were compared: only enrollment-evidence-candidate.mjs differs. Composite case
identities include file basename, declaration ordinal and full title, retaining
duplicate titles across files rather than silently collapsing them.

Fifteen new cases cover:

- Four original-cause identities: Error, DOMException, a lookalike object and
  undefined; core reached once, CMS/status not invoked on failure, state unchanged,
  then the same verifier accepts explicit original software-fixture repair.
- Four actual SQLite coordinator cases: internal 503, one reached digest failure,
  no key or receipt installation, exact pending operation retained, then explicit
  same-operation software repair installs counter0 at the original deadline.
- Two original expiry/rollback cases, with one reached fault and zero catch SQL.
- A healthy wrong digest and two invalid public-point shapes retain proof rejection.
- Two actual guarded HTTP cases: redacted503, no Retry-After or private detail,
  one request/key charge, unchanged nonce/state, then explicit original software
  repair 201 and exactly one additional charge. No nonce refresh or free retry.

The first preliminary baseline attempt had eight reached causal failures and two
HTTP setup failures before the target: before the first key charge, no budget-day
row exists. The setup now treats that absence as zero and the final baseline pair
reaches both expected401-versus503 failures. Those preliminary setup failures are
not counted as causal proof or a passing run.

All positives use the explicit existing SOFTWARE fixture namespace and local
software P256 keys/components. The actual shared engine, SQLite coordinator,
HTTP mapper and budgets execute; this is not a successful default Apple core/CMS
validation, genuine native enrollment or device/provider outage reproduction.
The default factory and native operator controllers remain unchanged.

## Qualification and immutable binding

Actual product-build 128/100 forbidden RPC checks, API 78, composition 49 with strict
types and root type checking pass. Full raw shared evidence remains private;
the compact publication retains all 1558 case outcomes, all 66 source pins and
canonical hashes of the existing capacity/create/shared observations, plus the
full raw summary hash. The existing 1 MiB decoder ceiling is unchanged.

Protected source baseline is 896ccdc69447c231d04da3a6af4f27ea1f763697. A closed
four-input delta covers the engine and its three changed test files. Complete
106 tracked inputs,32 unchanged installed bundle inputs and14 references bind
fresh66-input shared,85-input product and19-input composition proofs. Historical
callback, assertion-crypto and sharp receipts are preserved without rewriting
their execution identities. The old preparation correctly rejected changed source
before rebinding. The local preparation runtime only advances its product-proof
pointer; no experimental admission is added.

Machine evidence:
[causal pair](enrollment-point-digest-paired-v1.json),
[shared](enrollment-point-digest-shared-observations-v1.json),
[build](enrollment-point-digest-build-observations-v1.json),
[composition](enrollment-point-digest-composition-observations-v1.json),
[closed delta](enrollment-point-digest-source-delta-v1.json).

Exact committed default/private-profile negative preparation groups, independent
exact-candidate security and UX reviews, protected CI/merge, actual own-main
artifact/formal/durable readbacks and separate Finalization remain required.

## Remaining boundary

Core attestation/CMS and the complete provider/status/error taxonomy remain OPEN.
This fix cannot make a native test environment available. HA-dev and the user's
own iPhone 17 Pro are selected test targets only; current signed Apple source/build/
profile, native-owner agreement and separate operator/device/SDK/key/nonce/capture
effect admission remain required. No obsolete 40381 repin is inferred.

All 22 full-service gates remain OPEN/null/activationfalse, public rendezvous
compiled OFF/503 and QR off. No deployment, Cloudflare/D1, device/Keychain,
provider, HA or paid model/API effect is performed or granted. The night
automation remains PAUSED. Wire/success predicates, app flows and translations
in en/nl/de/fr/es are unchanged. This closes only the selected digest boundary
after its required delivery, not the whole function or genuine acceptance.
