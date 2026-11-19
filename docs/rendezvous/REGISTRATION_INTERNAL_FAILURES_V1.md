# Registration internal failure qualification

This bounded correction separates expected invalid registration input/proof/context
from unexpected internal storage, transaction, encryption, alarm or thrown verifier
failures. The first remains `invalid_sender_proof`/401; the latter uses existing
redacted `service_unavailable`/503. Exact closed verifier `enrollment_rejected`
remains401 and `attestation_unavailable` remains the separate existing503 category.
Unknown/malformed result envelopes, including arrays, cannot impersonate either
domain denial. Existing semantic evidence/material/context validation remains401;
this does not classify every malformed positive evidence value as an internal503.
Classification uses internal types, never exception text or client markers.
Malformed base64 decoding stays an expected rejection. Success and acceptance
predicates, cryptography, current-policy availability and management are unchanged.
The software-only fixture catches its JSON decoding errors as a closed denial;
it is absent from the product build and proves no native admission.

After original key/challenge/policy context binding, copied original creation and
expiry scalars preserve rollback/expiry rejection before an asynchronous thrown
failure. The catch performs no storage reads and never guesses an unknown deadline.
The original nonce, expiry, request identity and counter are not renewed or refunded.
A precommit failure leaves no key; a postcommit503 can retain one committed key and
result. It is an unknown outcome, not rollback confirmation. Explicit repair with
the same original request recovers that result. No automatic retry or new key is
introduced. Existing busy-return and assertion management behavior remain outside
this slice; this does not close the complete provider/internal-error taxonomy gate.

Actual local qualification passes1073 affected cases with isolated strict types,
1279 full shared cases and128 product export/private-RPC/default-genuine-negative
checks. A separate counterproof retains the two exact protected379 runtime files
with the new tests/fixture:1044PASS/29FAIL; it is not a whole-tree baseline run.
Exact source hashes are in the accompanying shared/root observations and closed
source delta. Six HTTP fault phases (read,
transaction, key-version digest, encryption, first alarm, postcommit alarm) each
require one observed hit, exact closed503, no Retry-After hint, one charged attempt,
and a second charged explicit repair with the original deadline and one key.
SQL rollback on each transaction half, arbitrary thrown values, malformed result
contracts, valid context replacement, decoder rejection, original expiry equality
and rollback precedence are separate checks. These are synthetic local workerd
checks; none is real App Attest or physical-device evidence.

The immutable supplying source is protected379d70b; the new closed six-input delta
and separately hashed shared/root observations bind the exact effective106-source
map. All historical proofs remain unchanged. Actual local preparation remains
blocked:22gates OPEN, root compiled OFF, no public activation, native effects,
provider calls, deployment, HA installation or physical TV acceptance. Independent
exact-source reviews, protected delivery and separate finalization are required
and recorded outside this source qualification document.
