# Unqualified certificate-status result, not invalid registration proof

Profile `0.4.0-draft` / wire `djc-rendezvous/1` remains **NOT_FROZEN**. Same sole
writer/draft PR96, continuation from74926a4; main e67f402 unchanged. Fresh ACK:
https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6262317721.
Independent security and UX design review preceded this isolated source change.

## Exact correction and remaining ambiguity

The existing CommonStatusClient returns the controlled private negative
`{ok:false,error:'status_unavailable'}` when status cannot be qualified. Previously
the enrollment composition reduced that result to registration rejection, and
HTTP reported invalid_sender_proof401. The verifier now recognizes only that exact
closed two-field result and uses a private typed exception to return the existing
canonical attestation_unavailable503. EnrollmentKeyState preserves only its exact
closed denial; composition recognizes that already-defined wire error code.
No schema, endpoint, new HTTP status, consumer protocol or capability is added.

The meaning is **status could not be qualified**. It does not prove an Apple
outage, revocation, invalid iPhone or an invalid receipt. Network/protocol/status
validation failures remain deliberately indistinguishable at this boundary.
Unknown results, extra fields, malformed markers and exception text do not acquire
this classification. Busy, crypto/CMS, encryption/storage and arbitrary exceptions
retain their existing generic paths: a complete provider-versus-proof/internal
error taxonomy is still OPEN and not inferred from this correction.

After each CRL/OCSP await, original challenge/snapshot/policy context checks
precede classification; receipt freshness and, for OCSP, the previously qualified
CRL's lifetime also run first. Late or mutated context still rejects. No success,
certificate/revocation, evidence, counter, lease, privacy or persistence predicate
is weakened. A rejected/unqualified status never authorizes a key or destination.

The enrollment layer returns before installation, keeping key/receipt tables
empty and the same original nonce/expiry pending; finally clears intent/busy.
A same-proof retry can succeed only within existing original deadlines and
budgets. Registration attempts still count, including unavailable outcomes; no
refund, fresh key, re-attestation, QR, implicit retry or extended lifetime. No
server retry hint is invented. Consumers use their bounded original-expiry fallback.

## Executed qualification

[Source-bound observations](workerd-provider-unavailable-observations-v1.json):
**961/961 actual local workerd + isolated strict TypeScript + exit0 PASS**:
21 new cases,87 existing enrollment-verifier cases newly included in this composed
runner, and853 prior HTTP/admission/index/key/transaction/crypto/storage cases.
No duplicate counting. Empty genuine fixture inputs are explicit: no fresh native
capture, genuine supported-iOS enrollment or provider/HA/TV runtime proof.

New cases cover CRL/OCSP controlled denials, finally recovery, exact/malformed/
extra-field markers, original challenge/nonce/policy/revision mutation, receipt and
prior-CRL expiry, and private exception-text rejection. Actual SQLite enrollment
tests prove no active key/receipt or pending-operation change, then original-proof
software enrollment success. Guarded HTTP produces exact503 without a hint,
counts the attempt, preserves nonce/expiry, and accepts that same proof after the
trusted fixture is repaired. Expired enrollment rejects before verifier invocation.
Test subclasses exist only inside local trusted constructor callbacks; there is
no environment/request selector or product software verification path.

Run a FAILED:960 passed/1 failed. The new receipt-expiry test mutated the borrowed
CMS result after the verifier had already copied its scalar fields, so it did not
actually expire the saved receipt. It now sets the initial receipt at its freshness
boundary and advances the clock; verifier predicates were not changed to satisfy
that failure. Final b961 passes. Historical failure remains explicit.

Reproduce using existing pinned cbor10.0.12/PKIJS3.4.1/ASN1js3.1.0/JOSE6.2.12:

```sh
node qualification/rendezvous/run_provider_unavailable_workerd.mjs /private/tmp/pinned-pki-deps /private/tmp/new-provider-results /private/tmp/pinned-jose-package
```

The runner preserves eleven temporary SQLite bindings, default HTTP503, disabled
fetch/telemetry and source/tool/trust/JOSE hashes, output0700/files0600. Sanitized
observations contain test labels, hashes and versions, no private proofs or user
credentials. Existing API/root types/projection/schema validation and independent
source/security plus actual-file UX/privacy/evidence reviews are registered on
API90/PR96; reviewer scope does not imply independent runtime execution.

## Source qualification and separate preparation rebind

This runtime source increment intentionally makes the old49ec supplying baseline
in the offline deployment-preparation validator reject current working bytes.
That is expected fail-closed provenance, not permission to ignore the validator.
After this source/test/doc review and its exact source commit, a separate change
must pin that new immutable supplying commit/proof hash and regenerate the
preparation plan. Its22 gates stay OPEN, artifact/account/approval/entrypoint null
and activation false. The earlier853 observations remain historical; this961
result is new evidence, not relabeled evidence or product artifact qualification.
The later preparation commit and final CI/producer receipt identify both pins.

No product handler/binding/root Wrangler configuration/dependency, D1/APNs/pairing,
consumer source/device/Cloudflare/timer change occurs. Source rollback is a reviewed
revert; state schemas and original cleanup remain unchanged. Public integration,
real edge/provider/load/cost/retention qualification and joint contract/security
freeze remain API-owned. Production deployment needs separate exact authorization.
Apple genuine signed actions/composition, Core actual HA/proxy/separate display
admission and physical HA/iPhone/TV stay separate; prior capture/ACK/crossruns
remain delivered, no unchanged repeat requested. Full function stays OPEN.
