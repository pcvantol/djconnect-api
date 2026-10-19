# Routed budget backoff metadata

Profile `0.4.0-draft`, wire `djc-rendezvous/1`, **NOT_FROZEN**. Same sole writer
and draft PR96, continuation from af0c200; main e67f402 unchanged. Fresh ACK:
https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6261606740.
Independent security and UX design-GO preceded source. This fixes the concrete
nonblocking hint-loss observation in [receiver review](https://github.com/pcvantol/djconnect-api/pull/96#issuecomment-6261463500).

## Change and trust boundary

[Shared validator](../../qualification/rendezvous/retry-hint.ts) accepts only
optional safe-integer retry_after_ms1..60000. Existing closed budget-denial shape
and code checks remain. KeyRpcRouter carries that validated value through its
private Failure/result; TransactionState retains it only on trusted negative
rate_limited/service_unavailable authorization; composition projects only the
fixed code plus validated hint. Existing ingress emits Retry-After rounded up
from milliseconds to seconds (1001ms becomes2s). The canonical optional field,
HTTP codes and endpoint schemas are unchanged.

Missing remains absent. An invalid type/range, including null/zero/fraction/NaN,
becomes redacted503 without a hint. Successes, proof rejection, conflict, unknown
codes and arbitrary exceptions do not acquire hints. No backend private text or
extra fields are projected. This does not change a success predicate, assertion
counter, lease, original transaction/key expiry, retry count or state transition.
A refused submit remains pending and the same assertion can succeed after quota
is restored; at original expiry it is rejected regardless of previous advice.

Consumers still need bounded fallback when no hint is supplied. A hint advises
waiting; it does not grant another attempt, new QR/key/enrollment, automatic retry,
a new clock window or HA screen/session admission. Source review is not contract
freeze, production adapter admission or deployed behavior qualification.

## Executed evidence and historical corrections

[Source-bound observations](workerd-retry-hint-observations-v1.json):
**853/853 actual local workerd + isolated strict TypeScript + exit0 PASS**:
38 new routed-hint cases and815 existing request/HTTP/index/key/transaction/
registration/assertion/storage/crypto cases. Guarded HTTP tests cover actual
allocation/IP/global quotas, key-call exhaustion before child namespace access,
registration-attempt refusal and submit-authorizer denial through real SQLite.
They check exact JSON hint and Retry-After,1/1001/60000ms boundaries, absence,
malformed/nonbudget/private failures, same-proof retry and original-expiry equality.
Additional actual SQLite cases verify valid and malformed trusted-authorizer hints
without state commit. Native enrollment remains explicitly software evidence.

Run a FAILED:844 passed/3 failed. Two old HTTP tests still expected the old
hint-less budget errors; their specific quota assertions now require60000ms.
Their helper accepts an explicit expected optional hint; other cases still require
no hint. A separate pre-existing software enrollment setup unexpectedly rejected
once. Run b847 passed without changing that setup. Inspection found a timing
hazard in the SOFTWARE status fixture: separate Date.now reads could produce
thisUpdate>checkedAt across a millisecond boundary, contrary to its verifier.
The fixture now uses one captured clock value for both fields. This is consistent
with the observed transient rejection, not a proven reconstruction of that run;
no real receipt/status/verifier predicate was changed. Six further SQLite tests
were added. Final c853 passes; unsuccessful run history remains recorded here.

Existing API40/40, root types, offline projection and107 schema cases/two byte
examples also pass. Independent supplied-source security and actual-file
UX/privacy/evidence source/doc reviews, corrections and exact-head CI are recorded
on API90/PR96. Reviewers did not independently execute this suite. Neither this
result nor local standard crypto evidence proves genuine iOS/public/HA/TV behavior.

Reproduce with existing pinned cbor10.0.12/PKIJS3.4.1/ASN1js3.1.0/JOSE6.2.12:

```sh
node qualification/rendezvous/run_retry_hint_workerd.mjs /private/tmp/pinned-pki-deps /private/tmp/new-retry-hint-results /private/tmp/pinned-jose-package
```

The new runner preserves the existing eleven local SQLite bindings, fetch/telemetry
denial, dependency/trust/source hashes and output0700/files0600. Five preceding
transaction/index/key/HTTP/request runners also copy/hash the new shared helper,
so their entrypoints remain usable. No dependency, root product binding or
Wrangler configuration changes; no root type regeneration is needed. Historical
observations remain bound to their original source, not relabeled as current.
Sanitized observations contain versions/hashes/test names and reserved synthetic
labels, no real user IPs, private proofs, keys or destination values.

## Delivery and remaining owners

Rollback is a reviewed source revert; no new table, migration or provider operation
exists. Default root remains503; no public service, consumer code, device/key,
Cloudflare or timer mutation. Previous source-qualified admission caps and their
joint NAT/capacity review remain unchanged. API still owns real edge identity,
public adapter coverage, WAF/abuse/provider-error and cost/capacity/retention/
monitoring/deployment preparation. The routed optional-backoff loss is now fixed
and locally qualified on these selected paths, replacing that earlier limitation.
It does not qualify every possible outage source or invent missing hints.

Apple supported signed-iOS action/genuine-composition proof, Core actual HA/proxy
and separate display admission, receiver's contract-gated adapter and physical
HA/iPhone/TV acceptance remain separate. Original captures/ACKs/crossruns stay
delivered; no unchanged repeats requested. No HA/Profile/Session credentials,
central destination-fetch/decryption or screen/session authority is added. No
merge, Finalization, deployment or whole-function completion is claimed.
