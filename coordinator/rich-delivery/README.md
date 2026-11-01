# Rich delivery adapter

This server-side adapter connects the qualified rich raw-fragment codec to a
single APNs request without routing ContentState through the older JsonObject
profile or JSON.stringify payload path. It implements the API-owned transport
portion of the agreed requirements. It is not an authenticated public endpoint.

The mandatory composition ports authenticate and consume/reserve the original
attempt, assert actual current admission, authorize the provider, durably mark a
single outbound attempt, persist the observation and supply time/transport.
There are no default ports, environment/key lookup, network transport or owner
booleans. A parser handle, caller-supplied JSON or the possession DATA verifier
cannot instantiate real custody. Actual deployment composition must provide the
original installation/permission/field-relay/target/clock checks; the current
production service has no such admitted rich composition.

After admission/reservation the adapter snapshots primitive original fields and
refuses accessors. It checks exact original Attributes/ContentState/UTC bounds,
requires update/end rather than remote start, and retains all three codec byte
limits. The internally committed digest binds operation, environment, topic,
token, expiry and the exact final body. This internal ledger commitment does not
select or replace the still-unselected public authentication/signature grammar.

Reservation precedes provider authorization. A durable once-only dispatch marker
precedes the outbound call. Synchronous current-owner/cancellation/expiry/time
checks run after every relevant await and immediately before that call. The
request preserves the original ContentState bytes, uses an allowlisted APNs
origin and explicit liveactivity topic, rejects redirects and bounds its signal
by cancellation and remaining expiry. No retry is performed.

Repeated/concurrent same-process operation IDs are negatively fenced. This set
is bounded at 4096 and never evicts an operation for replay; deployers must scope
the adapter to an admitted service generation. Durable markDispatch supplies the
cross-process once-only guarantee and must retain markers when replies are lost.
finish must never clear a marker or recreate authority. This adapter is not the
implementation or qualification of those required durable owner ports.

Provider ACK loss or ambiguous durable-marker/finish ACK remains UNKNOWN.
Withdrawal after an actual provider response preserves the recorded provider
observation but returns no positive current result. Provider acceptance means
only that APNs accepted the request, never iPhone delivery or product acceptance.
Invalid-token registration retirement is a separate owner-store responsibility;
this adapter returns the provider status and does not invent a registration write.

Qualification uses genuine local workerd plus synthetic owner/ledger/provider
ports and a fully mocked APNs transport. No actual key, token, APNs or device
effect is exercised. The original first run was 31 PASS/1 FAIL: the async-owner
negative expected not_sent although final guard correctly retained UNKNOWN.
That test expectation was corrected. The final expanded suite passed 45 cases
with zero failures/skips, including denied real global network/key/signing calls
and full-string final-LF negatives. Those LF cases already passed on the original
adapter; no regex failure or source repair is claimed. Two initial type diagnostics were in the
negative port cast and mock literal return type. Earlier evidence is retained.

Run strict types and tests with:

```
node_modules/.bin/tsc -p coordinator/rich-delivery/qualification/tsconfig.json --noEmit
node_modules/.bin/vitest run --config coordinator/rich-delivery/qualification/vitest.config.mts
node coordinator/rich-delivery/build-source.mjs "$TMPDIR/rich-delivery-package"
node coordinator/rich-delivery/qualification/check-package.mjs "$TMPDIR/rich-delivery-package"
```

No root HTTP admission, compiled surface gate, existing family/profile map,
production namespace, dependency or native consumer source is changed. The
separate #169 hold/registry dependency is untouched. Real management/signer
custody, exact authenticated receiving wire and qualified native clock mapping
remain required before production admission; they are not supplied by tests.
