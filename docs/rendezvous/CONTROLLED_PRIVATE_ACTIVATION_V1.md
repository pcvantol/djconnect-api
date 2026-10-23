# Controlled rendezvous preparation for private household use

Peter selected private use on23October2026. The accompanying Cloudflare dashboard
shows990/100000 daily Worker requests and26/200000 observability events. Prepare
for the existing Free-level quotas, without an upgrade or additional spend.
The screenshot is observed usage, not a billing authorization or proof of future
headroom. Account subscription and edge-rule reads returned403; the zone's Free
Website plan and Worker `usage_model:standard` do not establish a Workers plan.

This source prepares a small private operating profile. It does not launch a
public service, add an account/pairing/TV-code step, enable the root dispatcher,
provision a key, enrol an iPhone or close the22 historical full-service gates.
Existing limited-A trust and the released implementation wire remain unchanged.

## Separate, reduced admission profile

The operator-owned `RENDEZVOUS_CAPACITY_POLICY=private-household/1` selects:

| Bound | Private profile |
| --- | ---: |
| Regular / total HTTP admissions per minute |400 /500|
| Regular / total HTTP admissions per UTC day |2000 /2500|
| Minute identity capacity |128|
| Newly allocated transactions per UTC day |20|
| Initial registration attempts per UTC day |5|
| Key RPC attempts per UTC day |500|

The existing per-IP minute partitions remain poll256/create16/native64/terminal16,
total352; transaction allocation remains at most5/IP/minute. Terminal requests
retain100/minute and500/day of global reserved headroom after regular exhaustion,
subject to their original per-IP bound and the absolute total cap. A cap is not a
promise that every attempted flow succeeds, nor an invitation to repair by creating
a new key, operation or QR. Original120-second transactions and30-day key retention
do not change. Missing capacity selection preserves the historical qualification
profile; unknown values fail closed. The private selector does not select native
policy, target, credentials, trust or public admission.

Both coordinator budgets retain the exact selected profile across alarm awaits.
A changed selection cannot commit a counter charge under a different limit. The
HTTP handler and product composition also retain their original selection across
asynchronous boundaries. Existing SQL rows, counts, alarm deadlines and namespace
identities remain in place; a lower profile never resets or refunds counters.

Free Worker limits currently include100000 requests/day and10ms CPU/HTTP request.
Free SQLite Durable Objects have separate100000 requests/day,13000GB-s/day,
5million SQL rows read/day,100000 rows written/day and5GB total storage limits.
Each stub method call is a billed request; alarms and deletes also consume quota.
See [Worker limits](https://developers.cloudflare.com/workers/platform/limits/),
[DO limits](https://developers.cloudflare.com/durable-objects/platform/limits/) and
[DO pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/),
read23October2026. These are provider limits, not measured application use.

The existing source model's60-poll successful flow uses65HTTP and201DO calls,
before enrollment, alarm, retry, invalid traffic and SQL. A small household trial
does not need a public-scale SLA/load study; it still needs one bounded actual
CPU/SQL/cleanup observation and current shared usage before claiming Free fit.
Application admission caps cannot prevent rejected Internet requests consuming
Worker/DO quota. No paid overage, throughput guarantee or hard bill cap is inferred.

## Concrete configuration prepared, not applied

[The machine record](controlled-activation-preparation-v1.json) contains the exact
five SQLite class/binding overlay and proposed first migration tag. A complete
account namespace read returned zero current namespaces. The deployed Worker
already exports these five classes, but has no DO bindings. That resolves current
namespace inventory only; it does not approve migration, allocation or deletion.
Preserve the existing12 bindings, D1, routes, ordinary push and pairing settings.

Two new independent canonical-base6432-byte secrets are required:
`RENDEZVOUS_IP_HASH_KEY` and `RECEIPT_ACTIVE_KEY`. Both are absent in the actual
secret-name readback. `RECEIPT_PREVIOUS_KEY` is optional for initial configuration
and is used for explicitly admitted key rotation; its absence alone is not an
initial-start blocker. This package contains no values and provisions nothing.
Operator custody, recovery and rotation must preserve still-live receipt keys;
never copy existing APNs/pairing credentials into these bindings.

The current Worker has persistent invocation logs and query redaction disabled.
The prepared overlay enables `observability.redact_query_string` and disables
`observability.logs.invocation_logs`. It is not applied by this branch. Do not log
raw IPs, QR/claim secrets, nonces, assertions, receipts, encrypted destinations or
HA URLs. These settings do not erase historical logs or establish the provider's
retention/backup/DPA policy. No claim about physical deletion follows from source.

## Native and controlled-effect boundary

The normal deployed verifier remains the fixed development profile for measured
builds40227/40228/40230. The separate historical fixed-QA40408 window expired.
Apple has confirmed there is no current rendezvous native-positive/admission;
ordinary installed40450 is not that evidence. Do not rename the dev policy to
production, reuse an expired selection, use software fixtures as native proof or
put an arbitrary app/build into configuration. The prepared native tuple stays null.

For a private trial, identify one exact signed app/build/profile and finite test
window, retain original server nonce/deadline and obtain the real App Attest
positive and action-bound assertion with the Apple owner. This is a separate
bounded native action; no new capture/key/device action is performed here.
Then review the exact source/config/artifact and central private activation
manifest, perform the specifically authorized controlled deployment and small
live test, and retain actual iPhone/selected HA/browser results separately.
Existing source/wire ACKs and unchanged captures are not requested again.

Keep the public compile guard false until that admission is complete. Rollback
must preserve newly created class exports, bindings, rows, alarms and original
retention windows; the old ordinary Worker version alone is not a cleanup-compatible
rendezvous rollback. No reset/drop/namespace removal or secret rotation is part of
this package. The successful ordinary API healthsmoke does not prove rendezvous.

## Reproducible local preparation check

Run `python3 scripts/check_rendezvous_activation_preparation.py` and
`python3 scripts/test_rendezvous_activation_preparation.py`. Exit0 of the former
means the fixed package is consistent **and explicitly blocked**; it cannot issue
an activation, deployment or native approval. It performs no network, secret
discovery or effect. Provider metadata is a dated readback with preserved original
hashes, not a live monitor. Original403 reads remain unavailable rather than
being converted into successful or empty policy evidence.

Actual qualification of this candidate:1570 local shared workerd/SQLite cases
and strict types PASS, including12 new private controls;49 product-composition
cases and strict types PASS;128 actual bundled-product checks PASS, including100
forbidden private-RPC rejections and zero egress. Root types and diff checks PASS.
The same12 selected new cases against only the previous812 request/allocation
runtime give1PASS/11FAIL; all12 pass within the new1570-case run. No full old
suite result or genuine native positive is inferred from that targeted control.
Eight new preparation negative controls and36 existing offline-plan controls PASS.
The unchanged106-input protected baseline plus exact15changed/additional inputs
still yields110 unique tracked pins;66shared/89root/19module maps and all32
installed dependency hashes retain their original qualification scopes.

Original prepare failures (an incomplete historical temporary JOSE package,
wrong diagnostic source path, counterproof config cwd and Vitest-runner mismatch)
remain separately retained and count as neither passed tests nor causal failures.
The complete pinned JOSE6.2.12 test artifact was restored after checking its
registry SHA512 and all80 tracked file hashes, without install scripts. A trial
privacy-config edit correctly failed the existing immutable product-config check;
it was withdrawn byte-for-byte. Logging changes remain only in the prospective
reviewed overlay; the current128-check product proof matches the retained config.

Independent exact source/commit reviews and protected delivery remain pending.
No public/private service-readiness, installed or activation claim is made by
this preparation document.

## Closed qualification consumer rebind

The first candidate CI correctly rejected stale source pins in fixed-QA derivation
and the local native/browser harness. The QA record changes only composition
source/derived hashes under the original exact two replacement rules; historical
40408 identity and null current profile/admission are unchanged. The local harness
now reads the new independently pinned product proof, verifies its original digest
and rejects any overlapping source pin mismatch before merging installed hashes.
It still requires a clean exact source tree, literal closed guards and original
finite local nonce windows. This rebind cannot create native or provider admission.
The original failed CI remains failed; fresh exact-head results are required.
