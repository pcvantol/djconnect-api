# Authorization and exact submit-receipt lookup internal failures

This bounded increment changes only `AssertionKeyState.authorize` and
`lookupSubmit` failure classification. Private typed input/proof/context/material
rejections remain401. Unexpected state SQL/read/JSON/transaction/hash/alarm
exceptions become the existing redacted `service_unavailable`/503. No error-text
matching, details, hints, wire fields or additional success authority is added.
The issue path, busy return, assertion-policy401, verifier core, counters,
capacity and successful authorization predicates remain unchanged. Errors already
converted to null by the verifier core remain proof rejections; complete provider/
internal error taxonomy and the full VibeCast assignment remain OPEN.

Failure-only bounds are copied into invocation-local closures after existing exact
binding guards. Validated numeric safe-integer creation/expiry pairs can only
intersect the known window. There are no catch-time SQL reads, request selectors,
shared mutable windows or new RPC exports. Unknown faults before exact binding
remain503 even when an unread receipt's five-second lease has actually expired.
Known original expiry/equality or wall rollback remains401.

A new receipt's bounds are tentative inside its SQL callback. Its original
admission/five-second lease becomes known only after transactionSync returns
normally. A rollback after computing a disposition therefore remains503 while the
original challenge/key window is live. A wrapper may instead commit and then
throw before acknowledgement: that outcome is also unknown503, even after an
unacknowledged five-second lease, without guessing commit success. Existing
persisted replay/lookup receipts and acknowledged commits retain their original
lease; expiry never renews it. No additional database fallback is performed.

503 is not rollback confirmation. A precommit receipt-write fault rolls counter
and nonce back; a postcommit alarm/read failure can retain the advanced counter
and immutable receipt. Explicit exact-proof replay within its original live
lease recovers that result without counter advancement or lease renewal.
Authenticated deletion is different:503 can coexist with committed erasure and
a tombstone, and explicit retry can return401 because operations were erased.
There is no invented delete-success cache, rollback claim, automatic retry,
refund, replacement key or challenge/TTL refresh.

Actual local qualification covers1181 affected workerd cases/strict types,
1387 full shared cases, and128 actual product/private-RPC/default-genuine checks
including100 forbidden RPC calls. A controlled paired counterproof uses protected
9c runtime with the matching preceding1180-test set:1132PASS/48FAIL, versus the
corrected1180PASS before one additional regression. This is not a whole-tree
baseline delivery or native proof.

Twelve actual composed HTTP fault cases exercise recovery/deletion/submit across
snapshot-read, receipt/tombstone-write, alarm and lost-commit-ack phases. Each
requires fault hit1, exact closed503/nohint, request/key charge1 followed by
explicit repair charge2. Submit stays pending until the actual existing local
software-fixture authorizer admits its original immutable grant; its challenge
attempt is not repeated and the resulting ready state retains one counter/lease.
The submit fault seam is the existing trusted constructor-only namespace seam,
not a wire/configuration verifier selector or fake grant. Delete postcommit repair
is401/tombstone. State probes additionally cover actual SQLite receipt-update and
delete aborts, corrupt JSON, unknown thrown markers, final reads, reachable arm
SQL/setAlarm, original-window rollback/equality, exact lookup and both rollback
and committed-but-unacknowledged outcomes. Unreachable getAlarm/deleteAlarm paths
are not claimed as authorization coverage.

Preparation binds immutable protected9c plus a fixed closed three-source delta,
complete66shared/85root proof maps,106 tracked inputs,32 installed hashes and13
references. All historical proof bytes remain unchanged. Depth-one supplier
qualification rejects missing/old-only objects, drift and forged maps; there is no
HEAD fallback, lazy fetch or generic delta chain.

Root compiledOFF/public503/serviceOFF/all22 full-service gatesOPEN. This source
qualification grants no SDK/native key/capture, provider, Cloudflare, credentials,
installation, deployment, selected HA or physicalTV effects. Exact independent
source/package reviews, protected delivery, actual own-main artifact/formal/durable
readback and separate Finalization remain required for bounded delivery.
