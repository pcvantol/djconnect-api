# Worker/SQLite DO retirement capacity: separate source Finalization

[Source PR166](https://github.com/pcvantol/djconnect-api/pull/166) delivered reviewed
candidate `c91e40998398458bab76553a75e68af171f2127d` by normal expected-head squash
as protected main `81510409ea6b72f79bf744abf941e27fc17fdea7`, with parent
`a52a1dc9bece4a934a01e71dc1eb201759729225`. The reviewed candidate and protected
main share tree `9e99f8485746157acfaa71525690160a3604ee5b`. The human approved
that concrete source merge. This documentary Final requires its own review,
protected merge grant and original qualification.

Previously, registration or an unrelated pre-registration tombstone could consume
the final lifetime operation slot and prevent retirement of a stored epoch. The
[registry guide](../../coordinator/worker-do/README.md) now specifies the persistent
invariant `retained operations + stored unretired epochs <= max_operations`.
Registration consumes one operation and reserves one for its eventual retirement.
Retiring that exact stored unretired principal/epoch consumes its own reserved slot;
an unrelated tombstone may spend only unreserved capacity. Counts and reservation
share the existing SQLite mutation transaction. No mutable in-memory credits,
schema change, pruning, replay reset or production quota defaults are introduced.

Five selected new actual local workerd/SQLite DO cases fail against the original
module: 0 PASS, 5 FAIL and 31 unselected cases skipped. The corrected full suite
passes 36 cases with zero failures or skips. Strict types and locked source
packaging pass. Tests cover minimal budgets, multiple principals, unrelated
tombstones, real SQL trigger rollback with exact operation reuse and committed
registration with a lost persistence acknowledgement. A new test stub is not a
real process restart, eviction or remote restore proof. Previously saturated or
older restored journals are not repaired by this admission check.

Core personally reviewed all four complete changed files, model context, Git diff,
manifest input hashes and the owning original before/after reports. The exact
whole-source review receipt is
`e0899d542321ceb7ef0a9d83d4b46b395bec45a886634700f97435ceaf774565`.
All thirteen candidate workflows succeed. Required Owner Authorization is
SUCCESS/not-required for LOW/NORMAL risk via Trusted Delivery40806680578.
Actual candidate registry run40806680432/artifact12868875316 passes 36/0/0;
provider/download ZIP SHA256 is
`8c80e64de88b1acbb559b46a4c12376d5353794dab57a4b91dbe1f6050dcd26f`.
GitHub test merge9e6d10052d79ce9f737c38ea6da40271481750e1 has the same candidate
tree and exact base/candidate parents.

All thirteen original source-main workflows succeed. Actual main registry
run40831088024/artifact12878073455 passes 36/0/0; its downloaded ZIP matches
provider SHA256
`1340b2b5b332f06169b7085bcc2947c9b4ccb26f95d1e4e26044f85c770b5cb0`.
The package is byte-identical to local and candidate qualification. Original
formal40831277936 and release40831277693 are separate own-main producers.
Formal canonical digest is
`5d7b2d078832af2fe7d17a7ad0171f238ff16ddc467618348084adc3f13b1abd`;
durable asset687636363 matches raw/provider SHA256
`b8bb39b5da7f45573ce9bef6ccff81f4675ef33f1194145e4438b9da7f08fad4`.
Both canonical joins and all twelve durable checks pass. Actual downloaded release,
release-evidence and formal ZIPs were separately checked against provider hashes.

The original release TAR SHA256 is
`9ae7f6fe0c4a240cb772638d5f736b55e42d965a305d56d02951bb8f7d4d7f2c`.
Its ordinary API Worker is 1,291,540 bytes, SHA256
`ae79e64c45f0517aa9d3cb2cddb221f75fd5545b958ff597b0d1a71d8595c2db`.
Safe unique regular TAR paths, seventeen Git sidecars/migrations and license hashes
match exact main. This Worker equals original Final165 except one embedded release
SHA. The registry remains absent from the ordinary root Worker artifact.

Core personally joined the owning-downloaded original bytes, own live GitHub
workflow/artifact/durable metadata, canonical joins, Git tree/parent and original
TAR/sidecars/licenses. Core did not independently download those ZIPs or rerun the
current tests. The no-blockers original Source166 receipt is
`9150116ae7bd5a56342b9dfc2d7f26a61b486edbfceedb602968438c7bf2d8be`.
The [machine record](worker-do-retirement-capacity-finalization-v1.json) retains
exact original inventories and hashes; source packet SHA256 is
`7664de0f7e2fe9083ea3c55bb0fcec39ed90f002fae51b339e461a1b492c8153`.

This is an application DATA capacity correction, not a host availability guarantee
or actual registry admission. The standalone production factory remains unavailable
and HTTP remains no-store 503. Genuine operator/custodian, principal/key epoch/PoP,
independent Core-install trust, definitive purpose ACK, restore/current-read policy
and original clock/native/provider qualification are not supplied by this source.
No namespace, key, account upgrade, enrollment, provider/device or deployment effect
occurred. Ordinary API source/configuration/dependencies and all five supported UI
languages remain unchanged. This Final adds only these two documentary files.
