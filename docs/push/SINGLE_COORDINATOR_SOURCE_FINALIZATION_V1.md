# Single-executor SQLite coordinator: separate source Finalization

[Source PR161](https://github.com/pcvantol/djconnect-api/pull/161) delivered main
`81324d0d75b843de7f986d8bcfb44c87fdd9d542` from reviewed candidate
`a147f2afe3af44a763e6ff84bd5712932f592532`, based on qualified Final160 main
`11a342108caea66ab9d69306b16d79bf81f6871b`. Candidate, actual GitHub test merge
`024bc19161e822691c007c1e4175e9b9c75fb7d1` and protected source main have the same
tree `91173f532c204ef36c0c60045d57affac4b32e35`.

The [package guide](../../coordinator/README.md) describes one native SQLite
transaction domain, passive registration DATA decoders, original operation and
global key-counter CAS, and the final same-executor source-observation boundary.
The consumed private handle binds the complete original immutable admission,
Job and policy/clock witnesses. Actual SQL job/status/parent joins are checked
before and after synchronous construction, with a final local clock guard.
ProductionCoordinator remains unavailable before opening a DB or reserving work.
There is no HTTP server, native SDK, signer, provider callback, daemon or installer.
The private source coordinator records synthetic observations only.

Core personally reviewed all original fourteen files and every successor delta,
verified fifteen manifest inputs and the complete source TAR against Git, then
independently ran all 38 tests and three JavaScript byte vectors. Its exact-head
whole-source receipt reports no blockers. Apple separately reviewed passive
wire/vector/JS bytes at d1b; those bytes are unchanged in a147. This bounded
consumer review is not a whole SQLite, security, clock or native review.

Original failures remain preserved. The first 21-test attempt had 20 passes and
one cancellation-harness error; the successor repaired that harness and added a
post-commit cancellation guard. Original 99307's 29 tests passed but independent
causal probes found wrong opaque auth-generation typing and a final-context
substitution flaw. 3b1 fixed auth-generation but malformed types still raised
TypeError; d1b added controlled type rejection. a147 binds the exact original
admission and actual SQL joins and fixes reentrant callback accounting. No earlier
candidate or failure is relabelled as qualified by these successor results.

Actual owning and independent local qualification passed 38 tests on CPython
3.14.10/SQLite 3.54.1 Darwin. Candidate CI passed the same 38 on CPython
3.14.9/SQLite 3.45.1 Linux; original source-main CI passed 38 on CPython
3.14.8/SQLite 3.45.1 Linux. Each also passed three synthetic canonical-byte vectors
in JavaScript. Tests cover two-connection CAS, partial rollback, actual process
exit before/after COMMIT, lost ACK, late cancellation, no capability restoration,
original deadline/context/parent/scope checks, reentrancy, finite synthetic bounds
and malformed DATA. These environments are software evidence, not a selected
operational host, qualified UTC, physical power-loss or restore guarantee.

All twelve candidate workflows succeeded. Exact HIGH_RISK Owner Authorization
40490001468 followed Trusted Delivery 40489928217; the real PR CodeQL aggregate
122141423970 succeeded with zero annotations. Actual Validate also passed 443
Worker cases, 49 composition cases and 128 compiled-product checks with 100
forbidden RPC denials and zero egress. Its E2E subset passed one and skipped 39.
All thirteen original source-main runs succeeded, including Python 40490756583,
Validate 40490756698, native/browser 40490756017, formal 40490962484 and release
40490961810. Main workflow success does not imply an additional PR-style CodeQL
aggregate; none is claimed. No bypass, old-SHA authorization or scanner waiver
was used. UI and all five languages remain unchanged.

The [machine record](single-coordinator-source-finalization-v1.json) binds the
actual original run inventories and formal/durable/release verification. Formal
qualification has no findings and source digest
`903a8b93b77c029d2579a3de612b2f2213d931fb3acc19744c9e9731d41cc473`.
Durable asset 681289660 matches provider SHA256
`d7503e3bbf7a05e410dd3b29ef9d868365cfb0ddae0a94e8a615a98d42fb3bff`;
both canonical joins and all twelve durable checks pass. Release TAR
`538fa808fc2a521ab24b36dcc6f5c467019bdf2154a64f998e93b9f8beb5e578`
contains a 1,291,540-byte Worker with SHA256
`c82543035d9aa8c6dae74634f10a88a6fd87367807f3920932a46a6ec3cedd24`.
Unique safe paths, all seventeen sidecars/migrations and licenses match exact Git.
The Worker equals Final160 except one embedded source SHA. The coordinator source
package is not in that Worker artifact; its fifteen inputs plus manifest are
separately Git-bound source, not an installed coordinator artifact.

Core independently checked all eleven original packet-file hashes, both canonical
formal/durable digests, exact source/coverage/tree/parent, the safe TAR and all
seventeen Git sidecars/licenses, and direct equality against the original Final160
TAR except its one embedded source SHA. Core also read the formal/release/native
run metadata live and separately confirmed all thirteen original main runs on
attempt one. The receipt covers owning-downloaded original JSON/TAR and provider
metadata, not an independently downloaded raw artifact ZIP.

The protected source publishes preparation software only. Worker root, bindings,
dependencies, production migrations and deployment configuration are unchanged.
The compiled root remains closed/503 and the prior 22 full-service gates stay OPEN.
Actual management signature/native transcript/key-mode/role verification, durable
native reservation, signer custody, finite accepted live policies, qualified
UTC/boot/suspend, VFS/nonrollback, shipping status-only renderer and provider/device
acceptance remain open. DATA parsing, synthetic tests or a matching parent hash
cannot arm a legacy native task owner or supply native capability.

These two documentary files need their own exact independent review, protected
merge and original main qualification. They neither perform nor authorize new
production SQL, keys/tokens, SDK, HA/provider/device, installation or deployment.
