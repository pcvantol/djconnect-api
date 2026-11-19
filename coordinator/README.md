# Single-executor coordinator source qualification

This package composes one native `sqlite3` transaction domain, passive Core/Apple
wire decoders and a final local observation boundary. The public production
coordinator always raises `Unavailable`, before opening a database or reserving
an operation. There is no server, daemon, signer, native SDK, HTTP client,
provider callback, installation command, default DB or production factory.

The private source coordinator uses explicitly synthetic admission and clock
fixtures and records only source observations. Its submission seam cannot send
anything. A successful test is not native admission, APNs acceptance, delivery,
installation or a real Linux/UTC/VFS qualification. The Mac source run uses
CPython 3.14 and actual local SQLite; it does not select a production host.

The jointly reviewed r3 plan and its HTTP addendum are recorded by hash in
`source-manifest.json`. The Core-owned normative passive contract is pinned to
its exact content hash; it is not vendored or silently read from a sibling repo
at runtime. No source depends on an unpublished Core Python package. A/B remains
a separate family, with no reinterpretation of R9/APIv2/Source153 or null Session.
Core owns its actual pairing record, ACK, private scope hashes and mutation hooks.

## One transaction domain

`schema.sql` is disposable qualification DDL. Only tests create it. Opening a
store requires an existing file, matching explicit restore epoch and read-back
WAL/FULL/foreign-key settings. The profile requests real SQLite commit sync; it
does not prove physical storage/controller power-loss or backup nonrollback.

Operations/nonces are globally unique across jobs, stages, roles and epochs.
Claims jointly bind the original immutable job, revision, stage and body hash.
Counter scope and uint32 monotonicity are shared across real key references,
never reset by a new parent or principal epoch. Target verification must use the
job's original verified key. Partial writes fail inside one explicit transaction.

The domain ports the once/CAS/global-counter invariants from
`src/surface-push/native-proof-data-journal.ts` and its disposable SQL schema.
These remain uncomposed D1 DATA source, not a second authoritative Linux journal.
No existing D1 PASS is reused as proof of the new adapter. New tests exercise
the same causal invariants with actual native SQLite and explicit synthetic
authority. This increment does not implement actual native attestation or
management principal verification; DATA storage methods cannot confer admission.

An ambiguous COMMIT fences/closes the connection and reports `UnknownCommit`.
It never claims rollback of an acknowledged commit or repairs with a new UUID.
Cancellation is checked after actual settlement and before final publication.
Process-exit tests distinguish before/after COMMIT; they are not physical
power-loss tests. Restart never reconstructs an in-process submission handle.
The consumed private handle binds the exact original immutable admission,
complete Job and original clock/policy witnesses, rather than only a job ID.
Actual immutable SQLite job/status/parent joins are checked both before payload
construction and again before the final local clock guard. A reentrant build
callback updates only its own captured observation record.
Actual restore acceptance and unknown-native-outcome recovery remain unqualified.

## Passive wire boundary

Two exact role paths retain independent original A parents. The decoder accepts
only fixed-order closed canonical DATA, strict lexical integers, exact hashes,
UUIDs and platform/client aliases. `AUTHORITY_CURRENT` returns a plain DATA dict;
it has no connection to old native task owners and never triggers SDK fallback.
The child state has thirteen fields and labels the original **A** operation.
Index ownership, order, uniqueness and required injected child count are checked.
Normal and original-B-receipt body caps are 16,384 bytes. Only the index decoder
accepts 65,536 bytes. The receipt parser returns explicitly **unverified bytes**;
it cannot verify a Core signature, validate a B grant or produce native authority.

Callers must enforce the same decoded-body cap while receiving bytes, before
calling these in-memory parsers. There is deliberately no HTTP receiver in this
increment. Native status payload projection is not implemented or changed; the
existing profile's eight-field Activity/five-plus-six Widget shapes stay intact.

## Qualification and remaining work

Run with an explicit scratch directory on Shared Data locally (or runner temp
in CI), `PYTHONDONTWRITEBYTECODE=1`, and CPython 3.14:

```sh
python3.14 coordinator/qualify.py
```

The runner verifies every manifest source input before running tests. It needs
no pip install or third-party dependencies. The existing Worker bundle, root
imports, migrations, bindings and deployment paths are untouched. A separate
pinned CI job runs the Python qualification; existing Worker CI is not relabelled.

Actual management signature verification, complete new native transcript and
key-mode/role validators, durable native reservation, actual key custody, accepted
policy lifetimes/count/rate limits, qualified UTC/boot/suspend evidence,
VFS/restore and provider integration remain open. The Linux continuous clock
reader supplies no UTC and never enables production. No code/config flag or
synthetic fixture fills those facts. Independent exact-source review is required
before publication; normal source delivery does not authorize deployment.
