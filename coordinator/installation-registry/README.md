# Installation registry transactions

This implements the missing API-owned transaction domain of the private S1/S2 R2
installation-principal design `7b44758c5f7bba76dd3f61b042a776330ee25697523d3bd05248a5697f76db4b`.
Its DATA codec was delivered in PR169 (protected main
`f156c3049a6320bc16d084b4b17b526090ccb7a7`). This transaction source is
restacked from retained candidate `ce2b532c1058cf78213cfb76c837bfa741ed4020`
onto qualified Final190 main `13cb4f3ef82e16e6f4998f68cd5d867fdf8fc1c5`,
with the current locked Wrangler4.154.0 toolchain. Historical codec delivery
does not qualify these new transactions or their production admission. The existing
pair-bound registry V1, original source manifests, public routes and root Worker
are unchanged. No positive production authority is constructed.

## Actual implemented boundary

`InstallationRegistry` takes one real `DurableObjectStorage`, its original registry
identity/restore pins and a REQUIRED independent synchronous authority port. The
port must authenticate the exact original operator, installation, custody, clock,
restore, withdrawal and action. There is no implementation, default owner, Boolean
grant or public HTTP admission route. A matching hash, decoded record, valid PoP,
GitHub actor or HA pairing token supplies none of those facts. The exact originally
captured authority method is retained across awaits. Its exceptions propagate.

Preparation validates the complete original generation/receipt/subject/context/
proof/transcript/intent chain. One actual SQLite transaction reserves immutable
original intent, globally unique operation/challenge/nonce claims and its terminal
capacity BEFORE acknowledging preparation. Local custody epoch, principal epoch,
state revision and ledger revision are separate. A new principal begins at epoch1;
a successor requires the previous retained intent to be retired. No bootstrap
challenge or generation is issued by this library.

Admission durably consumes its original attempt before awaited real P-256/SHA256
verification. Invalid proof, crypto exception, missing commit ACK or cancellation
cannot retry that attempt. The final synchronous transaction independently rechecks
current authority, exact unretired original intent and original state revision,
then inserts an immutable principal record and original result. No await separates
the final guard and SQL commit. Crypto failures retain their identical original
cause; failed final SQL rolls back that transaction while the earlier attempt stays
consumed/UNKNOWN. Readback is point-in-time DATA, not a signing permission or lease.

Original-intent withdrawal handles both pending and committed/lostreply admission
without requiring the lost signer, a future result digest or a caller-supplied
current revision. Known-result withdrawal is a separate exact closed input family.
Both consume the SAME pre-reserved terminal capacity for the original intent.
The transaction retains withdrawal once/nonce, permanent original-intent tombstone
and parent retirement fence together. Stored historical principal bytes remain,
but principal reads and later admission cannot cross the terminal fence. A successor
or another principal is not wildcard-retired. There is no child enumeration or
existing device-pair table to migrate: per-device reconciliation is a later distinct
consumer increment. No pair join is written or claimed by this source.

The tombstone's exact canonical bytes and committed revision are stored atomically;
its existing R2 digest is derived for readback after the transaction. No nullable or
future hash is inserted. Cancellation or digest/sync failure after commit means no
positive response, never rollback. Identical withdrawal can read the original result;
another operation or variant cannot spend another terminal slot. Status uses the
existing closed operation-status families, including diagnostic NOT_FOUND_DATA;
absence is never permission to remint an operation, key, nonce or principal.

Limits are explicit inputs, with no chosen production numbers. For C retained
identity claims and L unretired intents, preparation maintains C + 3L <= max_claims.
A new intent adds3 claims and reserves3 terminal claims. Its one withdrawal adds3
claims and removes one unretired intent. max_intents counts all retained intents,
including retired/UNKNOWN ones. Neither budget is a request-rate or host storage
availability guarantee. No eviction, nonce pruning, retry repair or quota reset
exists. A matching restored database does not prove nonrollback or currentness;
that is a required independent authority dependency, not a SQL-derived assertion.

## Dedicated packaging and qualification

The source packager emits the exact standalone transaction ESM and a SEPARATE
closed Worker/template with one SQLite DO target and no public route. The library
is intentionally not wired into that production Worker until actual independent
management/admission composition is qualified. The closed factory fails before
reading supplied namespace/authority inputs. Its constructor initializes no SQL,
key, challenge or configured store. The reviewable template does not select or
create a live namespace or alter the ordinary API deployment manifest.

The qualification Worker has no command RPC. Tests instantiate the engine inside
`runInDurableObject` with disposable real workerd SQLite storage and explicitly
synthetic owner ports. Expired independent public fixtures are retained unchanged;
test relationships are derived separately. As with source168, fixed PUBLIC insecure
scalar/nonce1 arithmetic supplies synthetic public verification examples, never a
private CryptoKey, randomness, generateKey or sign API. This is not genuine custody,
a registered identity, operator authority or native acceptance.

Tests cover commit/rollback, concurrent requests, postcrypto withdrawal, separate
state/ledger revisions, reserved terminal capacity, lost persistence ACK, malformed
proof, original error identity, cancellation, reentrant closure, exact port identity
and new engine objects on retained actual SQLite storage. New engine construction
is not proof of real process eviction/restart, remote restoration or power-loss
filesystem durability. The delivered ESM also runs against actual Node SQLite with
real public WebCrypto verification; that packaging check uses synthetic authority.
Earlier private47/48 declarative design cases are not claimed as executed by this
new focused suite. The current focused suite has49 executed workerd cases,
including explicit successor epoch/revision, old-withdrawal isolation and global
claim conflicts. The existing root API suite has40 passing cases. Dedicated
registry and root strict types pass, as does the actual delivered ESM on Node
SQLite. Initial restricted execution failed to open its local listener and ran
no tests; the subsequent local runtime execution produced the stated results.

```sh
node_modules/.bin/tsc -p coordinator/installation-registry/qualification/tsconfig.json --noEmit
node_modules/.bin/vitest run --config coordinator/installation-registry/qualification/vitest.config.mts
node coordinator/installation-registry/build-source.mjs "$TMPDIR/installation-registry-package"
node coordinator/installation-registry/qualification/check-package.mjs "$TMPDIR/installation-registry-package"
```

## Remaining production composition

The deliverable here is the API-owned transaction library and its closed target,
not an enabled registration service. `RegistryAuthority.assertOriginal` is an
explicit required synchronous port: a qualified owning composition must verify
actual operator admission, installation association, custody, original clock and
deadlines, registry restore/currentness and withdrawal policy on each call.
There is deliberately no default adapter that treats records, HMAC possession,
a public proof or matching metadata as those independent facts. The existing
paired host-wake receiving path does not implement this installation-R2 port.
A future connection must preserve that separation and the original Core contract.
No production namespace, live limits or restore policy is selected here.

Source whole/exact review, protected delivery, main/original artifact qualification
and separate documentary Final remain required. Concrete installation/operator/
custodian/provider/path/user/backup/clock/restore/withdrawal facts, management
composition, selected resource manifest and a complete approved effect packet
still precede real key generation/signing/registration/provisioning/deployment.
The old temporary RAM K1 plan is not daily custody or an effect grant. One rich
widget and one rich Live Activity with push remain the product direction; this
registry adds no second status-only user surface or new content permissions.

Primary runtime references: [SQLite storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)
and [Durable Object rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/).
