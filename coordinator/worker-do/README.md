# Worker and SQLite Durable Object registration source

The human selected the existing Cloudflare Worker plus SQLite Durable Objects on
2026-10-28. This increment implements a concrete private registry DATA state machine
and actual local DO conformance. It contains no Container, Dockerfile, Node effect
executor, paid-plan dependency, provider, signer or new management credential. It
starts from protected main `2d8637e634f5b2db84151e66027204db885d4369`; open Container
source PR163 and its evidence remain intact. It is not a retry of its rejected merge.

## Owning boundary

Core's actual source join is
`core-worker-do-registration-owning-source-join-20261028.json`, SHA-256
`39b9c478a95df770d889fcae5071bef5143a3b8afa695f313e36fb6866257347`.
The existing passive Core contract remains exactly
`af201f6a74f358b09460f3cea026b6104aef93d54d8ac9ea05bac32d43874492`.
The previously reviewed private B trust inventory is SHA-256
`65edd7212680cd34798429fe39408e1145151d4f0980ac5f062ab02626685c96`.

This private DTO uses their existing identity, public-P256-pin, purpose and lifecycle
primitives. Its field layout and source RPC are deliberately NOT a new normative
client registry DTO, public route or change to the af201 role GET/A/B wire. It must
receive whole-source owning review. A record is scoped to an explicitly supplied
Core/install/pair-binding DATA tuple; this is not a claim that one operational global
Core principal has already been registered or that ordinary pairing authenticates it.
Allowed purposes use the existing A/B literals. Complete real registrar enrollment,
PoP and trust-distribution semantics are not supplied by this storage representation.

Core explicitly found no actual genuine registrar-auth source in protected Core.
Ordinary HA device/admin/install/bootstrap/HMAC tokens retain their existing domain.
They do not authorize accepting a public pin, purpose delegation, PoP or custody.
The label `SOURCE_REGISTRY_DATA_ONLY_NOT_AUTHORITY` is only a fixture marker.
Supplied provenance/PoP digests remain unverified DATA, never proof of acceptance.

## Implemented behavior

One real SQLite DO holds immutable canonical public records, per-principal epoch
heads, retirement tombstones and a global operation/nonce journal. All mutations use
the actual `transactionSync` interface and acknowledge only after `storage.sync()`
and an unchanged revision/restore read. Complete SQL cursors are consumed before
await. JavaScript-private methods prevent SQL helpers becoming incidental RPC ports.

Registration validates an exact closed public JWK, canonical coordinate encoding,
actual P-256 curve import and the SHA-256 of exact sorted four-member canonical
public bytes. It reuses only the existing public-point validation primitive, not
Source153 credentials, signing domain or thumbprint domain. No private key is loaded,
derived or generated. Tests use fixed public curve points only. One epoch cannot
change its key, scope or record. The next epoch requires retirement of its predecessor;
retirement before registration also creates a tombstone. No old-epoch resurrection,
skipped epoch, replay-result cache, retry repair, nonce pruning or TTL cleanup exists.

Global revision CAS and finite explicitly supplied fixture record/operation budgets
apply inside the same transaction as records, heads and once rows. Capacity refuses
new work rather than evicting replay evidence. A lost reply or failure after commit
returns no positive result and is never described as rollback. Read results are
point-in-time `STORED_SOURCE_DATA`, not ACTIVE authority, a renewed validity lease,
native eligibility or a shipping signature. Original expiry numbers remain DATA;
no unqualified Worker timer is used to manufacture currentness or extend a cutoff.
Read comparisons do not independently authenticate caller-selected Core/install IDs.
Matching an older restored journal remains an unresolved live nonrollback boundary.

The packaged Worker always returns no-store 503. `createProductionRegistry` throws
before reading arguments, environment, namespace or journal. Only the isolated
qualification Worker exports/binds the DATA DO. Root Worker imports, HTTP routes,
bindings, migrations and installed production remain unchanged. This source is not
a second live authority store and has no bridge into enrollment, A/B acceptance,
Apple SDKs, APNs or any provider. The original strict same-executor clock requirement
is not relaxed; no positive effect executor is implemented by this increment.

## Free local conformance and packaging

```sh
node_modules/.bin/tsc -p coordinator/worker-do/qualification/tsconfig.json --noEmit
node_modules/.bin/vitest run --config coordinator/worker-do/qualification/vitest.config.mts
node coordinator/worker-do/build-source.mjs "$TMPDIR/worker-do-registry-package"
```

Use explicit scratch on Shared Data locally or runner.temp in CI. The tests use
actual local workerd/SQLite Durable Objects and WebCrypto public-point import. They
include joint rollback after a real SQL trigger fault, concurrent revision winners,
global nonce replay, immutable pins, prior retirement, scoped reads and lost replies.
The source packager verifies every manifest input, actual locked Wrangler schema and
dependency lock, bundles the isolated Worker and validates configuration with the
real installed parser. It never deploys or provisions anything. No old Container or
native-SQLite PASS is transferred to this new package.

Cloudflare documents SQLite-backed Durable Objects on Workers Free; reaching a free
quota rejects further operations rather than establishing unlimited free usage.
See [pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)
and [limits](https://developers.cloudflare.com/durable-objects/platform/limits/).
No account upgrade, remote namespace, runtime assumption or invoice prediction is
made by this source package. Production policy/count/read limits still need admission.

## Remaining real facts

Activation requires the genuine registrar/custodian and accepted public principal
epoch/PoP, independently trusted registry origin and expected Core/install bootstrap,
qualified retirement/restore/read policy, definitive separate Core purpose ACK and
actual registered binding. None is replaced by a fake owner flag, ordinary bearer,
JWK from the same unsigned response or matching hashes. Core positive signing,
API A/B/native enrollment, Apple B-trust/SDK and strict final-clock/provider factories
remain unavailable. Independent source review and source delivery are separate from
resource provisioning, key access, deployment and actual enrollment acceptance.
