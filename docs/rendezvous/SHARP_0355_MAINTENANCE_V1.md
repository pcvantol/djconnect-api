# Patched sharp development dependency

This bounded maintenance increment addresses Dependabot alert39,
[GHSA-wq5f-xc86-pv6w](https://github.com/lovell/sharp/security/advisories/GHSA-wq5f-xc86-pv6w).
It is separate from the delivered enrollment-callback and assertion-crypto fixes.
The full rendezvous assignment remains OPEN.

The root override changes sharp0.35.4 to exact0.35.5, and the existing
allowScripts entry follows that exact version. The upstream advisory identifies
a librsvg memory vulnerability under certain glibc Linux runtime conditions;
the first patched sharp version is0.35.5, providing librsvg2.63.2.
This is a transitive development dependency of both Miniflare toolchains,
not a Worker application dependency. Miniflare has an image-transform path,
so an absent application import is not a blanket unreachability argument.

## Exact dependency change

Only27 lock package records change: sharp plus its26 platform/bundled-libvips
packages. Sharp binaries change0.35.4→0.35.5; bundled-libvips packages
change1.3.3→1.3.4. All unrelated lock entries are byte-equivalent as parsed
JSON, including Wrangler4.151.0, both Miniflare versions, workerd, the testpool
and all application dependencies. The sharp tarball integrity equals the
previously fetched0.35.5 registry metadata. No install lifecycle scripts were
run locally: lock generation and clean installation used --ignore-scripts.

Actual macOS arm64 loading reports sharp0.35.5, librsvg2.63.2 and libvips8.18.7.
A fixed local4×4 SVG was decoded, resized to2×2 and encoded as a95-byte PNG.
Both installed Miniflare dependency paths resolve to the same patched sharp.
This is a real local binary check, not a glibc Linux exploit reproduction or
a claim about every platform binary.

## Actual qualification and source binding

-128 actual product-build checks and100 forbidden private RPC refusals pass;
  no egress or activation. The compiled Worker bytes are exactly equal to the
  previous protected assertion-crypto build.
-78 API tests and49 composition tests pass with the changed clean installation.
  Composition strict types are included.
-Existing shared1543-case evidence is retained with its original execution
  identity. All66 shared source inputs are unchanged; this maintenance does
  not claim another execution of that unchanged software qualification.
-Immutable protected baseline: ec8029dbe7e4b0f4405253a3bf265d505303866b.
  A closed two-input delta covers only package.json and package-lock.json.
  Fresh85-input product and19-input composition proofs agree with that map;
  all32 installed Worker-bundle dependency hashes are unchanged.
-Preparation validates106 tracked inputs,32 explicitly pinned installed inputs
  and13 references. It now requires the third, exact fresh composition proof
  because that proof also names the changed package inputs. Missing, forged,
  foreign or conflicting proof inputs still fail closed.
-Local preparation runtime reads the new product proof. No protocol, predicate,
  application source, state, deadline, budget, binding, configuration or workflow
  changes are included.

The original preparation rejected the package changes before rebinding.
Attempting to combine the new product map with the historical composition map
also failed on the package-input conflict; the fresh49-case composition proof
resolves that conflict without rewriting historical evidence.
An initial host verification used the stale default GitHub root and reported
drift. Repeating the read-only check with the actual Shared Data root returned
MATCH; no host repair occurred.

Machine receipts: [maintenance](sharp-0355-maintenance-observations-v1.json),
[build](sharp-0355-build-observations-v1.json),
[composition](sharp-0355-composition-observations-v1.json) and
[closed source delta](sharp-0355-source-delta-v1.json).
Historical proof files remain unchanged.

## Delivery and acceptance boundary

Independent exact-candidate security and UX/evidence reviews, normal protected
CI/merge, actual own-main artifact/formal/durable verification and separate
Finalization are required. Local qualification alone does not close alert39 on
GitHub; its actual postmerge state must be read back.

The other three open Vite dependency alerts are outside this sharp-only change.
No production rollout or service activation is granted. All22 full-service
gates remain OPEN/null/activationfalse; public rendezvous stays compiled OFF/503,
QR stays off, and the expired night automation remains PAUSED. Genuine native,
selected external HTTPS/HA/B-consent, physical TV, operations and complete
provider/error-taxonomy acceptance remain separate. No translations or
end-user flow are changed in any of en/nl/de/fr/es.
