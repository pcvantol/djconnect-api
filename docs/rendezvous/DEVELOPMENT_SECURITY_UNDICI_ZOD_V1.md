# Development dependency security maintenance

The exact root overrides update undici7.29.1 to7.30.1 and Zod4.4.3 to4.6.6.
GitHub Dependabot alert51 identifies GHSA-xjj6-f33q-929c in transitive development
undici. The full npm audit then exposed GHSA-mrhx-c7xc-m3w5 in the worker test
pool's Zod4.4.3; this second within-major update addresses that actual finding.
The lock graph changes only node_modules/undici and node_modules/zod. No blanket
npm update, install scripts, new dependency family or runtime major is used.

Official references:

- https://github.com/nodejs/undici/security/advisories/GHSA-xjj6-f33q-929c
- https://github.com/advisories/GHSA-mrhx-c7xc-m3w5
- https://registry.npmjs.org/undici/7.30.1
- https://registry.npmjs.org/zod/4.6.6

The official archive integrity and installed member bytes were checked:210
undici members and840 Zod members. Both existing Miniflare paths resolve the
single patched undici; the worker test pool resolves patched Zod. The complete
post-update npm audit reports zero known vulnerabilities. That is a bounded
registry observation, not proof that every tool is vulnerability-free.

A local, isolated two-process counterproof exercises the undici advisory using
only a loopback server: more than five content codings, a promised body and an
early close. The official old version catches fetch rejection but then exits1
on the unhandled response stream error. The patched installed version catches
rejection, survives and exits0. No external server, provider or production
Worker participates. No deliberate host-memory exhaustion is attempted for Zod.

Actual final-graph qualification includes238 API tests and strict root types,
49 composition cases and strict composition types,128 compiled-product checks,
100 forbidden private RPC denials and zero egress. New module-v4 and product-v4
observations bind the new package/lock hashes. The source-delta-v5 closes the
same immutable106-input baseline through27 explicit deltas to117 tracked inputs.
All50 installed Worker-runtime inputs are byte-identical to the preceding
qualified graph. Shared-v4 crypto/state evidence is retained byte-identically
with its original historical scope; no unchanged crypto suite is claimed as a
new run. Earlier product/module/delta and separate Finalization records remain
unchanged. The local runtime helper points to the actual new product evidence.
Existing preparation and exact committed closed-runtime qualification are
separate terminal delivery gates; their completed results belong to the exact
review and subsequent separate Finalization records.

Application source, certificate predicates, configuration, migrations, runtime
library graph and original runtime license notices are unchanged. No Worker
runtime undici/Zod import is introduced. This does not dismiss the development
risk as unreachable: Wrangler/Miniflare/test tools execute on the development
host and their patched graph is independently tested.

Normal independent exact review, current candidate checks, applicable Owner
Authorization, protected source merge, original own-main artifact/formal/durable
qualification and a separate Finalization remain required. Alert51 is not
claimed closed until GitHub actually reads the protected corrected graph.
Public dispatch stays compiled off, Activity profiles stay empty and all22
full-service rendezvous gates stay OPEN. No production deployment, real
registration, issuer/key/provider/device action or operative clock admission is
performed or granted by this maintenance.
