# Sharp maintenance source Finalization

Source [PR #121](https://github.com/pcvantol/djconnect-api/pull/121) was normally
squash-merged to protected main
`ae48830c385f89ee3c7b5970b9800f96f9d26f52`.
Its tree `507e1d537e230657a356d3d8ce1a8ea1994e5f9d` equals reviewed candidate
`df26eee0237cc7218da6100f844c23b84b578ed6`. The actual CI merge commit
`320fe55ec0775ecf6c09d7f51787dee0c29de3d5` has that same tree and the exact
protected baseline/candidate parents, independently verified through GitHub API.

Fresh independent security and UX/evidence reviews give scoped GO without
findings: [source reviews](https://github.com/pcvantol/djconnect-api/pull/121#issuecomment-6315830950).
Agent review does not confer human approval or deployment acceptance.
Required Owner Authorization passed as not required for LOW/NORMAL risk;
normal protected checks were used, with no bypass or prior-SHA approval reuse.

## Executed evidence

Local qualification passed 128 product checks, including 100 forbidden RPC
refusals, 78 API tests, 49 composition tests with strict types, 34 preparation
tests, root types and the root derivation guard. The exact committed candidate
also passed all 16 default/private-profile negative preparation groups in
128.086 seconds, including the original 120-second nonce; zero failures,
skips, installed keys or outbound attempts.
[Actual negative-run receipt](https://github.com/pcvantol/djconnect-api/pull/121#issuecomment-6315850503).
These are preparation negatives, not a successful native/device experiment.

The historical 1543 shared-test proof remains at its original execution identity;
all 66 shared input bytes are unchanged. New source-main CI independently
executes affected workerd cases and actual private receiver/browser/root checks.
The source-PR job log records 1337 workerd cases, distinct from local historical
shared evidence.

All seven required source-main workflows succeeded, with exact IDs in the
[machine Finalization record](sharp-0355-finalization-v1.json). Two additional
conditional artifact/formal workflow_run events were skipped and are not counted
as successful delivery runs. The initial local run collector refused that mixed
set; selecting the exact seven verified delivery IDs resolves the bookkeeping
without relaxing any check.

Actual downloaded source-main artifact `12345173157` contains a release TAR
with SHA-256
`35e301749179f2c423adfaf002a94d4fb5c4048902db545b6229273eb75813b9`.
Its 1,259,120-byte Worker has SHA-256
`24212b24c3cb45a4a39b5e6ee2c97f01e8de5a3f9fcf1f2722db65e911f95159`.
All provider ZIP digests and extracted payload digests match. Archived
package.json, package-lock.json, wrangler.jsonc and all three licence sidecars
are byte-equal to protected source. The patched package files are therefore
actually present in the qualified archive.

Worker bytes equal the previous qualified main artifact after replacing only
the release SHA. Formal evidence is QUALIFIED with zero findings and digest
`f42c584ab249e169c31cd4baf899920ed9f7b6955b7b3e35533e23996be258a0`.
The actual durable asset `662439392` has SHA-256
`b5aee337b2a953aef8ac42f26cc54778228d96bf3c31a6b08046e8758a3f89fe`.
Its provider digest, canonical integrity, main binding and formal digest agree.
This is downloaded evidence, not inferred qualification from a green icon.

## Alert and remaining acceptance

The postmerge GitHub readback still reports alert 39 OPEN with no fixed_at.
The GitHub SBOM also still lists sharp 0.35.4, while the protected lock and
actual archive contain 0.35.5. This discrepancy is recorded as observed; no
automatic reconciliation timing or alert closure is asserted, and no alert was
dismissed manually. Other Vite alerts remain outside this bounded change.

See [maintenance scope](SHARP_0355_MAINTENANCE_V1.md) for the actual macOS arm64
sharp/librsvg probe and its Linux-platform limit. All 22 full-service gates
remain OPEN/null/activationfalse; public rendezvous stays compiled OFF/503,
QR remains off, and the night automation stays PAUSED. Complete provider/error
taxonomy, genuine native, selected external HTTPS/HA/B-consent, physical TV and
operational acceptance remain separate. No deployment or provider/service
mutation is performed or granted.

This document and machine record are a separate docs-only Finalization
candidate until their own reviews, protected merge, exact-main CI and actual
artifact/formal/durable readbacks complete. A final API #90 receipt must bind
that final main. Source delivery and its Finalization close only this sharp
maintenance increment, not the entire rendezvous assignment.
