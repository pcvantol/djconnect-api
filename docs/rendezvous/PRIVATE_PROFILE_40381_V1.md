# Fixed private40381 preparation

Scope **PREPARED_ONLY_NOT_NATIVE_ADMITTED**. The public Worker remains503 for
rendezvous, its internal handler unmounted and all22 fullservice gates OPEN.
Source/wire implementation.1 /djc-rendezvous/1 and the published40227/28/30
development verifier remain unchanged. This is a local derived profile, not the
unchanged default verifier and not production deployment.

## Exact producer input

Apple PR161 protected source0db4e137964a94ca2798b0efd89f6268db2b3261, reviewed
040cfc30d5499b381a1cb361310fd9bac56a6f3b, contains the independently reviewed
PR160 expiry correction. The five compiled inputs match the protected
[40381 proposal](https://github.com/pcvantol/djconnect-app/blob/0db4e137964a94ca2798b0efd89f6268db2b3261/Tools/qualification/vibecast-native/PROFILE_PROPOSAL_40381.json).
Proposal fileSHA25653ce83e05aede3f7a2e2c66890e2ce9be213aa8a4e023f0743c8c3637e91ad2c.
Signed artifact89 regular files: manifest fileSHA256
166dceca1a2217d69e7510be3182dc64075ff770113d94294e9e867637b51c2a.
This hashes the producer's **raw mapping manifest file**, not the older40380
list's canonical-JSON recipe. Actual file set/hashes and five protected source
hashes were independently verified. Executor strict codesign succeeded; the
security reviewer's restricted context still reported CSSMERR_TP_NOT_TRUSTED,
cause unknown. No truststore/signing changes were made.

App dev.djconnect.ios, Team ZEML4LPXH4, build40381, proposed development.
Existing profileSHA2569243e1b2b3c829a86073ecf61f50e13cb7f0c9ab0630c9597ca3e9fa286629dd.
The full artifact/profile/source hashes are operator provenance; they are not
whole-app attestation by App Attest. Genuine authenticated AppID/environment/
observed-build/flags/category/nonce/certificate/CMS/status/counters remain
strictly verified. An omitted entitlement is not a positive AAGUID proof.
The old40380 artifact is not corrected or reused. Apple's stable40380 attempt
directory and occupied/uncertain markers remain authoritative across upgrades.

## Closed derived source and unchanged default

The host reuses sourceSnapshot: its full hash map includes102 tracked baseline
inputs,32 installed package files, references and host tools with overlap; the
total is not102. All non-node_modules entries are privately copied at the same
relative paths in an owned0700 tree, with0600 regular single-link files. Exactly
one line changes: core BUILDS40227/28/30 becomes singleton40381. Every other copy
remains byte-identical. Verification before compilation and each explicit
command rejects changed/missing/extra files, links and mode drift.

Both enrollment's relative import and the assertion alias resolve to the same
derived core. The compiled graph must contain it once, include both consumers,
exclude the original core and admit only exact staged files plus the original32
pinned installed files and generated driver. Three fixed package entrypoint
aliases resolve cbor/asn1js/pkijs; the existing four product aliases resolve to
staged sources. No opportunistic dependency install or input-selected build,
verifier, provider, URL, clock or namespace exists.

The two fixed entrypoints share host lifecycle/file handling. The default
run-local-native.mjs still selects40227/28/30. The separate fixed40381 entrypoint
uses the derived profile; there is no CLI/environment/request selector.
Original crypto policy identifiers stay unchanged because the genuine engines
validate them; a distinct local revision/receipt labels this derived source.
Source/core/derived-core/graph/bundle and GitHEAD hashes bind each private receipt.

## Preparation is not permission to run

Only after separate exact operator admission, native-owner agreement and device/
private-transfer readiness use the existing private directory procedure from
[local native experiment](LOCAL_NATIVE_EXPERIMENT_V1.md), with the fixed entrypoint:

```sh
node qualification/rendezvous/run-local-native-40381.mjs /private/tmp/your-private-experiment
```

Startup creates no challenge. At most16 explicit commands in15 minutes remain;
the40381 controller additionally admits only four successful same-key requests:
register challenge, register proof, recover-key challenge, recover proof. It
binds returned challenge IDs and exact client_data. Any failed/uncertain request
is terminal for this in-memory experiment. Concurrent attempts, key/ID changes,
submit/delete/transaction routes and further requests reject. No automatic
retry/key generation/reset exists. A new local process is not authorization to
retry or bypass an occupied native marker; the operator must reconcile it.

Original server120s challenge expiry, construction-time native ContinuousClock
and request timestamp semantics remain. Never rewrite requested_at, renew TTL,
hash base64/ASCII nonce text, reuse stale capture or reattest an old diagnostic
key. Actual device installation/build/signature/foreground/unlock/SDK support,
private protected-subtree transfer and one new key setup require their separate
specific authorization and joint readiness before challenge issuance. No SDK
call, native key/assertion/capture, installation, trust/profile/account change,
tunnel or Cloudflare mutation is performed by this preparation. A receipt URL is
bookkeeping, not machine-verifiable operator authority.

One recovery experiment proves neither submit/JWE/consume nor paired HA-owner
authority, separate Core screen admission, physical TV or fullchain acceptance.
Public service activation, edge/CORS/TLS/operations and production deployment
remain separate gates. Five product languages are unchanged; no new user flow.

## Qualification and rollback

Run node --test qualification/rendezvous/private-profile-40381.check.mjs on a
clean committed checkout. Cases cover exact derivation, hostile stage/graph,
bounded controller, cryptographically signed P256 **software assertion fixtures**
distinguishing old/new builds plus crypto denials, and actual private workerd
default-genuine rejection/zero key rows/original120s operation. No Apple/CMS/
provider positive is fabricated. CI also retains the original ten host/native
negative groups, nine receiver guards/seven Node checks and four browser cases.

The runtime uses the existing fixed common-certificate CRL/OCSP-only outbound
guard, independent interception controls, isolated nonpersistent local DO storage, loopback bridge,
disabled inspector, source drift checks and cleanup. No secret or native input
is logged; diagnostics are fixed codes and public provenance only. OS/SDK temporary
behavior is not an exclusively-RAM storage or physical-erasure guarantee. Private
proof files are retained; cleanup is not physical erasure. Rollback: stop this
owned local process and retain its evidence; use the original default tool for
separately admitted default-profile work. No product migration/deployment or
native marker deletion is involved. Protected delivery and separate exact
postmerge evidence review are required before this source slice is finalized.
