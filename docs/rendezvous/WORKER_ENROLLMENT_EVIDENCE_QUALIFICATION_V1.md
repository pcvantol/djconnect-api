# Local composed enrollment evidence v1

Profile0.4.0-draft/djc-rendezvous/1 **NOT_FROZEN / NO_ATOMIC_REGISTRATION /
NO_RUNTIME_GO**, same API94 writer. This composes checks; it does not enroll keys.

[Implementation](../../qualification/rendezvous/enrollment-evidence-candidate.mjs),
[typed private contract](../../qualification/rendezvous/enrollment-evidence-candidate.d.mts),
[executed tests](../../qualification/rendezvous/enrollment-evidence.check.mjs):
[95/95 local workerd](workerd-enrollment-evidence-observations-v1.json),
[87/87 public-only](workerd-enrollment-evidence-public-observations-v1.json) PASS.
The type check compiles a declaration consumer, **not the JavaScript implementation**.
Positive orchestration cases explicitly replace crypto/status components with
software stubs. No fresh genuine composed-positive, native nonce32 enrollment,
key installation, public endpoint or live-chain success is claimed.

## Composition and owned inputs

The default factory imports the existing attestation core, fresh CMS verifier and
CommonStatusClient. Pinned root bytes come from a trusted internal QA alias;
the runner independently checks both root SHA256s, and real component verifiers
also enforce their existing pins. No caller-selected app, policy, root, clock,
status string, URL or weaker-verification mode. Current support remains the
reviewed development app/profile/build set, not production iOS qualification.

The trusted readState callback supplies a closed server-owned policy and original
register challenge: id, canonical Apple key ID, action, creation/deadline and
exact saved bytes. The request supplies only challengeId/keyId/attestation bytes.
The default requires the exact existing **32 decoded server nonce bytes** as
core input, per wire profile159; the core hashes those bytes. It never signs a
new JSON envelope, hashes a base64 string or changes register into register-key.
Normal challenge issuance/ownership, one-use atomic consumption, correct per-key
routing and global ingress limits remain separate integration requirements.
This callback is a trusted internal boundary, not a client/RPC input.

Copy proof, saved bytes, roots and authenticated component data before awaits.
Use Uint8Array.from even for Buffer: Buffer.slice is a view. Validate canonical
IDs, closed state/request shapes and bounded32KiB proof/2KiB fixture bytes before
crypto. Original challenge is at most120s; policy must be currently enabled with
the same ID/revision/deadline. Recheck these snapshots after every await and at
return. One active verify call per instance denies overlapping work; no aggregate
allocation/CPU/egress or rate-limit qualification is implied.

Order: real attestation path/app/key/nonce -> fresh receipt CMS/path/fields ->
authenticated issuer CRL -> authenticated signer OCSP. The existing core now
returns its already-validated leaf and minimum path notAfter; CMS returns its
already-validated common signer/intermediate/root and minimum path notAfter.
No signature/profile/field predicate or trust exception was relaxed, and no second
receipt parser is introduced in the wrapper. Core93 and CMS83 regressions pass
on these exact metadata changes:
[core](enrollment-core-regression-observations-v1.json),
[receipt](enrollment-receipt-regression-observations-v1.json).

Only the authenticated **common CMS certificates** reach the fixed status client;
never device leaf, receipt, nonce, key ID, HA destination or credentials. The
unchanged client enforces its reviewed role/tuple, fixed URL, signed response,
time/cache/size/timeout controls. The wrapper additionally checks the expected
CRL/OCSP scope and original checkedAt/cacheUntil/signed deadlines. After signer
status, recheck earlier issuer status, both path expiries, receipt freshness and
original policy/challenge. Copy metadata so a retained component object cannot
renew an already-made decision. No stale-while-revalidate or fail-open outage.
The App Attest chain retains the explicitly reviewed offline pinned mode; this
is not live revocation proof for the device attestation leaf.

## Private evidence, never a reusable admission proof

Success returns only a private evidence object: scope, original key/challenge and
creation/deadline, current policy revision, verifiedAt/validUntil, public point,
original initial receipt and receipt creation time. validUntil is capped by both
certificate paths, both authenticated status deadlines, original challenge/policy,
receipt expiry and its existing inclusive5min freshness rule. Because UTC times
are integer milliseconds, freshness through created+300000 maps to a half-open
commit deadline created+300001. No key lifetime is created or extended here.

The initial receipt remains sensitive. Do not log, return it publicly or store
it before the later encrypted atomic registration. Evidence is an ordinary
internal object, not a signed bearer/capability or permission to create a key.
The registration coordinator must recheck its actual saved challenge, exact
request, active policy, current time and evidence deadline inside its final
SQLite transaction; receipt encryption/key state/challenge consumption must
commit together. That stage and hardened private RPC are **not implemented or
approved by this qualifier**. No HA-owner, installation or display rights result.

## Actual tests and explicit diagnostic path

The87 public cases cover positive **stub orchestration** plus real default input
rejection: fixed order/exact bytes/common tuples; closed shape/size/key/action;
policy/challenge mutation after core/digest/CMS/CRL/OCSP; unavailable, mis-scoped,
future/stale/expired status; path/receipt expiry during later work; cache/receipt
alias mutation; immutable deadlines; concurrency/error recovery; Uint8Array and
Buffer ownership. The stub constructor has a distinct success scope and is never
selected by the default factory or a request flag. It allows bounded opaque
1..2048-byte test inputs solely to replay existing diagnostics.

Eight additional old genuine-fixture tests: two authenticated core leaf/path
metadata checks; two CMS common-tuple/deadline plus stale-freshness rejections;
two default nonce32-adapter rejections of old157/162-byte diagnostic input shapes;
and two real core->freshCMS stale-denials through the explicit fixture constructor,
with no status call/fetch. These deliberately supplied old input bytes do not
prove normal server challenge issuance, fresh enrollment or actual nonce32 wire.
No borrowed assertion, new device capture, App Attest key, credential or refresh
request is used. Existing diagnostic custody/deletion-review deadline2026-11-16
is retained, without an automatic/hardware erasure claim.

First90-case run had88PASS/2FAIL: Buffer versus Uint8Array test comparison,
not a signature failure. Compare explicit byte arrays; also replace view-style
Buffer copies in the wrapper with owned Uint8Array.from and add a Buffer ownership
regression. Intermediate91 then final95/87 runs pass. Failed artifacts remain
private and are not relabeled PASS. All40 existing API regressions and root types
pass after the metadata extension; product source/config/bindings remain unchanged.

Independent design and implementation security reviews: scoped GO/no P1/P2
on complete supplied wrapper/tests/runner/declaration and two componentdiffs.
A separate reviewer read those files and the new qualification/handoff/wire docs:
scoped UX/privacy GO/no P1/P2. Security reviewer had no independent Git-readback;
neither reviewer reran tests or validated fresh runtime/storage behavior. These
are scoped composition/document reviews, not full enrollment or runtime approval.

## Reproduce and remaining gates

```sh
node qualification/rendezvous/run_enrollment_workerd.mjs /private/tmp/isolated-pki-deps /private/tmp/new-enrollment-results
```

Optional third argument is the already-authorized private diagnostic root, not a
request for fresh device material. Runner uses existing cbor10.0.12/PKIJS3.4.1/
ASN1js3.1.0 and repository test/compiler artifacts, installs/deploys nothing and
prints fixed labels. New output directory0700, runner-owned files0600; spawned
diagnostics remain inside that directory. Public summaries contain source/root
hashes, versions and fixed test names only, no private receipt/key/nonce hashes.
Temporary Worker answers503/no-store, with no DO binding or product configuration.

Still open: atomic encrypted registration/challenge consumption/recovery integration,
hardened private RPC and global admission, transaction winner/consume/cancel,
actual supported signed-iOS nonce/action integration, fresh genuine composed
positive, full independent security review/jointfreeze, real HA/display/physical
chain, protected product delivery, separate Finalization and authorized deployment.
Receiver's unchanged API-generator crossrun is already delivered; do not repeat it.

Primary references: [Apple validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server),
[Cloudflare limits](https://developers.cloudflare.com/workers/platform/limits/).
No application test bound here is asserted to be a measured provider quota.
