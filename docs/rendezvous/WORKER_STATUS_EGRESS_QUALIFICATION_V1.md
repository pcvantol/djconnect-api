# Local workerd fixed status egress qualification v1

Same API94 writer, profile0.4.0-draft/djc-rendezvous/1 **NOT_FROZEN**.
**Scoped isolated adapter: no public enrollment or runtime GO.**

[Client](../../qualification/rendezvous/receipt-status-client.mjs) and
[tests](../../qualification/rendezvous/receipt-status-client.check.mjs):
[101/101 local workerd cases PASS](workerd-status-egress-observations-v1.json),
[35/35 public-only cases PASS](workerd-status-egress-public-observations-v1.json).
The101 include all68 previous status cases plus33 adapter cases. The35 public
cases omit actual Apple response/adapter-positive cases explicitly. Installed
versions, exact current source/corpus hashes and case names bind these reports.
Earlier status-only68/34 reports bind commit e5d3c8d and remain historical evidence.

## Fixed request preparation and network budget

Authenticate the bounded common certificate context against pinned Apple RootG3
and measured purpose/signature/validity rules **before** emitting a CertID. This
is not the complete preceding CMS profile. A private device attestation leaf or
fake root fails preparation. Use standard PKIJS OCSPRequest SHA256 CertID, one
unsigned request, no nonce/extensions/device proof, bounded4KiB request.
Only three fixed roles/URLs: signer OCSP at Apple's ocsp03-aaica5g101, intermediate
OCSP at ocsp03-applerootcag3, or rootG3 CRL at applerootcag3.crl. Never dereference
a client URL, arbitrary AIA or HA destination. Fixed HTTP is solely authenticated
certificate-status transport, never an exception to HTTPS-only HA destinations.

Fetch uses manual redirects, omitted credentials, no referrer, no HTTP cache;
only expected Accept/content-type headers. Require200, no redirected response,
expected OCSP/CRL MIME. Reject empty bodies, invalid/oversized declared length,
and actual streamed decoded bytes above64KiB. An absolute4s fetch/body/verification
deadline races the operation, requests abort and cancels the reader, including
stalled response headers/body. A late result cannot promote cache state.
These are chosen application budgets, not provider limits or cadence claims.

One tracked active operation per fixed role is independent of tuple replacement;
same exact tuple shares the operation and a different concurrent tuple is denied.
A verified cache is replaced only after the new tuple's full status verification.
Role-local attempts start at least2s apart, preserved across tuple switches;
cache reads/denials do not renew this bound or status expiry. Exact-tuple valid
cache remains usable during outage; missing/expired/bad status fails closed with
one generic status_unavailable result and no raw errors/logging or automatic retry.
This instance-local limit is not distributed rate limiting or a production cache.
Context-preparation crypto precedes this concurrency budget; general CPU/admission
controls remain open. An aborted task may finish late without authority; actual
provider cancellation/global resource bounds still require qualification.

## Independent review and executed fault cases

Independent supplied-code review found oneP2: replacing a tuple-indexed slot could
start additional operations while the former one remained active. Fixed separate
operation/cache maps, stable per-role authority and identity checks on promotion/
cleanup. Failed replacement retains old verified cache; a timed-out old operation
cannot clear or promote on behalf of a newer operation. Corrected scoped egress
GO; no remaining supplied-scopeP1/P2. This is supplied-code/results review, not
reviewer source access, independent execution or complete runtime approval.

Tests exercise each actual common certificate role's fixed URL/method/options,
standard exact CertID/no signature/extensions, outage-valid cache and expiry,
eight concurrent calls; outage,302,wrong MIME,empty,declared/streamed oversize,
tamper; real4s header/body stalls with abort/reader cancellation; invalid profile
before fetch; A/B/A tuple switching, failed replacement preserving cache and a
late timed-out response during the next operation. Adapter tests use injected
fetch with previously captured actual signed responses: **not a fresh live
network run of this adapter**, provider deployment or fresh enrollment.

Three concurrency fault tests additionally substitute only the prerequisite
context preparer to admit a second test tuple B. B is not a second real Apple
certificate and never gets cryptographic GO; this seam isolates orchestration
behavior. Default real preparation and all68 cryptographic status cases remain
separately exercised. Fetch/preparer injections exist only in this excluded
qualification module; production adoption must remove/close test seams.
Earlier98-case runs preceded the P2 correction; final101 includes its regressions.

## Reproduce and remaining gates

Use the same `run_status_workerd.mjs` command and optional private input directory
as [status qualification](WORKER_STATUS_QUALIFICATION_V1.md). It now executes both
status and adapter suites. No installation, private upload, new capture/key,
credential/fraud API, public endpoint, production binding or deployment. Existing
private-derived-evidence deadline2026-11-16 and0700/0600 output rules remain.

Full original-challenge/AppAttest/CMS/status/operator-policy/storage/action
composition and atomic replay/recovery review remain required. Production cache,
status outage integration, cleanup/key operations and provider propagation need
separate proof. Native JWE/action vectors, joint contract freeze and actual
HA/iPhone/TV chain remain separate gates. No owner/display/Session permission
or full runtime/deployment approval follows from this adapter evidence.
