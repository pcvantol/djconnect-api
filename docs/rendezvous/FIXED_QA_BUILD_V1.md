# Fixed isolated rendezvous QA build

Selected source scope: build and qualify the fixed QA-only Worker for service
`djconnect-api-vibecast-qa`, API origin
`https://api-vibecast-qa.djconnect.dev`, browser origin
`https://qa.vibecast.tv`. These proposed hostnames have no availability,
ownership, DNS, certificate or operational admission claim.

Run `node scripts/qualify_rendezvous_qa_build.mjs` without arguments. It builds
an isolated package in a private temporary directory, executes only Wrangler
`deploy --dry-run`, checks the exact copied Worker bytes, runs actual local
workerd qualification, and emits a QA-only archive and integrity receipt.
The dedicated read-only CI workflow retains its exact archive for14 days.
It has no secrets, write permissions, deploy job or workflow dispatch.

## Fixed graph and consumer fixture

Production source, configuration, aliases, protocol version and main entry are
unchanged. A separate QA entry exports the same five genuine coordinators and
their existing RPC allowlists, without ordinary API/D1/APNs routes or bindings.
A fixed five-file source derivative validates original SHA256 and exact literal
counts before changing only the selected service/browser origins:
composition exact URL; ingress exact URL/CORS; assertion client-data origin;
transaction QR service_origin; and four service/one browser constants in the
wire schema. Unselected files, changed hashes/counts or extra CLI selectors
fail. No runtime host/profile/verifier selector, global source replacement,
window/URL/query injection or product CSP change is introduced.

The archive includes `qa-origin-fixture.json` and the exact derived
`wire-request-schemas-qa.json`, bound to source SHA, tuple, Worker hash and
schema hash. This is the concrete fixture for receiver/Apple source review;
production/QA origin constants are not accepted interchangeably. Receiver has
given design-only GO; Core reports no B-origin allowlist change is required
provided independent selected destination/owner/context/entry/Profile/Session/
epoch/explicit-consent fences remain. Apple current signed profile and parser/
service disposition and joint frozen-source review remain required. These
source dispositions confer no live/native/full-chain acceptance.

## Deliberately closed current artifact

The QA source guard is literally false and the profile records current Apple
profile and operational admission as null. A new reviewed source increment
must bind the actual producer identities and bounded admission before any
activation. Setting env values, changing request headers/body or choosing a
different host cannot enable this artifact. This is executable build/config
wiring and a closed Worker, not a completed active/native service.

The QA Worker serves only its fixed host. Its exact health URL reports source
SHA and activation_allowedfalse. All rendezvous paths return redacted503
before reading request body, runtime configuration, secrets or DO bindings;
CORS is exposed only to the exact QA browser origin. Wrong service hosts and
ordinary API routes return404. Closed OPTIONS returns503 and grants no methods.
No nonce, key, challenge, transaction, network or provider effect is admitted.

The fixed package config has no routes, workers.dev/previews, D1, APNs or policy
secrets; it names the five proposed QA SQLite bindings and a separate proposed
QA migration tag. These are offline configuration bytes, not provisioned
namespaces or migration-collision proof. Production promotion requires the
existing ordinary `API release artifact` workflow provenance and release TAR
layout; this separate QA workflow/archive supplies neither.

## Actual local qualification and limits

The implemented local workerd check covers50 transport cases, exact source
health binding,100 forbidden RPC calls/reads and11 source/hash/count guards.
It checks exact QA versus production/lookalike/no-Origin behavior, no body or
runtime-env read while closed, no Retry-After/encoding/credential CORS, all11
routes, OPTIONS, wrong hosts and ordinary API route rejection. An explicit
egress control first proves the test boundary intercepts outbound attempts;
the actual qualification then observes zero egress. Root strict types pass.

The initial sandbox run failed loopbackEPERM before workerd qualification.
The subsequent permitted loopback run really passed; EPERM is not a PASS.
Repeated builds of the same source yielded byte-equal Workers; TAR bytes can
differ through file timestamps and are independently hashed, not claimed
reproducible. Committed exact-candidate and CI receipts must retain their own
source SHA and dirty flag, independently from the initial local WIP results.

Source reviews, protected delivery, own-main ordinary and QA artifact readbacks
and separate Finalization remain required. The existing product/shared/native
proofs retain their execution identities; no unchanged1558/16 suite is rerun
locally or relabelled. No real TLS/CORS/CF ingress, current Apple attestation,
selected HA external HTTPS/B, once-consume, physical TV or end-user success is
claimed. All22 full-service gates remain OPEN; automation PAUSED. DNS,
provisioning/configuration/deployment/device/key/nonce/SDK/capture/private
transfer and HA effects require separate specific authority and are not run.
