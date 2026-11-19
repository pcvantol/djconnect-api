# Prepared local native experiment

Scope: `PREPARED_LOCAL_EXPERIMENT_NOT_REACHABLE_NATIVE_TARGET`. This API-owned
operator tool composes the actual five private product Durable Objects and
ordinary internal HTTP module in one local workerd process. The default genuine
App Attest verifier and fixed Apple common-certificate status client are unchanged.
There is no software verifier, injected grant, alternate crypto, new public API,
Cloudflare mutation, tunnel, native installation or consumer source change.
The product Worker still returns503 for rendezvous. Source/wire release
`djc-rendezvous/1-implementation.1` / `djc-rendezvous/1` is unchanged.

## Required owner decisions before a genuine attempt

The existing Apple owner must select an exact signed appID/build/environment and
the private byte-transfer mechanism. Current diagnostic source at Apple main
`8d2455f7ab0864850332d989ba83a9833cc9e423` reads bundled `[String:String]`
challenges as UTF8. That cannot ingest this server's decoded32-byte nonce or exact
action clientData. Its current40371 build also differs from the fixed API development
allowlist40227/40228/40230 (`ZEML4LPXH4.dev.djconnect.ios`, development only).
Do not relabel builds, widen policy, change a nonce to base64/ASCII text, re-use an
old attestation, or repeatedly generate keys to overcome a failed attempt.
The existing Apple owner needs a targeted rawData adapter and an explicit profile
choice. This preparation does not require another writer or reopening old ACKs.

The file bridge is an API-side local experiment, **not** a reachable iPhone HTTP
target. It proves no scanner integration, service-origin TLS, direct Cloudflare
metadata, native FIFO transport, HA owner authority or physical TV behavior.
Synthetic cf/IP/canonical-origin values are fixtures. Any later network target,
profile extension or deployment needs its own exact review and authorization.

## Operator procedure

Use the locked dependencies and a clean source checkout. Keep all native evidence
outside Git and cloud-synced/public folders. Prepare a new existing canonical
directory owned by the current user with mode0700, for example beneath
`/private/tmp`; it must not be a symlink or inside this repository. Never put
key handles, proofs, nonces, URLs or tokens on the command line or in logs.

Start once with the directory path as the only argument:

```sh
node qualification/rendezvous/run-local-native.mjs /private/tmp/your-private-experiment
```

Startup reserves `experiment-started.json` exclusively. Reusing that directory
fails; a new process has new isolated DO state and secrets. `process` on stdin
executes exactly one prepared request; `stop` or EOF disposes the runtime and
removes only its own build scratch. Interrupt/termination also requests cleanup.
No challenge is issued at startup. Do not issue one until the Apple owner is
ready. No watcher, timer automation, retry, nonce refresh or native key generation
is started. At most16 explicit requests are admitted within15 minutes, with a
real wall-clock policy deadline. An idle process does not extend any120-second
operation and must be stopped by the operator. A crash cannot guarantee cleanup;
private operator inputs/outputs are retained, and secure physical erasure is not
claimed.

Write private `request.json` mode0600 (one regular owned inode, no hardlink or
symlink, at most102400 bytes). It is **canonical compact JSON without a newline**,
with exactly these keys in this order:

```json
{"route":"/attestation/challenge","body_base64url":"<unpadded canonical base64url of exact wire JSON bytes>"}
```

The placeholder is descriptive, not executable input. The body is decoded and
forwarded byte-for-byte, including any invalid/duplicate-key JSON that the actual
ingress must reject. It is never parsed and reserialized by the bridge. Supported
routes are the existing eleven: `/create`, `/poll`, `/consume`, `/cancel`,
`/inspect`, `/attestation/challenge`, `/attestation/register`, `/submit-challenge`,
`/submit`, `/attestation/delete`, `/attestation/recover`. MethodPOST, identity and
Origin fixtures are fixed; there is no operator-selected host, header, namespace,
RPC, clock, verifier or provider. Existing wire schemas and limits still apply.

For initial enrollment the exact wire body is the version/keyID/action-register
request from the released contract. On explicit `process`, the tool writes
exclusive0600 `NN-response.json` with the actual wire bytes. A successful challenge
also writes `NN-nonce.bin`, exactly the32 decoded server bytes. Action challenges
add `NN-client-data.bin`, exact decoded canonical action bytes. The response retains
the original challengeID/expiry. Hash the relevant **binary bytes once** using
the native SDK as specified by the released contract; do not sign their printed
encoding. Keep the same process alive for registration and subsequent requests.

Prepare the actual registration wire request privately with that exact keyID,
challengeID and attestation; issue one explicit next `process`. A malformed proof
returns the real401 and does not install a key. A provider failure remains finite
and fail-closed. Never infer enrollment from file creation, a challenge200 or a
negative test. Only an actually verified201 plus counter0/operation/receipt evidence
can qualify initial enrollment. Original120-second expiry is never extended.
Following expiry/restart, do not automatically attempt another key or challenge.
Record the bounded failure and coordinate the next explicit experiment.

## Local security and privacy

Before startup and each request, the tool verifies the existing102 tracked
preparation inputs/references and the32 installed dependency bytes deliberately
excluded from Gitblob validation, plus its four tool files and currentHEAD.
Git readback strips all inherited `GIT_*` overrides and disables lazy fetch,
prompts, optional locks and replacement objects, matching the offline validator.
The build import graph must remain within those pinned inputs and its own generated
driver. All existing22 deployment gates remainOPEN/null/false. No replacement
deployment manifest or authorization is produced.

Private input validation uses `O_NOFOLLOW|O_NONBLOCK` and fstat ownership, regular
file, single link, exact0600, size and stable metadata checks on the opened file.
Directory ownership/mode/inode/canonical path are rechecked. Outputs use exclusive
creation and never overwrite. As with other local developer tools, a compromised
same-user process is outside this boundary; this is not hostile multi-user hosting.

The SDK listener binds127.0.0.1; the inspector is disabled. A fresh RAM-only bridge
capability is checked before route/body/DO processing, including unauthenticated
actual loopback probes. HMAC/receipt/bridge secrets are random, not written in
the generated config, wire receipts or command line. DO persistence is disabled;
private scratch is cleaned on normal disposal. OS/SDK temporary behavior is not a
physical-erasure or exclusively-RAM storage guarantee.

Actual workerd outboundService applies default-deny. The only permitted tuples
are GET `http://crl.apple.com/applerootcag3.crl` accepting `application/pkix-crl`,
and POST `http://ocsp.apple.com/ocsp03-applerootcag3` or
`http://ocsp.apple.com/ocsp03-aaica5g101` accepting `application/ocsp-response`
with `application/ocsp-request`. No cookie/auth/header expansion, redirects,
arbitrary URL, HA access or fallback; request4096-byte/response65536-byte and4s
bounds apply. The existing genuine client validates common certificate roles,
signatures and freshness; these HTTP status URLs do not establish a general TLS
claim. A separate fixed denied-egress control verifies real interception without
fake-good status responses or provider requests. Invalid native proofs produce
zero actual provider calls in qualification.

`NN-receipt.json` contains source/tool/dependency hashes, sourceHEAD, local bundle
hash, fixed route/status and timings. It contains no raw IP, key handle, nonce,
attestation, assertion, receipt, capability or HA destination. Raw protocol and
nonce files remain private and must never be pasted into GitHub. All console
results are fixed scope/status/sequence messages or a finite generic failure.

## Verification and remaining acceptance

Run `node --test qualification/rendezvous/local-native.check.mjs`. Ten host/local
integration groups cover descriptor/mode/link/FIFO/size/traversal/replaced-directory
guards, canonical byte preservation, source fingerprint drift, inherited Git overrides,
finite command budget, status tuple guards,
actual compiled genuine-verifier negative with original SQL operation/zero keys,
exact output nonce, real120s expiry and isolated restart. A separately labeled host
I/O fixture tests exact action-byte output; it is no native/Worker positive.
Startup checks unauthenticated
bridge503 and disabled inspector/127binding and real outbound interception. These
are synthetic-key negative qualification, not an Apple positive or E2E user test.
The additional read-only CI workflow runs the same host/workerd suite while
existing Validate/root78/privateRPC128/module49/regression gates continue.

Next acceptance is one independently observed fresh genuine Apple/server experiment
after the existing owner resolves exact binary input/build/profile/transport.
Native signing/assertions/JWE, authorized direct-edge target, HA route and separate
HA screen admission, receiver adapter and physical-TV acceptance remain distinct.
Production deployment and full-product Finalization remain unauthorized/open.
