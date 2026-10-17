# Code-free A wire and crypto profile — review candidate 0.4.0

**NOT_FROZEN / NO_RUNTIME_GO.** Proposed wire `djc-rendezvous/1`.
Read [KEY-STATE](KEY_STATE_V1.md) and [the contract](CONTRACT_REVIEW_V1.md).
This specifies a profile for independent review, not a new cryptographic primitive.

## Exact producer/consumer boundary

Use current Core candidate `6e560061cbee3bed86c50fc0deee7d74b9bfee9b`:
existing authenticated Hybrid expected-install equality, then
`POST /api/djconnect/v1/display/owner/context` using only the existing app->HA
Authorization and `{contract_version:1,identity:{client_type:"ios",device_id:...}}`.
Use current `display_entry_url`, not cached pairing URL. Recheck monotone pairing/
Profile/route/epoch/flow validity after awaits and immediately before assertion/
release. A route/epoch change requires fresh confirmation. `issuer_epoch` is a
process fence, not installation identity or a signing root. Generic capabilities
mean protocol support, not available external route or admission consent.

The Apple source review reports one saved installation; explicitly show that
actual configured installation. No invented multi-install registry. The future
actual signed app must prove configured App ID prefix/bundle/environment; the
reported development artifact `ZEML4LPXH4.dev.djconnect.ios` is not production
qualification. Use supported iPhone runtime `isSupported`; do not enable this
profile for Mac/Catalyst/iOS-on-Mac or borrow another device's assertion. Official
Apple documents currently have differing platform scope: recheck SDK/runtime at
qualification; iOS-only v1 does not claim general Mac capability.

## Standard algorithms and exact investigation pins

Candidate destination encoding: RFC7516 compact JWE, **RSA-OAEP-256 + A256GCM**;
2048-bit RSA browser key, exponent65537, no compression. RFC7518 defines key
management and AEAD; use library-managed CEK/randomness/IV/tag. No hand-written
OAEP/KDF/GCM, algorithm negotiation or weak fallback. Browser private key is
nonextractable, memory-only, unique per transaction/window; erase references on
terminal/rotation/unload. Public JWK is exactly `{kty:"RSA",n,e:"AQAB"}` with
canonical unsigned2048-bit modulus. RFC7638 SHA256 thumbprint identifies it.

Exact protected header fields: `alg:"RSA-OAEP-256"`, `enc:"A256GCM"`,
`typ:"djc-rendezvous-destination+jwe"`, `kid:<browser thumbprint>`.
Reject extra/duplicate fields, zip/crit/jwk/jku/x5u, other algorithms, noncanonical
base64url and trailing data. Five compact segments; standard12-byte IV and16-byte
tag. Digest SHA256 of the **exact ASCII compact-JWE bytes**, base64url without
padding. OAEP/AEAD integrity alone is not paired-sender authentication.

Investigation pins, no dependency installed/selected for runtime:

| Role | Exact source | Qualification status |
| --- | --- | --- |
| Browser/Node reference | panva/jose6.2.12, `505a55b8f73536082367b2614cb77e927ba96ec1` | Declared browser/Worker support, no current app interop evidence |
| Native reference | airsidemobile/JOSESwift3.0.0, `c2664a902e75c0426a1d43132bd4babc6fd173d3` | Declares compact JWE and both proposed algorithms; Apple owner must qualify actual build/interop |
| App Attest verifier reference | node-app-attest1.0.1, `f16c4bb71b737466872bc8b8a7dfd215364eaa83` | Unmodified source is not approved: complete chain validity/constraints, strict CBOR, unsigned counters and current Apple fields need qualified verification |

An App Attest verifier must follow Apple's exact attestation/assertion rules,
including chain/root/nonces/app/key/environment, known-key counter and saved
challenge. No bare WebAuthn/Safari-attestation substitution. Do not hand-convert
ECDSA DER/P1363 or change hash layering ad hoc: independent real Apple vectors
must determine the exact library adapter behavior. Certificate expiry, malformed
CBOR/ASN.1 lengths/duplicates/trailing objects and unsupported app/distribution
policy fail closed. App Attest enrollment is not HA pairing or a new account.

[Reference audit](VERIFIER_REFERENCE_AUDIT_V1.md) records15 executed synthetic
assertion observations on two Node runtimes and specific source-only path/parser
gaps. The reference remains rejected for runtime. Current Apple extension and
fraud-receipt applicability/retention need explicit resolution with actual
producer fixtures; operation receipts are not Apple fraud receipts.

## Serialization and binding

All JSON is one UTF8 object, reject duplicate keys, invalid UTF8, trailing data,
nonfinite/fractional/out-of-range numbers and unknown fields before use. Opaque
tokens are32 random bytes, canonical unpadded base64url43 chars. Transaction IDs
are server UUIDv4; generation is integer1..2147483647; times are safe-integer UTC
milliseconds. Apple key ID is canonical **padded standard base64 of32 bytes**;
do not confuse it with URL-safe tokens or the browser JWK thumbprint.

`claim_commitment` is unpadded base64url SHA256 of the decoded32-byte browser
claim secret. Store only that commitment and the SHA256 commitment of the
server-generated32-byte QR capability. Compare supplied secret commitments
in constant time; never return the browser claim to a scanner. These are bearer
capability checks, not owner authentication.

JWE plaintext is a closed object with only:
`v,transaction_id,generation,browser_key_thumbprint,expires_at,bootstrap_origin,
display_entry_url,issuer_epoch`. No HA install/device/user/Profile ID, credential,
Session state or grant. Native checks installation locally; browser checks its
own context and exact raw URL. It does not independently prove paired ownership.
Plaintext URL follows the Core raw-route corpus: initial canonical public ASCII
non-IDNA HTTPS DNS, implicit443, exact `/djconnect/vibecast/display`, no query,
fragment/userinfo/IP/percent/backslash/dot aliases/trailing slash. Subsequent
navigation belongs to selected HA/proxy; no JavaScript redirect-fence claim.

Server creates and saves **exact clientData bytes**, returned as unpadded
base64url `client_data`. Parsed contents are a closed object:
`v,action,service_origin,transaction_id,generation,browser_key_thumbprint,
expires_at,key_id,challenge_id,challenge,envelope_digest`.
`action` is exactly `submit`; origins are fixed `https://api.djconnect.dev` and
the transaction's `https://vibecast.tv` browser context. The bootstrap origin is
bound by transaction/browser-key context and inside JWE plaintext.

Apple must decode and strictly parse these bytes and compare **every field**
with its own captured flow/key/envelope/challenge context before hashing and
asserting them. Never blindly sign server-returned bytes. It uses SHA256 of
the exact saved bytes as the App Attest clientDataHash; no JSON reserialization
or client-side canonicalizer is needed. API requires byte equality to its saved
clientData as well as parsed binding, assertion and coordinator authorization.
Changing whitespace/key order therefore requires a new challenge, not reusing
the old assertion. This is byte binding, not a claimed cross-language JSON rule.

## REST messages and limits for review

All requests/responses include `v:"djc-rendezvous/1"`; see the machine-readable
[request schemas](wire-request-schemas-v1.json). They are review artifacts;
request validation does not implement runtime authorization or cryptography.

| POST route under `/v1/rendezvous` | Success | Maximum raw request body |
| --- | --- | --- |
| `/create` |201 transaction/generation/created_at/expires_at/qr_payload |4KiB |
| `/inspect` |200 browser_public_key/browser_key_thumbprint/generation/expires_at |1KiB |
| `/attestation/challenge` |200 challenge_id/challenge/expires_at; delete-key also client_data |1KiB |
| `/attestation/register` |201 key_expires_at, no user/HA association |64KiB |
| `/submit-challenge` |200 challenge_id/challenge/client_data/expires_at |1KiB |
| `/submit` |202 accepted:true, operation_id=challenge_id; historical acceptance only |32KiB |
| `/poll` |200 state/expires_at/retry_after_ms, no envelope |1KiB |
| `/consume` |200 state consumed/destination_envelope/expires_at |1KiB |
| `/cancel` |200 state cancelled; browser claim required |1KiB |
| `/attestation/delete` |200 state revoked/purge_at; challenged assertion required |16KiB |
| `/attestation/recover` |200 original key_expires_at; fresh recover-key assertion required |16KiB |

QR is raw compact UTF8 JSON, **not a URL/deep-link**: closed object
`{type:"djc-rendezvous-qr",v,service_origin,transaction_id,generation,
expires_at,browser_key_thumbprint,qr_capability}`; maximum1024 UTF8 bytes.
In-app scanner only, no automatic OS URL open, history or query/fragment secrets.
`inspect` requires the QR capability and original generation, reveals no browser
claim secret and grants no winner reservation. No arbitrary service origin.

Body limits apply to streamed/chunked bytes before buffering/decode. Content-Type
application/json only; no content encoding. Decoded attestation<=32KiB,
assertion<=4KiB, clientData<=2KiB, compact JWE<=8KiB, plaintext<=2KiB. The endpoint
ceilings supersede revision0.2's blanket16KiB body limit; they are not platform
quotas. Rejection413/415 precedes crypto; fixed redacted errors only.

Enrollment challenges use action register and exact key address; registration
attests SHA256 of the server nonce bytes per Apple's documented API. Deletion
has its own action `delete-key`, challenge, key_id and exact saved clientData;
it cannot reuse a submit challenge/signature. Production server configuration
selects the app/environment, never a client-declared development allowance.
For action `delete-key`, the challenge response also returns `client_data`:
the exact server-saved bytes in unpadded base64url. Native strictly parses and
checks fixed protocol/service identity, action, key ID, challenge ID/nonce and
expiry before asserting SHA256 of those exact bytes. The delete request echoes
those bytes; the server requires exact equality with its saved clientData.
Registration continues to use its separate nonce-hash attestation flow.
Revision0.4 adds management action `recover-key` using the same challenge
response shape as delete-key, but action-separated exact clientData and a
separate recover endpoint. [Enrollment recovery](ENROLLMENT_RECOVERY_V1.md)
defines deadlines/counters/receipts/errors and the paused local repair policy.
There is no public registration status lookup or expiry extension. Machine
schemas cover the new request/response, decoded recovery clientData and its
exact byte example; structural validity never proves the signature or key state.
The submit request echoes `client_data` for exact byte equality against the
saved challenge; signature verification uses only those saved matched bytes.
The machine schemas also define registration/delete responses;
there is no supported fallback registration or inferred account service.

## Replay, failure and diagnostics

Coordinator operation ID=challenge_id. The202 response is an immutable accepted-operation receipt, not a promise that
the browser transaction is still ready. Status of an identical lost submit may
recover that receipt without another destination release; original browser poll gets only state.
Same operation with changed ciphertext/clientData conflicts; different operation
cannot reuse nonce/assertion/counter. Burned authorization recovery,5s lease,
cross-key concurrency and revocation windows are defined in KEY_STATE_V1.md.
All operations recheck original120s expiry; cancel/rotate/new key never renew it.
After a ready commit, an identical submit retry may recover the historical202
from the transaction's immutable operation/request digest and QR-capability check,
without a new key authorization, counter change or destination release. This
also applies if the key coordinator's receipt has since been erased by revocation.
Before ready, a retry still needs a current unexpired coordinator authorization.
No response claims that a later cancelled/consumed transaction is currently ready.

Fixed error shape `{v,error,retry_after_ms?}`. Codes: invalid_request400,
unsupported_version400, invalid_capability401, invalid_sender_proof401,
attestation_required401, app_not_supported403, origin_denied403,
operation_conflict409,
already_submitted409, already_consumed409, cancelled409, not_ready409,
expired410, payload_too_large413, unsupported_content_type415, rate_limited429,
attestation_unavailable503, service_unavailable503. No parser/certificate/counter
details or IDs echoed. Expired/revoked/unknown key states are private coordinator
results or local native states; public requests receive invalid_sender_proof.
There is no public key-ID existence oracle or unauthenticated recovery lookup.
Unsupported/native attestation state may be a local UI error, not an unsigned
server claim. All retries stay within original expiry and server Retry-After.

Only exact browser Origin `https://vibecast.tv`; native no-Origin still needs
proof/capability per operation. Null/foreign/duplicate Origin denied, no cookies
or credentialed CORS. No-store/no-referrer/nosniff on all responses, `Vary: Origin`.
No HA fetch, body/proof/ID/URL logs or automatic Apple fraud-metric calls.
Address sent/ready/consumed/navigation initiated are never display connected.

## Interoperability exits, not fabricated fixtures

Apple has delivered actual app-bound development fixtures and ACK0.4;
[offline qualification](GENUINE_APP_ATTEST_QUALIFICATION_V1.md) records measured
snake_case extensions/flags, real nonce/receipt/assertion binding and the strict
leaf-AKI finding. Its [narrow policy](LEAF_AKI_POLICY_V1.md) now has policy GO and
an executed strict OpenSSL probe; equivalent Worker enforcement remains pending.
These diagnostic inputs are not actual action-specific wire
clientData or live enrollment. The remaining obligation is qualified fresh
action-separated fixtures with exact signed identity/environment and redacted public evidence;
no private key or production/user payload in repository. Include app/prefix/env,
CBOR/chain/counter/nonce mutation and reorder cases. The signed app must actually
exercise current owner/context, missing route and monotone flow invalidation.

JWE: native JOSE library encrypts synthetic payload -> browser library decrypts;
browser/Node reference encrypts -> independent native decrypts. Test identical
protected/context fields, key-thumbprints and all ciphertext/tag/header/key/
expiry mismatches in Chromium/WebKit plus the actual native build. Schema/model
cases and declared library support are not that proof. Audit candidate verifier
against actual Apple validation vectors and strict certificate/CBOR cases inside
workerd; test DO crash/races separately. No borrowed assertion or synthetic
signature is reported as an Apple-device PASS.

Sources checked17October: [Apple server validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server),
[Apple lifecycle](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity),
[Apple rollout](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service),
[isSupported](https://developer.apple.com/documentation/devicecheck/dcappattestservice/issupported),
[JOSESwift3.0.0](https://github.com/airsidemobile/JOSESwift/tree/c2664a902e75c0426a1d43132bd4babc6fd173d3),
[jose6.2.12](https://github.com/panva/jose/tree/505a55b8f73536082367b2614cb77e927ba96ec1).
