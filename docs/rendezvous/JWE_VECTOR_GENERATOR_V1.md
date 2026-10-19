# Software-only destination JWE vector generator v1

Assignment DJC-API-VIBECAST-RENDEZVOUS-V1-20261016, same API94 writer.
Profile0.4.0-draft / wire djc-rendezvous/1 **NOT_FROZEN / NO_RUNTIME_GO**.

This is the concrete API counterpart requested by the existing receiver owner
at [receiver16/6241859224](https://github.com/pcvantol/djconnect-vibecast-receiver/issues/16#issuecomment-6241859224).
It allows a synchronous producer call while a freshly generated, nonextractable
browser private key is still alive. Do not post a stale public key in comments
or keep the browser open while waiting for another lane. Only public key and
synthetic plaintext cross the local process boundary; no private key transfer.

## Invocation and exact interface

[Generator](../../qualification/rendezvous/generate_destination_vector.mjs):

```sh
node qualification/rendezvous/generate_destination_vector.mjs /absolute/isolated/jose-package
```

One package-directory argument; stdin is one UTF8 compact `JSON.stringify`
object `{jwk,thumbprint,plaintext}`, optionally followed by one LF, at most16KiB.
Formatting equality rejects duplicate keys and alternate numeric representations
in this **tool input** without adding a JSON parser. Pretty JSON is deliberately
unsupported by the CLI; this is not a wire-format canonicalization requirement.
The receiver's existing Node harness already creates this form naturally.

Public JWK is closed `{kty:"RSA",n,e:"AQAB"}`: canonical unpadded base64url,
256-byte unsigned modulus with high bit set and odd low bit. No private fields,
alg/key_ops/x5u/jku or extra metadata. Provided thumbprint must be canonical
32-byte base64url and equal library-calculated RFC7638 SHA256 for that key.

Plaintext is exactly the eight fields in [WIRE_PROFILE](WIRE_PROFILE_V1.md):
v,transaction_id,generation,browser_key_thumbprint,expires_at,bootstrap_origin,
display_entry_url,issuer_epoch. Require protocolv1, lowercase UUIDv4/variant,
generation1..2147483647, safe nonnegative integer expiry, the exact public-key
thumbprint, fixed https://vibecast.tv and canonical32-byte epoch. Destination
uses only reserved example DNS: example.com/net/org and subdomains, or .example;
ASCII non-IDNA HTTPS, implicit443, exact display path, no query/fragment/userinfo/
percent/IP/aliases. This restriction prevents accidental real HA inputs; it is
**not** the production HA URL validator or an authentication/ownership check.
Unknown fields, credentials, Profile/Session content and plaintext above2KiB deny.

Past or far-future synthetic expiry is deliberately expressible for consumer
denial fixtures. This tool does not enforce transaction TTL or declare a
transaction valid. The consumer still checks its own original deadline/context.

Success: exit0, **one compact JWE plus LF on stdout**, empty stderr. Fixed header
alg RSA-OAEP-256, enc A256GCM, typ djc-rendezvous-destination+jwe, kid thumbprint;
at most8KiB envelope. Library manages CEK/OAEP/IV/tag/randomness, no overrides or
algorithm negotiation. Repeated input produces different encrypted output.
Failure: exit1, empty stdout, only `vector_generation_rejected` plus LF on
stderr; no input, destination, key, parser/library error or path echo.

Harness call, using its existing live `jwk`, `thumbprint` and synthetic `plaintext`:

```js
const result = spawnSync(process.execPath, [generatorPath, isolatedJosePackage], {
  input: JSON.stringify({jwk, thumbprint, plaintext}),
  encoding: 'utf8', timeout: 5000, maxBuffer: 32768,
});
assert.equal(result.status, 0);
assert.equal(result.stderr, '');
const envelope = result.stdout.trimEnd();
// Decrypt/validate with the original live browser key, then close the browser.
```

The caller owns its subprocess timeout. The generator is a local development
tool, not a network service, trusted sender, transaction issuer or QR source.
It reads stdin and pinned package files, writes no files, performs no network,
HA, Apple, AppAttest, credential or fraud-metric calls. No AppAttest/device key
is generated or recaptured. There is no product import/dependency/binding change.

## Exact dependency identity

Use isolated jose6.2.12. [Artifact manifest](../../qualification/rendezvous/jwe-dependency-provenance-v1.json)
records the freshly verified official npm archive SHA512 and all80 files'
SHA256. Loader checks exact inventory, every file hash, no symlink/nonregular
entry, package version/name and no dependencies before importing. Package path
must resolve outside this repository. Existing receiver's isolated package can
be used read-only if it matches; the tool never installs or alters it.

Official annotated tag v6.2.12 resolves through99eaf5ed to the existing source
investigation pin505a55b8f73536082367b2614cb77e927ba96ec1. The npm artifact has
no gitHead metadata. File/archive matching establishes artifact identity, not a
reproducible source build, complete dependency audit or production selection.
The manifest/source are trusted development inputs; a compromised local machine
or concurrent dependency filesystem mutation is outside this tool's boundary.

## Executed qualification and reviews

[API test runner](../../qualification/rendezvous/run_jwe_vectors.mjs):

```sh
node qualification/rendezvous/run_jwe_vectors.mjs /absolute/isolated/jose-package /private/tmp/new-api-jwe-results
```

Creates a new0700 directory; its own evidence files0600. Software RSA private
keys remain process-memory only; they are never exported/persisted. Fixed-label
sanitized [results](jwe-generator-observations-v1.json) bind source/manifest hashes:
**52/52 PASS** under Node26.12.0. Positive CLI encryption decrypts to exact bytes
with jose and separate standard Nodecrypto RSA-OAEP256/AES256GCM APIs. These APIs
share platform cryptographic implementations; this is not independent backend
qualification. RFC7638 is separately calculated; library randomness, all five
segment mutations, wrong recipient, expired test payload and CLI framing tested.
Private-key fields, malformed public key/thumbprint/context, credential fields,
unsafe/nonexample URL and extra/duplicate/invalidUTF8/oversized input deny
without echo. Dependency changes, extra files and symlinks deny before import.
No browser private key, real device proof or production/user payload is used.

Independent supplied-guards security and product/privacy review: scoped generator
GO, no P1/P2 in supplied material. Reviewers did not independently inspect files
or run tests. No full crypto/wire/runtime approval follows. Existing40 API
regressions,107 schema+2byte examples, types and offline projection pass separately.
No user-facing translations changed; normal CI remains separate from local52.

First normal CI at c21f3a0 ran its CodeQL analysis successfully but the security
result gate FAILED with one high alert on first-occurrence string replacement
in the duplicate-key negative fixture. The test builder now constructs the
explicit duplicate prefix instead of a replace operation. Each duplicate fixture
also proves valid JSON syntax before testing generator rejection, so a broken
JSON string cannot masquerade as duplicate detection. Final52-case rerun passes;
generator and manifest hashes are unchanged. No alert suppression, dismissal,
workflow or gate change; the failed first CI remains part of delivery history.

Receiver already reports Mac JOSESwift3.0.0↔Chromium/WebKit jose6.2.12, nonextractable
keys and28 profile-oracle denials. That evidence predates this concrete API
generator, is producer-reported, and explicitly uses predetermined fake destination/
epoch comparisons and a test-only flat JSON oracle. It is not independent HA-owner
proof, a production parser, actual signed iOS action binding or this crossrun.

## Delivered consumer crossrun and remaining handoff

[Receiver16/6244059388 intake](RECEIVER_GENERATOR_CROSSRUN_INTAKE_V1.md) now
closes that exact concrete generator crossrun: Chromium/WebKit fresh keys,
synchronous API CLI/native roundtrips and48 combined context/crypto denials.
API independently read the receipt and matched receipt/probe/generator/manifest
hashes; no API browser rerun. Earlier oracle-only evidence above remains historical.
No repeat crossrun of the unchanged generator, website publication, structural ACK
or private-key transfer is required. Full TRUST-2/joint freeze remains open.

Existing Apple owner: retain responsibility for actual supported signed-iOS
action/flow bindings and native integration. A Mac software CLI result cannot
replace that proof. Core retains actual current HA route/proxy and independent
screen-admission qualification. API retains complete original-challenge/verifier/
status/policy/storage/action composition and independent full review. Joint freeze,
runtime/DO/replay/abuse implementation, physical chain, protected delivery,
Finalization and separately authorized deployment remain open.

Primary references: [jose CompactEncrypt](https://github.com/panva/jose/blob/v6.2.12/docs/jwe/compact/encrypt/classes/CompactEncrypt.md),
[RFC7516](https://www.rfc-editor.org/rfc/rfc7516.html),
[RFC7638](https://www.rfc-editor.org/rfc/rfc7638.html).
