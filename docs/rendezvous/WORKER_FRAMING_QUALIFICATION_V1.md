# Local server JWE framing qualification

Profile `0.4.0-draft`, wire `djc-rendezvous/1`, continuation from protected
PR94/main `e67f402b5f9d1a3099850dd2f6d9edd42a004aa0`.
**STRUCTURAL QUALIFICATION ONLY / NOT_FROZEN / NO_PUBLIC_RUNTIME_GO.**

[Typed candidate](../../qualification/rendezvous/jwe-framing.ts) validates public
JWK and compact-JWE shapes for later transaction composition. It does not decrypt,
verify an AEAD tag, validate plaintext or authenticate an app/HA owner. Product
source/dependencies/configuration/bindings, D1/APNs/pairing and translations remain
unchanged. A framing success is never submission authorization.

## Exact boundary

`qualifyBrowserPublicJwk(unknown)` accepts only `kty,n,e`: RSA, exponent AQAB,
canonical unsigned256-byte modulus with high bit set and odd low bit. It copies
fields before awaiting SHA256 of UTF8 JSON `{e,kty,n}` in RFC7638 order. Success
returns the copied public JWK and canonical32-byte base64url thumbprint. This is
not RSA factorization/key-provenance proof. Raw HTTP JSON duplicate-key rejection
is still required before constructing the object.

`qualifyCompactJwe(unknown,expectedThumbprint)` accepts at most8192 ASCII
characters and exactly five nonempty canonical unpadded base64url segments.
Encrypted key/IV/tag lengths are256/12/16 bytes; ciphertext is1..2048 bytes,
consistent with the existing uncompressed plaintext ceiling. These are application
bounds, not provider quotas. Expected thumbprint must be canonical32-byte
base64url from saved trusted transaction context in future composition, not an
unauthenticated caller claim.

Fatal UTF8 decoding preserves BOM for rejection. The bounded fixed
object-of-strings grammar permits only JSON whitespace (space/tab/CR/LF), uses
native JSON.parse per string and a Map to reject duplicate decoded names,
including escape aliases, without object-property assignment. Exactly
`alg,enc,typ,kid` are required: RSA-OAEP-256, A256GCM,
djc-rendezvous-destination+jwe and the expected thumbprint. Unknown/duplicate
fields, nested/nonstring values, zip/crit/jwk/jku/x5u, other algorithms, malformed
escapes/control characters, trailing JSON and noncanonical base64url fail closed.
Legal header spacing, order and equivalent escapes require no canonicalization.

The digest covers the **original exact compact ASCII bytes**, without header or
segment reconstruction. Success returns only digest and ciphertext byte count;
failures return fixed `public_key_rejected` or `envelope_rejected`. No fetch or
logging occurs. SHA failure denies. This is not a general HTTP/JSON parser and
does not enforce Origin/CORS, streamed request limits, rate/admission budgets,
transaction expiry, App Attest or a state transition.

## Actual evidence and reproduction

[Observations](workerd-framing-observations-v1.json): **92/92 actual local workerd
cases and isolated strict TypeScript PASS** on the first run. The runner reuses
the unchanged generator and fully pinned external jose6.2.12 manifest; no package
is installed. Ephemeral software RSA private key stays in process memory, never
exported or persisted. Only generated public example material enters the local
fixture. No Apple/device/credential inputs or new App Attest keys are used.

Before Worker tests, pinned JOSE encrypts via the existing generator, decrypts to
exact synthetic reserved-example plaintext, and rejects an altered tag. Independent
Node SHA256 matches its RFC7638 thumbprint. The same public envelope enters
workerd. Its plaintext expiry is deliberately1: structural acceptance proves no
plaintext freshness. Shaped encrypted-key/IV/ciphertext/tag corruptions deliberately
pass framing. JOSE's separate tag denial is not attributed to this validator.

Tests cover closed shapes, JWK copy across SHA await, independent exact digest,
legal header variants, decoded duplicates, forbidden fields, UTF8/BOM/JSON,
canonical encodings and segment lengths, size boundaries, browser mismatch,
SHA outage, no logging/fetch and 503/no-store harness HTTP. Test fetch is disabled;
no product endpoint or namespace is provisioned. Prior registration141/137 and
40 API regression evidence remain separate from parser integration.

```sh
node qualification/rendezvous/run_framing_workerd.mjs /private/tmp/isolated-jose-package /private/tmp/new-framing-results
```

Output must be new/outside the repository; directory0700, runner-owned files0600.
Summary records toolchain/source hashes and fixed case names; generated public
JWK/envelope and child diagnostics remain local. No generated key/ciphertext/URL
or their hashes enter that summary. No install/deploy/provider/root-binding change;
product `wrangler types` is unnecessary because bindings are unchanged.

## Reviews and remaining work

Independent security and UX/privacy design reviews returned scoped GO before
implementation. Security required copied JWK fields, strict JSON whitespace,
decoded duplicate detection without prototype assignment, BOM preservation and
original-byte hashing. Actual source/document review and CI receipts are recorded
separately on API90 and the continuation PR; design GO alone does not approve code.

The [transaction design](TRANSACTION_QUALIFICATION_DESIGN_V1.md) still needs actual
SQLite state/lease/race implementation and review. API retains HTTP/controller,
trusted routing and global admission. Joint exact consumer freeze, fresh supported
signed-iOS nonce/action integration and genuine composed-positive, full independent
review, Core actual HA/proxy/separate display admission and physical HA/iPhone/TV
remain open. Existing receiver generator crossrun is delivered; no unchanged rerun
requested. No owner/screen/Session authority or complete-service readiness follows.
Separate Finalization and explicitly authorized deployment remain open. Rollback
is a reviewed revert of this isolated increment; no provider rollback is required.

Standards: [JWE compact/header requirements](https://www.rfc-editor.org/rfc/rfc7516.html)
and [JWK thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html).
