# Offline principal-possession crypto DATA

This standalone candidate library verifies a proof over an independently supplied
original expected transcript. A valid result is `KEY_POSSESSION_DATA_ONLY`: it
does not enroll a principal, authenticate installation ownership/operator/custody,
accept a purpose grant, consume a nonce, check time or establish restore freshness.
No public route, Worker configuration, registry call, signing or key-generation
path is added. The ordinary API Worker and the existing registry DATA model are
unchanged. The latter is still pair-bound; no installation-principal migration is
implied by this crypto module.

The exact [byte contract](byte-contract-r1.json) is the frozen private R1 design,
SHA256 `69801f4dc741ed1f18289ebce9e380778bbefa005cd443c6aebcc32a103392e5`,
personally reviewed by Core in receipt
`29542fb0e9c096cb9cb023177708e56ddad306dc803eb91da9822349cdc85b80`.
Its historical not-implemented/source-GO flags describe that original design
snapshot. This new implementation needs its own exact source review and delivery;
the design receipt is not such a review. No normative af201/090b/Source153 wire
is changed or silently reinterpreted.

`verifyPossessionData(expectedBody, proofBody, signatureBase64url)` accepts only
canonical primitive JSON strings, at most4,096 UTF8 bytes. It snapshots/validates
both, requires complete byte equality, recomputes the exact nested public JWK pin
and imports only the original expected public key. Signing input is the fixed
50-byte ASCII domain, exactly one0a, then canonical body bytes. ECDSA/SHA256 uses
exact64-byte P1363 r||s; r and s are1..q-1. Both genuine S representatives verify
as the same original operation/challenge/body identity. Neither signature bytes
nor a successful repeated crypto call creates a new operation or extends expiry.

Malformed data throws `PossessionDataInputError`; an invalid signature returns
null. Crypto failures, including point-import and output-digest failures, preserve
their original cause instead of being relabelled as an invalid signature. The
result is a frozen object of public DATA scalars. An expired transcript may verify
cryptographically; no clock or currentness validation is promised. Supplying a
matching expected body is also not evidence that it was independently authorized.

The [public fixtures](public-vectors.json) contain an expired synthetic transcript
and a deliberately insecure mathematical test point/signature. Public P-256 G and
fixed public test scalar/nonce1 give r=G.x modq and s=(SHA256(input)+r)modq. These
are reproducible software conformance constants, not real Core/Apple/operator keys
or credentials. No private CryptoKey, RNG, key generation or signing API is used
to construct or run them. Never use these public constants operationally. Their
positive candidate and opposite-S proofs are distinct from the original RFC/R1
encoding-only vector. Wrong LF/domain variants remain real invalid proofs over
the admitted fixed domain. No real registration tuple is supplied.

Qualification runs in actual local workerd/WebCrypto:65 PASS,0 FAIL,0 SKIP,
including both positive S aliases, all13 original malformed-body cases, all10
scalar-boundary cases, strict expected-body mismatch before crypto, wrong domains,
off-curve import, exact crypto-error identity and no private/egress operations.
The first run passed64/65; a test-helper default incorrectly replaced undefined
expected input. That helper was fixed to call the actual verifier directly, then
the full65 passed. Preliminary shared-buffer type errors were fixed before that
run. Neither preliminary failure is reported as a PASS.

The existing closed qualification HTTP host stays503; that is not a new test of
the production root. Root source/configuration and registry tests are unchanged;
their old PASS is not claimed as a new verifier result. UI and all five supported
languages are unchanged. No native, provider, installation or deployment effect
is performed.

```sh
node_modules/.bin/tsc -p coordinator/principal-possession/qualification/tsconfig.json --noEmit
node_modules/.bin/vitest run --config coordinator/principal-possession/qualification/vitest.config.mts
node coordinator/principal-possession/build-source.mjs "$TMPDIR/new-possession-data-package"
node coordinator/principal-possession/qualification/check-package.mjs "$TMPDIR/new-possession-data-package"
```

Use a fresh external scratch leaf with an existing parent. The packager rejects
repository output, follows the parent's real path before choosing the output,
refuses existing leaves, verifies source/lock hashes and records installed esbuild
hashes. It produces only a standalone browser ESM library, frozen byte contract,
public vectors, metafile and hash proof. No Worker deployment configuration or
positive factory is generated. Its only bundled sources are this module and the
existing strict JSON/canonical primitives. A separate host check imports the actual
packaged ESM, verifies both positive public aliases, wrong domains, exact expected
body mismatch, module hash and the two DATA-only exports. This does not turn host
verification into workerd/native/registration authority. Required GitHub checks and independent
whole-source review remain separate from local qualification.
