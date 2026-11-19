# Local workerd App Attest core qualification v1

Same API94 writer; profile0.4.0-draft/wire djc-rendezvous/1 NOT_FROZEN.
**Scoped core qualification; receipt UNVERIFIED, no enrollment/runtime GO.**

The [isolated candidate](../../qualification/rendezvous/app-attest-core-candidate.mjs)
composes the previously reviewed [certificate path](WORKER_PATH_QUALIFICATION_V1.md)
with measured development-app CBOR/nonce/credential/app/COSE binding and assertion
signatures. This is an adapter of Apple's App Attest verification procedure using
standard maintained parsers/WebCrypto/PKIJS, not a new cryptographic protocol.
No product import, endpoint, dependency, config, binding, D1 or workflow changed.

## Exact measured scope and hard exclusions

App identity is fixed ZEML4LPXH4.dev.djconnect.ios, iOS development marker/category3,
flags0xc0 and observed builds40227/40228/40230 only. These are qualification
constants, not a production/multi-platform/distribution allowlist or negotiated
client policy. Other flags/categories/builds/platforms fail this candidate.
Apple's macOS access-policy checks and other distributions remain NOT_QUALIFIED.

CBOR10.0.12 enforces duplicate keys, depth8, complete top-level consumption and
closed typed maps. Bounds: attestation32KiB, assertion4KiB, saved clientData2KiB,
authData2KiB, extension1KiB, individual cert8192bytes, receipt16KiB. Attestation
checks the fixed-root path, counter0, credential length/canonical standard-base64
key ID, AAGUID, app hash, COSE type/algorithm/curve/coordinates, exact leaf point
and SHA256(point) credential binding, measured snake_case extensions and nonce.
Nonce is exactly the single explicit[1]/primitive OCTET STRING32 structure,
reconstructed with fresh ASN.1 nodes to enforce its canonical encoding, and equals
SHA256(authData || SHA256(savedClientData)).

Assertion uses simplified authData, measured extensions/app, unsigned32 counter
strictly greater than the supplied prior counter and a standard P256 public-key
import. Strict short-form DER ECDSA SEQUENCE/two minimal positive INTEGER values
is converted by PKIJS's standard DER/P1363 adapter. WebCrypto ECDSA-with-SHA256
verifies the signature on the nonce above: the additional signature hash is
confirmed with actual Apple signatures and a negative single-hash control.
No handwritten DER/P1363 conversion or private-key extraction.

Returned attestation scope is
`ATTESTATION_CORE_ONLY_RECEIPT_UNVERIFIED_NO_ENROLLMENT` with point/opaque receipt;
assertion scope is `ASSERTION_CRYPTO_ONLY_NO_ATOMIC_COUNTER_OR_WIRE_ADMISSION`.
Null means denial. Receipt presence/size is checked, **not its CMS validity**.
No active key, transaction authorization or public success response is produced.
Saved clientData/prior counter are trusted test-adapter inputs. Fresh challenge,
exact action/bytes, server deadline, receipt CMS, revocation and atomic persisted
counter acceptance remain mandatory separate gates. Crypto acceptance of old
capture bytes is not permission to enroll them now; archived receipts are stale.

## Executed evidence and the discovered DER failure

[Private-fixture sanitized results](workerd-core-observations-v1.json): **93/93
PASS**, two original raw private iPhone attestations and nine normal actual
assertions (eight prior plus counter6), copied-QR-independent crypto checks,
replay and changed saved challenge denial, raw31-byte SDK boundary denial under
server hashing, signed synthetic policy negatives and strict parser controls.
[Public-only results](workerd-core-public-observations-v1.json): **44/44 PASS**,
without private device data. These public controls include high-bit/max unsigned
counters, counter exhaustion/range, wrong app/flags/build/category, changed input,
invalid key/signature/DER, direct decoder duplicate-key/UTF8/trailing/depth tests,
and rejection of incorrect signature hash layering. These are crypto/counter
predicates, **not persisted replay/race tests**. No fetch occurs in actual-core
checks. Actual installed pool0.22.0/Miniflare5.20260815.0-alpha/workerd1.20260815.1,
Node26.12.0; compatibility date2026-06-20/nodejs_compat. Source hashes bind results.

A public intermediate run had42PASS/1FAIL: an otherwise valid signature with a
non-minimal outer SEQUENCE length could be accepted. ASN1js can preserve BER
length forms on round-trip; round-trip equality alone did not prove strict DER.
An earlier private92PASS run missed that case because random signature size
could make the mutation exceed the general72-byte ceiling. Neither result is
relabeled. The corrected candidate explicitly requires the short outer header
and short primitive INTEGER headers, in addition to minimal positive values;
nonce uses a fresh canonical reconstruction.

The final regression first obtains a valid synthetic signature<=71bytes using
at most32 attempts, proves original verification succeeds, then inserts the
non-minimal length, asserts the mutation is still<=72bytes and proves denial.
Thus the DER guard is tested below the payload ceiling. Both final93/44 runs
include it. This is not a claim of general ASN.1/RFC validation equivalence.
Historical SDK false32-byte assumption remains FAILED; the raw31 server denial
is a separate result, not a repair/relabel of that producer assumption.

## Reproduction, software identity and privacy

Use the existing repository local Worker test dependencies plus an external
isolated install with scripts disabled: cbor10.0.12, PKIJS3.4.1, ASN1js3.1.0.
[Core provenance](../../qualification/rendezvous/core-dependency-provenance-v1.json)
records all dependency versions/integrities. The CBOR npm SHA512 matched and all
30 installed archive files matched the official npm tarball. Existing PKI library
artifact checks remain in the prior path checkpoint. No reproducible source
build or independent dependency audit is claimed.

```sh
node qualification/rendezvous/run_core_workerd.mjs /private/tmp/isolated-core-deps /private/tmp/new-core-output
```

Optional third argument is the original owner-authorized private capture root,
containing device-evidence/reuse-evidence/input-evidence. No new capture or device
key is needed. Inputs are the actual original CBOR files and saved input bytes;
the runner does not rebuild those proof envelopes. Public reproduction omits
all genuine cases and explicitly records them NOT_RUN.

Runner creates a new0700 directory (never overwrites), its own generated files
0600; child logs/full test outputs stay inside the private directory. Raw errors
are suppressed at the console. Public summaries contain fixed labels/results,
software versions/public source hashes only. Actual device certificates,
identifiers, handles, receipts/proofs and their hashes are never published.
The existing owner review/delete deadline2026-11-16 covers derived workdirs;
no automated erase or hardware key deletion is claimed.

## Independent reviews and remaining security gates

Supplied-guards/results technical review initially returned scoped core GO.
The independently discovered public DER failure superseded that encoding claim;
review assessed the exact corrective guards and required a negative below the
payload ceiling. Corrected93/44 runs included that control; follow-up review restored **scoped core
GO, no remaining P1/P2 in supplied correction material**.
Reviewers did not independently inspect files/libraries/fixtures or execute code.
UX/privacy/evidence review returned scoped GO. Neither review approves the full
verifier, fresh enrollment, wire lifecycle or public runtime.

[Initial receipt policy](INITIAL_RECEIPT_POLICY_V1.md) now proposes finite,
encrypted original receipt retention tied to the original key expiry with atomic
registration and revoke/expiry erasure; independent technical/privacy reviews
GO for that bounded proposal, **not actual storage implementation**. No fraud
refresh/Apple credential use is authorized. CMS/signer profile, revocation status
source/freshness/outage/root policy, encryption-key operations and real storage/
crash/cleanup tests remain explicit security gates. No implicit soft-fail.

Next: qualify actual CMS/signature/path/fields and adversarial cases, resolve
reviewed revocation policy, then compose the complete verifier and obtain full
review before runtime admission. Actual native action/JWE, DO lifecycle/counters/
recovery/races, joint freeze and physical HA/iPhone/TV chain remain open. The receiver0.4
browser-consumer ACK is already delivered (API94/6231693523, reconciled in
receiver16/6233688083), including its scoped reviews/schema checks; it is not a
missing-input blocker. This checkpoint changes no browser fields/schema, so that
bounded ACK is retained, not promoted to runtime adoption.
Normal protected product delivery, separate Finalization and separately authorized
production deployment remain pending. Existing APNs/D1/consumer WIP is unchanged.

Primary requirements retrieved2026-10-17:
[Apple server verification](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server),
[Apple receipt validation](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk).

Current existing regression verification:40/40 Worker tests,107 schema cases plus2
clientData byte examples, typecheck, offline projection, whitespace and69 local
links PASS. Secret scan102 unchanged baseline lines/no new matches. No bindings
or D1 changes; no type generation/migration needed for this isolated checkpoint.
No user-facing translation changed; release-language review remains a later gate.
Normal CI runs separately from these optional local/private qualification tests.
