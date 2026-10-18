# Initial App Attest receipt — finite policy candidate v1

Same API94 writer, profile0.4.0-draft; **REVIEW_CANDIDATE / NOT_FROZEN /
NO_ENROLLMENT_OR_RUNTIME_GO**. This refines the previously open receipt storage
question. It changes no consumer endpoint/schema or deployed configuration.

## Validation before any key registration

Apple requires independent receipt verification and immediate storage after
successful attestation. A valid certificate/nonce/App Attest core is insufficient.
The initial receipt must pass complete bounded CMS/ASN.1 signature and signer
path validation against the official Apple Root CA G3, then app ID field2,
attested DER certificate field3, type6 exactly ATTEST and creation12 freshness.
Reject duplicate field types, malformed versions/types/encodings and unsupported
CMS algorithms/critical attributes. Exact accepted optional fields and signer
profile still require the actual CMS implementation and adversarial review;
this policy does not preapprove permissive parsing.

Server clock requires `0 <= now - created <= 300000` milliseconds; original
120-second enrollment challenge must independently still be live and bound to
the exact saved clientData, key and action. Equality with challenge expiry is
expired. A stale receipt cannot be refreshed, backdated or substituted with an
operation receipt to make enrollment succeed. No success or persisted active
key until all checks and the local atomic registration commit succeed.

Receipt CMS signer/root validation is separate from the App Attest leaf path.
The reviewed missing-AKI exception applies **only to that App Attest leaf** and
never to CMS signers/intermediates. No system trust or client-supplied root.
CMS signatures alone do not prove a trusted signer or fresh receipt.

## Proposed finite storage

Retain the original independently verified initial receipt, encrypted at rest,
inside the same key coordinator record as the public key. Absolute deadline is
the original key_expires_at, at most30 days from successful enrollment. Assert,
recover, exact retry and day27 rollover never extend it; a replacement has its
own independent attestation/receipt/deadline. This is linkable security evidence,
not anonymized data; no user/HA/account/installation lookup index is created.

Use the existing standard WebCrypto AES-256-GCM storage helper/pattern with a
separate rendezvous-receipt operator key; never reuse APNs encryption/relay or
Apple provider credentials. The eventual authenticated plaintext record binds
receipt to key address, configured app-policy/environment and original enrolled/
expiry timestamps; decrypting must verify that context against the owning key
record before any use. Random96-bit nonce and full128-bit tag, no deterministic
nonce, compression or new cryptographic protocol. Exact storage adapter and key
rotation/error handling require implementation tests and security review before
adoption. No secret/binding is created by this document.

Only ciphertext/nonce/key-version plus minimal validated metadata are persisted;
no plaintext receipt, extracted token/client-hash/risk metric, raw attestation,
request body, destination or HA credentials. Metadata: policy revision,
receipt creation time and verified type; key record already owns public key,
app/environment and deadlines. Do not add a separate receipt digest index or
permanent device correlation table. Field5 token is treated as sensitive even
though it is not an HA/Profile/Session bearer. Bound raw receipt to16KiB.

Registration and receipt persistence must be one local atomic decision. A key
cannot become active with missing/invalid encryption material, failed write or
unverified receipt. Crash before commit produces no active record. Postcommit
retry returns only the existing finite enrollment result, never receipt bytes or
new expiry. Unknown outcome follows existing bounded recover-key policy.

Revocation/delete/key expiry removes receipt ciphertext, nonce, key version and
receipt metadata together with public key/counter. Tombstone contains only the
already-defined key address/status/original expiry/purge_at; no receipt residue.
Existing alarm/deadline/overdue cleanup incident policy and provider-backup
qualification apply. This promises application-state deletion, not instantaneous
physical deletion from provider backups or removal of a device's hardware key.

## Fraud refresh and revocation remain separate

No Apple fraud-metric request, receipt exchange, risk scoring, APNs/DeviceCheck
credential use or automatic refresh is selected or authorized. Stored initial
receipt is not interpreted as a continuing fraud metric. Any future refresh is a
new reviewed privacy/operational scope, not implicit permission from retention.
Monthly key cadence remains an Apple-owned practicality/throttling qualification
gate; retaining receipts does not prove it safe or appropriate.

Certificate revocation availability is **NOT_QUALIFIED**. Before runtime
admission an independent security decision must define the exact supported
Apple chains/status source, freshness/cache bounds, outage/failure behavior and
operator root/policy revocation. Neither no-fetch qualification nor a library's
OCSP authorization fix is evidence of good certificate status. This candidate
does not silently choose soft-fail or authorize bypass when status is unknown.
Until that decision and CMS path tests exist, public enrollment remains disabled.

## Qualification obligations

Test actual CMS signer path/signature/content, wrong app/key/type, stale/future,
field duplicates/malformed ASN.1/trailing content, signed attributes and signer
confusion. Test expired/revoked/unknown-status certificates and status-source
outage against the reviewed policy. Storage tests must show ciphertext transplant
rejection, wrong/missing key and write/decrypt failure, atomic commit/crash,
original expiry at equality, revoke/expire deletion and retained minimal tombstone,
rotation/rollback and cleanup failures. No test is claimed PASS here.

Primary Apple requirements freshly retrieved2026-10-17:
[server verification](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server),
[receipt verification/fraud risk](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk).
This policy proposes bounded retention rather than permanent receipt history;
independent privacy/security review and actual runtime evidence remain required.

Independent supplied-policy technical/security and UX/privacy reviews returned
GO for this bounded storage/retention proposal, no P1/P2 in supplied scope. They
did not execute code or inspect fixtures. CMS/revocation/encryption-key operations
and storage lifecycle implementation/tests remain the gates listed above; this
is not implementation approval or a fully resolved receipt production policy.

[Local CMS qualification](WORKER_RECEIPT_QUALIFICATION_V1.md) now executes83/44
actual workerd cases for the measured sandbox signer/fields and archived Apple
receipts. This diagnostic stage explicitly leaves revocation unchecked and grants
no enrollment/storage permission; the production gates above remain required.

[Local storage qualification](WORKER_STORAGE_QUALIFICATION_V1.md) now adds39
actual SQLite DO cases plus isolated types. Review cleanupP2 corrected with
confirmed alarm before sensitive commit; scoped storage GO, not provider
monitoring/backup/production-secret qualification. [Status policy candidate](REVOCATION_POLICY_CANDIDATE_V1.md)
now has corrected scoped design GO; actual OCSP/cache/propagation remains open.
