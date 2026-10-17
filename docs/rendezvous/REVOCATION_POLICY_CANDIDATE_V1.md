# Certificate revocation policy candidate v1

Same API94 writer; profile0.4.0-draft, **DESIGN_CANDIDATE / NOT_FROZEN /
NO_RUNTIME_ADMISSION**. This proposes an exact split rather than treating absent
provider status as an implicit production fallback. No provider request policy,
operator config or deployed behavior changes through this document.

## App Attest chain: explicitly offline pinned trust

The two delivered development fixtures' App Attest leaf/intermediate certificates
advertise neither OCSP AIA nor CRL distribution points. This is measured input,
not proof of all future Apple chains. Apple's published server procedure anchors
this chain at its App Attest root; it does not supply a status endpoint for these
measured certificates. Do not invent URLs or send the device's attested leaf,
serial, key ID, challenge, receipt or destination to an arbitrary service.

Proposed supported mode: OFFLINE_PINNED_APP_ATTEST_PROFILE. Require the exact
reviewed Apple root, closed issuer/leaf certificate policy, all signatures,
constraints, validity, nonce/app/key bindings and current active server-policy
revision. This deliberately does not assert live leaf/issuer revocation status.
Unknown/changed chain/profile remains denied pending independent review, never
automatic fallback to weaker validation or a second trusted root.

Operator emergency denial uses the existing protected API configuration/delivery
boundary: disable a root/profile revision and invalidate the corresponding key
policy. A coordinator must check the active policy for every challenge/recovery/
authorization, including previously enrolled keys. Known policy expiry caps
authorization expiry. Unplanned revocation prevents new authorizations once
enforced by that instance; already issued grants may remain usable for their
remaining lifetime, at most5s. End-to-end latency also includes measured
configuration propagation. No instantaneous global revocation is claimed.
The per-key deletion/revocation/tombstone rules remain independently enforced.
No permanent device ban/owner registry or new signing protocol is introduced.
Actual propagation, rollback safety and operator response are release tests;
no instantaneous global CA-revocation or offline device-erasure promise.

This offline trust choice requires explicit independent security-policy review.
If not accepted, the absence of a supported status source is a real contract
blocker, not permission to silently call unknown status good.

## Receipt signer: good authenticated status required before enrollment

The measured receipt signer advertises OCSP at the fixed Apple endpoint
`http://ocsp.apple.com/ocsp03-aaica5g101`. The receipt intermediate advertises
OCSP and `http://crl.apple.com/applerootcag3.crl`. These common signing certificates
are distinct from the private device attestation certificate embedded in payload3.

Proposed mode: RECEIPT_STATUS_HARD_FAIL. Complete the existing CMS/path/field
checks, then verify good OCSP status for the exact signer/issuer CertID using
standard RFC6960 and a reviewed maintained verifier. Verify responder authority,
signature, exact CertID, response success/good and signed times. No caller
`status:good`, unverified HTTP result or unauthenticated cache entry can authorize.
For the intermediate, authenticate the issuer CRL against pinned Apple RootG3,
issuer/AKI, signed validity window and membership. Root trust/denial stays operator
controlled; a root certificate is not declared good merely because absent from
its own CRL. Do not reuse the App Attest missing-AKI exception for receipts.

Proposed status-cache bounds: now>=thisUpdate, producedAt<=now for OCSP,
mandatory nextUpdate>thisUpdate and now<nextUpdate. OCSP thisUpdate at most24h old.
A validated cached result expires at min(signed nextUpdate,checked_at+1h,
thisUpdate+24h for OCSP). Re-fetch may return the same still-valid signed status;
it does not make that status newer. Re-fetching the same CRL hourly cannot
prove status newness of one hour: its authenticated replay/staleness window can
last until the signed nextUpdate, including the measured multi-month window.
That issuer-validity risk is explicit; cache frequency does not shorten it.
CRL issuer validity can be longer than OCSP;
revalidate/fetch at most1h cache lifetime, always before nextUpdate. These are
application review choices, not claims about Apple response cadence or quotas.
Actual signed OCSP compatibility/freshness must be qualified before selection.

Unknown/revoked/expired/future/bad-signature/wrong-issuer or unavailable uncached
status denies new enrollment with the existing service-unavailable boundary.
A prior still-valid authenticated cached result may be used only to its original
deadline. No TTL extension, stale-while-revalidate or permanent allow-on-outage.
Existing App Attest keys retain their original finite key policy; API key/policy
revocation remains separate from checking a new receipt. Fresh enrollment still
needs the original120s challenge and<=5min initial receipt; no fraud refresh,
re-attestation/key-generation loop or revived QR while status is unavailable.

Only fixed reviewed Apple hosts/paths may be fetched by a bounded status adapter;
no URI from a client, HA destination or arbitrary certificate extension is fetched.
No redirect following, credentials or device-specific proof upload. Common signer
status requests are not fraud-metric refresh and carry no HA/user payload.
HTTP status transport requires authenticated signed bodies and replay/time checks;
never apply this exception to the HTTPS-only Home Assistant destination policy.
Timeout, response-size and egress controls require implementation qualification.

## Current source evidence and remaining work

[Public-source observations](apple-status-source-observations-v1.json) record one
read-only CRL probe at the earlier storage checkpoint: advertised HTTP URL returned a CRL with valid signature,
pinned issuer/AKI and current signed validity; measured receipt intermediate
not listed. The same path over HTTPS returned404. This proves neither signer
OCSP status nor App Attest leaf status or runtime availability. No OCSP request,
fraud refresh, private proof upload or Apple credential use was performed at
that checkpoint. A subsequent [status component qualification](WORKER_STATUS_QUALIFICATION_V1.md)
now verifies common signer/intermediate OCSP and issuer CRL under actual local
workerd,68/34 tests, with bounded nonrenewing in-memory cache. Production egress/
cache/propagation and full verifier/admission remain unqualified. Later
[isolated fixed egress](WORKER_STATUS_EGRESS_QUALIFICATION_V1.md) adds101/35
local tests and scoped egress GO, not live adapter/provider proof.

Before runtime: independent policy review, actual OCSP compatibility and negative
status corpus; authenticated cache/outage/expiry/revoked controls, fixed egress;
operator profile-disable/propagation/rollback qualification and complete verifier
composition. Existing diagnostic `REVOCATION_UNCHECKED` helpers remain disabled
for public admission until the selected status decision is actually enforced.

Primary references: [Apple server verification](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server),
[Apple receipt verification](https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk),
[RFC6960 OCSP](https://www.rfc-editor.org/rfc/rfc6960.html).

Independent supplied-policy technical review identified oneP2: already issued
grants may survive an unplanned policy revocation for their remaining<=5s,
plus configuration propagation. The text above now states that bound and the
potentially long signed CRL staleness window. Follow-up review: **scoped policy
GO**, no own source/network/runtime execution; actual status verifier/OCSP/
propagation/operations remain gates. UX/privacy design scoped GO. This does not
freeze the contract or approve runtime admission.
