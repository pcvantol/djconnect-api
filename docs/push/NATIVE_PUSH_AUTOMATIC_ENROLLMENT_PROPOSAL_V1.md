# Automatic native push enrollment proposal

This is a proposed Core, API and Apple contract for HA-dev qualification. The transport must remain closed until the independent pairing witness and exact role-specific native proofs are selected and verified. The API's local admission helper is only a preflight.

## Trust and scope

The normal HA app pairing currently obtains a per-installation `djci_` bearer via `POST /v1/pairing/bootstrap-proof` and `POST /v1/install/token`. The legacy bootstrap route validates request fields and rate limits issuance. It does not verify a signature over the original authorized pairing. A bearer from that path and proof of possession of a new Core key cannot establish the first trusted key for an installation.

First key registration needs an independently trusted pairing witness. API must verify the issuer against a server-owned trust anchor and bind the witness to the exact installation credential, original authorized owner and pairing generation, new Core key thumbprint, challenge nonce, audience and expiry. The trusted issuer and wire for this witness remain open. An install bearer scopes later requests to its installation. It never supplies push consent.

Push defaults to off. One consent coordinate is installation, owner, physical device, pairing generation, channel and consent generation. Target digest, role, public purpose key thumbprint and original deadline are also bound. A different device, role or pairing needs its own consent. The Core signer must represent the actual explicit user action under the current native pairing. Local display, retained content, an OS notification permission, shared settings and pairing alone cannot authorize push. Separate Apple proof binds the exact target where required.

## Native proof by platform

Core's HOST_WAKE_FIRST_KEY_V1 and DIRECT_RICH_HOST_WAKE_PROXY_V1 describe native key custody, original challenges and durable proof acknowledgements. The API's NATIVE_PROOF_TRANSCRIPT codec supplies canonical bytes and digests. It does not verify attestation. The genuine Rendezvous App Attest verifier can be evaluated for supported iPhone and iPad host apps after binding the exact production-equivalent app ID, attestation environment and nonce. The existing verifier qualifies the native app and key. First trust still requires independent proof that the same challenge belongs to the current HA pairing, owner and installation.

Apple reports App Attest unavailable on Mac, including Mac Catalyst and iOS/iPadOS apps running on Apple silicon. The existing Mac widget can only be admitted after a separate independently verified pairing and native target proof is selected. Apple documents support for watchOS extensions starting in watchOS 9, with restrictions on generating keys in an extension. The exact signed Watch target and usable SDK path need their own runtime qualification. Watch Smart Stack also requires the existing signed preference and restore witness for the exact Watch. Missing proof closes the affected role.

Source: [Apple App Attest availability](https://developer.apple.com/documentation/devicecheck/dcappattestservice/issupported).

## Proposed API routes and proof

Use POST for every route below, with the existing per-installation bearer and strict JSON. Route names are proposed and unmounted. Every signed statement binds protocol version, method, path, environment audience, original installation and pairing generation, operation ID and API challenge. Sign using P-256 over the agreed canonical encoding. Return no-store responses. Keep assertions and credentials out of shared logs.

| Route | Request and authority | Result |
| --- | --- | --- |
| `/v1/push/native/key/challenge` | Installation bearer, operation ID, requested key thumbprint and pairing generation. No key is trusted at challenge creation. | A short-lived single-use nonce bound to that original request. |
| `/v1/push/native/key/register` | Challenge plus new key proof of possession and the independent pairing witness above. Replacement additionally requires the active key and expected key revision. | Exact key ID, revision and active status. A changed key or pairing never replaces a prior binding implicitly. |
| `/v1/push/native/enrollment/challenge` | Current installation and registered Core key, operation ID and exact device/channel/role/target coordinate. | Short-lived nonce scoped to the action and original deadline. |
| `/v1/push/native/enrollment/issue` | Current Core-key signature on the explicit original opt-in, challenge and full coordinate. Verify purpose key possession and the separate Apple proof when the role requires it. | One bounded purpose grant using the existing role-specific issuer semantics where applicable. Return a credential only on the original issuance response. |
| `/v1/push/native/enrollment/status` | Current installation and a fresh Core proof for the exact operation and scope. | Original operation outcome and expiry. Never return or mint a credential from status. |
| `/v1/push/native/enrollment/revoke` | Current Core authority signs opt-out or unlink with the expected scope and generation. Revocation does not require the target still to be opted in. | Durable revocation of the scoped grant, capabilities and registrations. Retain tombstones and audit references. |

Commit checks must bind the exact active install credential, key revision, pairing/consent generations, operation, nonce and original deadline to the mutation. A preflight followed by an unguarded write is insufficient. Consume a challenge at most once. Exact idempotent retries return the stored outcome without new credentials or a longer deadline. Conflicting operation ID, scope, target, key or revision returns a conflict. An ambiguous response goes through status. Re-enrollment requires fresh authority and proof. A revoked generation never reopens. Loss of the Core key requires the independently verified recovery path, not a fresh legacy bearer.

Opt-out retires only the selected device/channel. Device unlink retires that device's channels. Owner or installation retirement can retire all grants in its own scope. Dispatch must recheck the same scope immediately before provider handoff and preserve existing provider replay rules.

## Channel-specific reuse and open work

| Channel | Existing API behavior | Still needed |
| --- | --- | --- |
| WidgetKit | Closed `/v1/push/surface/enrollment/redeem`, issuer challenge/issue/status/withdraw and surface register/revoke/event/status. V1 enrollment currently uses a separate operator authorization. | Start here. Connect the independently verified pairing and original opt-in to automatic issuance and the live delegation fence. Preserve exact extension bundle, widget kind, platform and environment. |
| Live Activities | The surface issuer distinguishes `live_activity_start` from `live_activity_update` and validates the iOS/iPadOS content policy. | Admit the exact ActivityKit profile and purpose for start/update. Bind the activity instance where applicable. Keep role-specific credentials and stop handling. |
| Moments in the app | Installation-authenticated legacy `/v1/push/register` and `/v1/push/event`; separate private `/v1/push/host-app-wake` receiver. | Bind the exact committed Moment/publication and recipient. Qualify protected original-Moment read and the actual app delivery contract. |
| Watch Smart Stack | Separate signed Watch preference and restore witness, with source-only Moment send/status/cancel. | Bind the distinct Smart Stack role to the exact Watch and current pairing/incarnation/epoch. Preserve the signed preference path of Core #1439 and prove restore and provider handoff separately. |

HA-dev acceptance begins with a fresh normal HA pairing. Verify default-off, explicit opt-in on the selected physical device, refusal for a different device or role, key replacement and restart, expiry, scoped opt-out and safe re-enrollment. Require actual publication, provider receipt and device rendering separately per supported platform and channel before closing the joint acceptance.
