# Rendezvous implementation contract1

Release ID **djc-rendezvous/1-implementation.1**, wire **djc-rendezvous/1**.
This record is a REVIEW_CANDIDATE outside protected main. It becomes
**IMPLEMENTATION_CONTRACT_RELEASED** ONLY when this exact record is delivered on
protected main through the existing review/CI/authorization gates and the API
publishes the exact-main producer receipt. A draft PR, local commit or green
candidate alone is not delivered release. No tag/product version/live deployment
is created by this source/wire contract record.

[Machine record](implementation-contract-release-v1.json) pins supplying source
**aef408686f485e02b6f5082d69d1fe31bd62f289**, qualification sourcecf749619,
66executed source/input hashes and13contract/root/library/schema hashes to
immutable Git blobs. New delivery commit/main pins and final independent release
reviews/CI belong in API90/PR96 receipts; they must not be inferred from this file.
The implementation interface is fixed by this record; the underlying historical
source-profile name0.4.0-draft and selected recovery ID suffix-draft are retained
for exact provenance, not an invitation to change the released interface.

## Scope, precedence and closed decisions

This releases source/wire agreements FOR IMPLEMENTATION by the existing API,
Apple, Core and receiver owners under their own admissions. It does NOT authorize
public/runtime enablement, Cloudflare writes, deployment, real-device/key traffic,
consumer activation or a new writer. Existing receiver adapter must remain gated
on actual qualified service/configuration and its own protected adoption. This
is not a new API backend or a stronger authentication claim.

Normative precedence for this limited release:

1. Exact closed schemas and byte examples at the machine record's source pin
   define messages, field sets/versions and canonical input limits. No additional
   field, query, endpoint, idempotency or recovery lookup is selected.
2. This record's explicit current policy/lifecycle/authority selection governs
   semantics and STATUS for implementation, superseding old provisional/HOLD/
   NOT_FROZEN/admission sketches to the precisely enumerated extent below.
3. Pinned WIRE_PROFILE,KEY_STATE,ENROLLMENT_RECOVERY,INITIAL_RECEIPT_POLICY and
   LEAF_AKI_POLICY define unchanged details. Historical feasibility/qualification
   documents retain their original dates/pins/scopes, not current missing-ACK
   declarations. An unenumerated contradiction fails closed and requires an
   exact versioned correction, never a permissive consumer workaround.

The prior NEW receiver exception review is **CLOSED/RECEIVED**, not a current
blocker: [exact ACK6270491529](https://github.com/pcvantol/djconnect-api/pull/96#issuecomment-6270491529)
and [owning register6270497278](https://github.com/pcvantol/djconnect-vibecast-receiver/issues/16#issuecomment-6270497278)
confirm both independent consumer reviewers accept exact proposalff9ff5778,
SHA25642159308b8d5c23ccc013775f1a265d2d3af9da35d3aa4139780fcf9f7faf40c
and qualification955ab367. Those exact proposal/reference bytes are unchanged in
the source pin. No repeat receiver ACK/capture/crossrun is required by this record.

[Apple6231637013](https://github.com/pcvantol/djconnect-app/issues/87#issuecomment-6231637013)
already ACKs exact-byte/action-separated120s recovery, coalescing, persistedmax2
explicit attempts>=60s,24h replacement/day27-day30 and serializeduint32assertions.
This closes the generic policy-design question for IMPLEMENTATION. Actual monthly
cadence practicality/throttling/fraud implications and genuine SDK behavior remain
mandatory owning-native/product-enablement gates, exactly as KEY/RECOVERY warn;
this record does not erase, waive or claim that evidence. Source interface choice
is not production Apple policy validation. Existing app-bound diagnostics remain
delivered; no unchanged key-generation/capture loop is requested.

## Selected implementation behavior

- Accepted limited-A: genuine-app reported selected pairedHA route. API does NOT
  attest HA-owner/pairing or that a copiedQR belongs to the scanner's intendedTV.
  Core6e560061 raw/publicHTTPS route/context policy and existing separate B-screen
  admission remain. No extraTV/OOB/PAKE/login/manualIP, centralHA fetch, credentials,
  Profile/Sessionbearers, DJsession management/grant or screen-triggered sessionend.
- Original transaction120s,2000ms minimum pollhint/60poll limit. Independent browser
  ephemeral RSA-OAEP-256/A256GCM JOSE with authenticated exact transaction/generation/
  thumbprint/expiry/origin context; actual positive/negative vectors/libraries are
  pinned in the source profile/proofs, no custom cryptographic protocol. Native
  action-separated exact saved clientData/P256AppAttest follows pinned schemas.
- Cryptographically random QR/claim/challenges, browser/generation/capability
  binding, atomic one-winner submit and one consume/cancel. Lost consume never
  redelivers; a historical202 is not fresh admission or a delivered screen.
- Request policy/2 ALL recognized methods inclOPTIONS spend canonical route lane:
  IPminute256poll/16create/64native/16consume+cancel, total352. Globalhard10kminute/
  1mday with regular9k/900k and reserved terminal headroom. Existing5create/IPminute,
  10ktransaction/day,500registrationATTEMPTS/day,50kkeycalls/day/cardinality preserved.
  Four issuanceATTEMPTS/transaction across all keys/digests; downstream failure
  counts/no refund. Proofslots28submit/2recover/2delete with immutable receipts.
  No old120total/20native or3spoll example is the effective current admission rule.
- Same appkey counters are globally monotone, not one counter perTV. Full
  sign→submit sequence must serialize perkey. Exact retry receipts do not advance
  twice. Recovery/registration keep original deadlines/keyexpiry, generic401 does
  not authorize newkey or freshQR. Finite120smanagement/exactbytes/30daykeyexpiry,
  foregroundday27eligibility and boundedrepair/replacement/twohandle semantics
  stay precisely selected; no indefinite retention or newdeviceidentity index.
- Missing/malformed active receipt config503 before guarded precommit; healthy
  badproof401. Strict origin/CORS/payload/HTTPS destination policy and no central
  redirect/fetch; privacy-safe bounded diagnostics with no tokens/destinations.
  Full provider/internal taxonomy and platform retention remain operational work.

### Selected pre-QR exception and receiver obligations

Select exact recovery **djc-pre-qr-replacement/1-draft** for IMPLEMENTATION under
this release. It is ONE replacement only in retained foreground context before
ANY accepted validated201/QR exposure: fresh independent nonextractable RSA,
32byte claim, single generation increment, max2POSTstarts,5sprep/10ssentattempt/
30sinteraction. Fence old epoch/attempt/phase BEFORE best-effort abort/reference
disposal. Unknown original allocation can commit late and keeps unknown original
server lifecycle: no guessed expiry/cancellation/idempotency/memory-erasure claim.
Any known non201 at headers, including late429/503, is terminal BEFORE body and
per-attemptdeadline; complete malformed/context-invalid201 stops. No thirdcreate,
newQR/key loop or quota refund. Both allocations charge existing limits.

Receiver adoption MUST guard EVERY async keygen/fetch/headers/body/validation/
render continuation and foreground effect. Wire generation, controller epoch and
attempt identity are distinct. Exposure is sticky BEFORE QR data/render/
accessibility/share callbacks; thrown/partial rendering never restores eligibility.
Hidden/unload/contextloss is terminal and becoming visible does not replenish
allowance. Existing create-catch→recovering→reconnect→start, online reconnect and
persisted pageshow/BFCache start must not reset or create repeated batches.
After any accepted201/exposure, ordinary original-expiry/poll/consume/cancel rules
exclusively apply; no postQR/reload/lostconsume/uncertaincancel exception.
Replacement failure ends finitely in existing five-language unavailableUX, no
extra userstep or false cancelled/expired/connected claim. Actual receiver/browser
adoption and presentation/disposal tests remain REQUIRED before activation; API
reference has no fetch/timer/keygen/render/event/disposal implementation.

## Evidence and unclosed activation gates

Current1208localworkerd+strictTypes,66sourcepins,96unique observationreceipts;
shared24assertiontargets=22deliverycases/58consumes+2expected expiryrefusals.
Existing54capacitytargets/126fixtureTVconsumes and6preQRcases are separate.
SoftwareP256/enrollment/controlledtime/loopbackCORS are not genuine freshnative,
provider/publicedge/load/SLA/browserloss/disposal/physicalTV proof. Independent
full protocol audit and source/test/privacy/UX reviews permit this bounded source
release; exact final record review/CI/protected delivery must still be received.

All22 operational preparation gates remain OPEN/null/false, including actual
public router/bindings/secret/config provenance, account/plan/WAF/edge budgets,
full provider/status/error taxonomy, genuine supported signed native, monthlykey
practicality, HA/proxy reachability/separate B, physicaldevices, load/latency/SQL/
cost, platform retention/logging/backups/cleanup, immutableproductartifact,
separate Finalization and exactcentralmanifest/deploymentauthorization/rollback/
livesmoke. Existing sharp advisory39 is unresolved. No source-contract release
closes them or proves product readiness. The current verifier implementation and genuine diagnostic evidence are development-environment scoped; production app/attestation/environment configuration must be explicitly qualified before activation, never inferred from these development fixtures. No production deployment command is
part of this record. Timer remainsOFF; all other lane WIP/writers preserved.
