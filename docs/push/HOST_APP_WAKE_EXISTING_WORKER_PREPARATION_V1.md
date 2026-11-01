# Host app wake on the existing Worker

This change prepares the existing `djconnect-api` Worker and its `DB` binding. It does not create another hosting service or require a container. The central Worker's compatibility date stays `2026-06-20`; the separately qualified portable library uses `2026-08-22`.

## Concrete target and current state

The existing account is `efe77cadf8317a53832fca0848e3ae51`. The Worker is `djconnect-api`, with custom domain `api.djconnect.dev`. Binding `DB` selects `djconnect_api`, database ID `476a564f-08b2-4966-83b0-1221e2a4d063`. The read-only metadata observation on 2026-11-01 found `install_tokens` and no `host_wake_%` or `host_app_wake_%` tables; it reported zero rows written. This is an observation to recheck before any migration, not an ongoing account guarantee. No installation token values, private keys or credentials were read for that inspection.

`src/index.ts` calls `src/host-wake-receiving/dispatch.ts` synchronously before unrelated awaits. The source now selects the private `/v1/push/host-app-wake` receiving mount. Environment variables and caller DATA cannot select or bypass it. Existing principal/custodian authentication, saved original/native policy, original request windows and database guards remain required. Missing database configuration returns503; missing private identities or authentication reject before body allocation. The HMAC operator grammar is checked before reading its bounded body. Other namespaces, including the compiled-off public rendezvous service, continue through the existing root. This source selection is not a performed deployment, native policy or positive enrollment.

The receiving factory now accepts an optional server-side observation tied to the exact original Request object. It retains the original 30-second window, uses only the remaining abort-timer duration, rejects clock regression, and cannot transfer the observation to another Request or reuse it. Later clock observations remain current. This is timing plumbing, not cross-component clock or native admission.

## Additive D1 preparation

Before any change, recheck the exact Worker/account/database binding and actual schema definitions, retain the original metadata and a recoverable database backup, and compare existing installation identity columns without exporting token values. An existing object with a different definition must stop preparation; `IF NOT EXISTS` alone is not a compatibility check.

The numbered migration0011 adds its two hash-only authorization tables and must be explicitly included in the reviewed pending set. It is separate from the nine host-wake files below; a generic migration-folder apply is not evidence that the new scope was approved. The reviewed host-wake schema order is:

1. Preserve the actual `install_tokens` table and existing identity. The package's `existing-install-tokens.sql` is reference material only and must never recreate it.
2. Add the unchanged `coordinator/host-app-wake/schema.sql` tables for Source181.
3. Add `coordinator/host-app-wake-receiving/schema.sql` receiving tables.
4. Add `eligibility-view.sql`, then the six code-pinned guards: `issuer-guard.sql`, `registration-guard.sql`, `dispatch-guard.sql`, `native-first-job-guard.sql`, `native-key-insert-guard.sql`, and `native-first-proof-guard.sql` from the receiving directory.
5. Read back the actual view and all six trigger definitions and compare them against `guard-schema.ts`. Retain exact applied source hashes and original D1 results. The runtime refuses positive work when those guards are absent or changed.

These files remain source-only; this change does not add an auto-applied migration or execute remote SQL. Do not drop existing tables for rollback. Keep the source mount closed if verification fails; retain negative withdrawal/history fences rather than reopening or recovering a capability.

## Concrete admission inputs still required

The concrete controlled run must name its actually selected physical iOS/iPadOS host and signed artifact from the current owner/Apple receipts. Historical iPad or iPhone build labels do not select a new run. Apple owns the actual device identity, signed build, app/team/environment/entitlement facts, SDK key identifier and evidence. None are inferred from a simulator, an old Mac build or synthetic test records.

Core must supply its actual existing installation principal and selected original child, with the receiving contract's retained identity, generation, revision and deadlines. The API custodian must bind the one-time operator/native policy to those facts and the signed iPad build. Use the existing HMAC-only custodian channel, never a shared-secret Bearer fallback, a fabricated operator tuple or a new installation identity. Public/private keys and token encryption remain under their existing custody; no secret value belongs in this document or a source PR.

Current platform UTC observation does not itself establish the retained Core/Apple clock relationship. The original bounds must be checked in the actual caller chain. Status freshness, native enrollment, token registration and APNs delivery remain distinct results. The exact original-request window cannot be renewed after expiry.

The source capacity is bounded at 256 entries in the central composition, within the receiving factory's 1..4096 range. Existing per-original operation/wake limits and the reserved negative-close capacity remain owning. Do not increase capacity or retention to work around a denied registration.

## Controlled execution order

After exact source review and protected delivery, qualify the actual Worker artifact and deployment configuration against this existing target. The existing deployment workflow also applies numbered migrations: fresh read-only inventory must permit exactly the explicitly reviewed pending0011 addition, followed by the separate nine-file host-wake schema operation and exact readback; unknown pending work stops execution. The previous old94 deployment manifest grants none of these new changes. Prepare and review the additive schema operation separately before applying it. Obtain the original Core/iPad/custodian inputs, qualify the actual clock and genuine native flow, and independently review this exact private-mount source. No concrete custodian/category/key/installation tuple is supplied by the source. Neither green synthetic tests nor an environment flag can authorize that source change.

Then deploy the exact qualified artifact through the existing deployment flow, retain its version/deployment IDs and configuration receipt, and read back the private/public denial boundaries before any controlled positive registration. Use one selected original iPad/Core child and preserve all original deadlines. A successful SDK attestation is not a successful push: separately verify registration, bounded provider submission, device receipt and withdrawal. Stop and close the child on unknown or expired authority; do not mint replacement UUIDs or extend the lease to complete a test.
