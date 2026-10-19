# Complete distribution notices

Bounded API-owned packaging correction from protected main
`1463b3293badfdc8ad2610ebe82ee9366b62234b`, assignment
`DJC-API-VIBECAST-RENDEZVOUS-V1-20261016`. The actual PR99 artifact readback
confirmed five compiled private DOs and the disabled root, but also confirmed the
archive omitted the full licence documents retained in the source repository.
Bundler legal comments alone do not carry all nine complete dependency notices.

The existing artifact workflow now copies `LICENSE`, `THIRD_PARTY_NOTICES.md` and
`docs/rendezvous/THIRD_PARTY_LICENSES_V1.md` under their corresponding release
paths. `release/LICENSES.sha256` records their exact bytes and is checked before
creating the tarball. The existing outer archive digest binds these documents and
the sidecar together; no artifact-evidence schema or deployment gate changes.
This is distribution attribution, not independent legal certification.

The maintained licence document contains the complete unmodified texts for
`cbor`10.0.12, `asn1js`3.1.0, `pkijs`3.4.1, `bytestreamjs`2.0.1, `pvutils`1.2.0,
`pvtsutils`1.3.6, `@noble/hashes`1.8.0, `nofilter`3.1.0 and `tslib`2.8.1.
No dependency, Worker code, binding, migration, secret, wire contract or public
entrypoint changes. Existing deployment extracts the release archive; no content
allowlist is bypassed or broadened by this change. No deployment is executed.

Local verification packages the actual PR99 main-built Worker with the unchanged
migrations/package/config plus these sidecars, verifies the internal checksums and
all three document bytes, checks all nine licence headings, and confirms the
Worker's main stamp/hash are unchanged. Exact-source independent reviews, normal
candidate/main CI and actual new main archive readback are separate required
delivery evidence; local packaging does not substitute for them.

Rollback is a protected source revert of the packaging lines; no runtime or DO
state changes. The nine-package attribution requirement must still be satisfied
by any subsequent distribution. The complete rendezvous assignment, API trusted
edge/HTTP integration and separate Finalization remain OPEN. Timer OFF; native,
HA/screen/TV acceptance and deployment authorization are unchanged.
