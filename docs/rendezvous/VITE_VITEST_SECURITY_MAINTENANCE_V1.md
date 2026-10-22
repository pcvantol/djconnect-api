# Vite and Vitest development dependency maintenance

This separate source increment starts from protected main
`9ab24315a10b569b84e738d09bf32df6da12e38b`. It updates the development
toolchain associated with GitHub Dependabot alerts40–47: locked Vite8.3.1
becomes8.3.5; Vitest and coverage-istanbul4.1.11 become4.1.12, including
the corresponding mocker4.1.12. The two direct Vitest declarations retain
their existing tilde range shape. No new direct Vite dependency, override,
installation-script permission or Cloudflare pool migration is introduced.

The thirty changed lock entries include root metadata, aligned Vitest packages,
Vite and its required Rolldown/platform bindings, Oxc types, PostCSS and nanoid
development dependencies. Chai remains6.2.2. Every non-development lock entry
is deep-equal to the protected base; cbor10.0.12, pkijs3.4.1, asn1js3.1.0,
sharp0.35.5 and undici7.29.1 retain their previous resolutions. The selected
Vite/Vitest/mocker/coverage integrity fields were compared with actual official
npm registry version metadata. A clean `npm ci --ignore-scripts --no-audit
--no-fund` installed the graph; `npm ls` confirms aligned peers. The initial
lock solve warned against the previous installed Vitest; the clean graph has
no peer errors. The existing pool deprecation warning is retained, not treated
as a reason to migrate this patch.

This addresses development-server and test-tool vulnerabilities; absence from
the deployed import graph does not make their local attack surfaces irrelevant.
The actual npm audit of the new graph reports zero vulnerabilities. GitHub
alert closure is a separate protected-main readback, not inferred from a local
audit. Existing bot PR117 and its branch are preserved until replacement
delivery is verified; its older whole lockfile is not copied onto this base.

Actual local qualification completed before this record: root TypeScript,
78 API/coverage tests,49 composition tests and strict composition types;
128 product checks,100 forbidden private RPCs rejected and zero egress or
activation. The full QA derivative passed1578 software workerd cases with
zero failures/skips and strict types, including20 fixed-profile controls.
The clean committed QA artifact check is recorded separately with its actual
outcome. Independent
security and UX reviews, protected delivery and actual own-main artifact and
formal evidence remain required; this document is not their receipt.

Runtime source, bindings, migrations, configuration, five-language translations
(en/nl/de/fr/es), licenses and consumer contracts are unchanged. Actual built
Worker comparison is required in delivery evidence. No provider deployment,
DNS, namespace, credential, native/device/SDK/Keychain, HA or publication effect
is included. The fixed QA guard stays false, current Apple profile and
operational admission stay null; the historical40408 window remains expired.
All22 full-service gates remain OPEN and the original automation stays PAUSED.
