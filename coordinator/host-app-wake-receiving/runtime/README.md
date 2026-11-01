# Portable private receiving package

This builds the reviewed receiving factory into a portable Cloudflare-compatible ESM module. The only exports are `createReceivingService` and a public default handler that always returns 503. The factory requires explicit D1, original clock, transport and capacity ports; the package creates no operator, native enrollment, service binding, schema or public admission.

The explicit source-maintenance command `node coordinator/host-app-wake-receiving/runtime/pin-inputs.mjs` updates pins for review. The builder never invokes it. Source, installed dependencies, the complete compiled input graph, compatibility date/flags, seven SQL object code pins and the export allowlist are checked before a package is accepted. The selected production imports `prepareCommonStatusRequest` and `qualifyCommonStatus` originate in the protected `qualification/rendezvous/receipt-status-candidate.mjs`; that path is not a vendor-model substitution. The isolated modeled enroller tests never enter this graph.

Build into a new absolute directory outside the checkout:

```sh
node coordinator/host-app-wake-receiving/runtime/build-package.mjs "$DJC_PACKAGE_OUTPUT" > "$DJC_BUILD_RESULT"
```

The result identifies the `package/` directory, proof digest and module digest. A trusted externally retained proof digest is mandatory when checking a package; a package's own editable JSON is insufficient:

```sh
node coordinator/host-app-wake-receiving/runtime/check-package.mjs "$DJC_PACKAGE" "$DJC_PROOF_SHA256"
node coordinator/host-app-wake-receiving/runtime/check-negative.mjs "$DJC_PACKAGE" "$DJC_PROOF_SHA256" "$DJC_NEGATIVE_REPORT"
node coordinator/host-app-wake-receiving/runtime/check-integrity.mjs "$DJC_PACKAGE" "$DJC_PROOF_SHA256" "$DJC_NEW_CORRUPTION_OUTPUT"
DJC_HOST_WAKE_PACKAGE="$DJC_PACKAGE" DJC_HOST_WAKE_PACKAGE_PROOF="$DJC_PROOF_SHA256" node_modules/.bin/vitest run --config coordinator/host-app-wake-receiving/qualification/vitest.packaged.config.mts
```

Only the fixed allowlist of module, normalized metafile, source manifest, source-only schemas/contracts and actual bundled license texts is delivered. Sourcemaps, build logs, native tool binaries and host-absolute metadata are excluded. The proof records the actual platform/toolchain and locked native esbuild binary hash. Linux and macOS builds keep platform evidence distinct. `package-proof.json` is an artifact-integrity record, never native or operator authority.

The packaged qualification reuses the ordinary receiving HTTP/SQL suite with its service import bound to the delivered factory. An explicit identity test verifies that this is the same factory as the shipped module; additional cases verify the closed public entry. The original modeled vendor-result suite remains a separate source process. The packaged HTTP suite includes synthetic prior key/operator authority where explicitly labeled; no genuine positive Apple attestation, signing, cross-domain clock or provider/device acceptance is inferred.

Current local qualification has 315 packaged cases, 53 additional workerd negative checks and four artifact-integrity controls. Those retain separate reports and scopes. A changed module, a self-authored replacement proof, an extra file and a missing external proof root are rejected. Each package contains the exact reviewed view/six guards and their code-pin joins, plus schema sources for the receiving layer, Source181 and the existing install-token prerequisite. These are source only: do not automatically apply them or recreate an installation identity.

Production composition must use actual current custodian/installation state, signed iPad host and native policy, the genuine original clock/HTTPS suppliers and separately reviewed existing-D1 provisioning. A deployment configuration switch cannot substitute for those inputs. The separate production-prefix adapter reserves the namespace while its source mount remains disabled; physical provisioning, activation and device/key actions require their concrete reviewed target and original lifetime. The runtime package itself performs none of those actions.


The production caller is qualified separately at the existing central Worker's compatibility date, `2026-06-20`; the portable library's compatibility date remains `2026-08-22`. Neither result is silently promoted across runtime profiles. The private composition passes an optional raw observation bound to the exact original Request; this changes no wire DTO and grants no authority. Every subsequent UTC read remains current. The original capture clips all request windows and abort timers, and cannot be transferred to a different Request, mutated or reused. The central caller invokes the closed prefix dispatcher before unrelated awaits, and no environment variable enables or qualifies it.
