# Joint ASN.1 / PKI major-version maintenance

This corrects the existing ASN1.js4 dependency PR148 against protected API main
94a2dc6. Its original graph pairs application ASN1.js4 with PKI.js3.4.2 and a
nested ASN1.js3. Valid KeyUsage and SubjectKeyIdentifier extensions then fail
the existing CMS class-identity predicates. The paired local counterproof uses
the same synthetic extension bytes and unchanged predicates: both fail in that
original mixed graph and pass with ASN1.js4.0.0 plus PKI.js4.0.0.

The [ASN1.js migration notes](https://github.com/PeculiarVentures/ASN1.js#breaking-changes-in-v4)
require application and PKI classes to share an ASN.1 major. The
[official PKI.js4 release](https://github.com/PeculiarVentures/PKI.js/releases/tag/v4.0.0)
declares ASN1.js4 as a peer dependency. Both packages are ESM-only with a
supported Node requirement of `^20.19.0 || >=22.12.0`; local Node26 and CI26
satisfy it. No forced peer override or certificate predicate change is used.

Active shared/challenge starters resolve each package's public export instead
of its removed `build/index.es.js` path. Historical starters retain their own
versioned evidence. The current product verifier and local native source guard
consume new observations; historical proof records are byte-preserved.

Official npm archives for the five changed runtime packages match their lock
SHA512 integrities and every installed archive member. New provenance3 records
the seven current runtime packages and exact archive hashes. It claims package
artifact matching, not reproducibility of upstream source builds. Current
licence texts are copied from the actual packages without changing their text.
Dependency installation uses `--ignore-scripts`; install-script permissions,
Worker configuration, migrations, app policy and native profiles are unchanged.

The immutable106-input baseline is retained. An explicit27-path cumulative
delta derives117 current tracked inputs. All original32 installed inputs remain
accounted for:18 removed paths and36 additions produce50 current installed
inputs, while14 retained inputs have identical hashes. Every addition/removal
is independently named and hash-bound; unlisted, restored-removed and forged
original inputs are rejected. Authority-reference changes remain separately
limited to the exact two licence documents.

Actual local results include238 API tests (nine new dependency-boundary cases),
strict root types,49 composition tests/types,1571 shared crypto/state tests/types
and1365 challenge tests/types. The fixed closed QA derivative passes1591
cases and strict types. The real compiled product passes128 checks,
including100 forbidden RPC denials with zero egress. New cases check original
extension class identity, application-to-PKI schema compatibility and v4's
stricter integer/time/wide-string boundaries. The cryptographic verifier source
and all acceptance predicates remain unchanged. Further exact committed checks,
independent reviews, candidate CI, protected source, original own-main evidence
and separate Finalization must be recorded as actual results, never predicted.

The initial shared attempt stopped during preparation because its former
temporary JOSE input had been removed; no tests ran in that attempt. The fixed
input is the exact80-file original JOSE6.2.12 manifest, independently matched to
the official archive. The new complete shared run is the qualification above;
the preparation failure remains preserved. Earlier dependency and CI failures
are not relabeled as passing.

Public surface dispatch remains compiled off, Activity profiles remain empty
and all22 full-service activation gates remain open. This maintenance grants no
custody/enrollment/provider/native/device or deployment effect. API94 production
and its previous exact deployment/smoke receipts retain their own source scope.
