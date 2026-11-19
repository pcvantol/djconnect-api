# Local HTTP-to-state composition qualification

Profile `0.4.0-draft`, wire `djc-rendezvous/1`, **NOT_FROZEN**. This continues
sole API writer PR96 from e5723d4; main e67f402. Resume ACK:
https://github.com/pcvantol/djconnect-api/issues/90#issuecomment-6255070309.
The Shared Data checkout and original evidence hashes were verified after the
storage migration; unchanged490-case baseline was rerun successfully. Pinned
PKI/JOSE dependencies were restored only into isolated temporary storage.

## Implemented boundary

[Composition factory](../../qualification/rendezvous/composed-http.ts) joins the
existing eleven-route ingress to the immutable allocation index, transaction
state and budgeted key router. It explicitly translates wire snake_case fields
and private RPC input/output. Closed canonical response schemas remain final
egress checks. Private counters, receipts, policy and authorization fields are
never projected into public-shaped responses. Exceptions are fixed redacted503.
Malformed backend deadlines yield503; valid elapsed/equality deadlines yield410.
The underlying verifier can still conflate provider faults with proof rejection;
complete provider-error taxonomy is NOT qualified by this composition.

Create returns the already-required top-level browser_key_thumbprint and QR
object, verifies the closed QR against the computed JWK thumbprint and original
index descriptor, and never trusts a caller allocation/expiry. The abbreviated
WIRE_PROFILE response table does not replace canonical JSON schemas. No wire
field was added. Inspect verifies scan capabilities before submit-challenge
binds the exact transaction ID, generation, thumbprint, envelope digest and
original expiry. Existing child issuance uses that exact expiry without clamping.
Expiry is checked after the key await; concurrent cancel remains enforced by
final submit. Challenge issuance does not reserve a winner.

Browser poll/consume/cancel and native enrollment/challenge/submit/recover/delete
all select explicit private methods. The new BudgetedTransactionCoordinator
constructor supplies keyRoutedAuthorizer, closing the old private adapter bypass
for selected composed submits. TransactionCoordinator's new optional trusted
constructor argument preserves its old default; no state predicate, counter or
lease is weakened. Old QA-only namespaces remain separate. No request can select
these constructors, a software verifier, namespace, method or policy.

Trusted identity is a constructor callback, resolved/copied per invocation only
for create/register. Existing allocation and key adapters own each charge; ingress
does not charge twice. Parallel requests do not share identity state. Actual edge
IP provenance, per-IP controls on all other routes/challenges/invalid attempts,
WAF and complete request-cost containment remain API work. Proposed caps remain
10,000 transactions/day,5 allocations/IP/minute,500 registration ATTEMPTS/day and
50,000 key calls/day, subject to joint operational review. They are not provider
quotas, approved costs or load qualification. No deadline/key auto-renewal or new
QR on an uncertain create result is introduced.

## Executed evidence and review corrections

[Source-bound observations](workerd-composed-http-observations-v1.json) record
**746/746 actual local workerd tests, isolated strict TypeScript and exit0 PASS**:
37 new HTTP composition tests plus709 unique prior tests (490 key/index/state/
budget/crypto tests plus219 ingress cases). The46 shared budget tests count once.
Existing API40/40, root TypeScript and offline projection also pass.

A complete local Request/Response flow creates QR state, polls, inspects, enrolls,
issues a bound challenge, signs a real P256 assertion, submits an actual JOSE
RSA-OAEP-256/A256GCM envelope, polls ready and consumes exactly once. The test
decrypts with a nonextractable ephemeral browser private key and compares exact
plaintext context. Initial App Attest enrollment is explicitly SOFTWARE evidence;
subsequent cryptographic assertions and JOSE operations are real implementations.
This is not a genuine signed-iOS enrollment or HA/physical acceptance result.

Tests cover races, consume/replay, cancellation, expiry/restart/purge, unknown IDs
before child access, saved binding bytes, known/unknown management coalescing,
same-key recovery/revocation, historical retries, budget exhaustion, no double
charges, concurrent identity isolation, malformed backend QR/expiry, private egress
stripping, wrong Origin and disabled policy. Test fault injection uses trusted
constructor seams only, never request-controlled verifier switches.

Run a FAILED:738 passed/1 failed: its positive fixture used the wrong JWE typ. The fixture
was corrected to existing `djc-rendezvous-destination+jwe`; no verifier predicate
was relaxed. Run b passed739/739. Independent security source review then found
P2: malformed backend deadlines incorrectly produced expired410. Structural503
validation and seven malformed/elapsed/equality tests correct this in final run c.
Failed-run history is retained here rather than overwritten by a success claim.
Independent security and UX source/document reviews are registered on API90/PR96;
supplied-source review does not imply independent Git/hash checks or test execution.

Reproduce using pinned cbor10.0.12/PKIJS3.4.1/ASN1js3.1.0 and JOSE6.2.12:

```sh
node qualification/rendezvous/run_composed_http_workerd.mjs /private/tmp/pinned-pki-deps /private/tmp/new-http-composition-results /private/tmp/pinned-jose-package
```

The runner hashes source, canonical schemas, public Apple trust roots and tools;
uses ten temporary SQLite bindings/classes with local-only migrations; denies
fetch and telemetry; records output0700/files0600. Sanitized committed evidence
contains test names, versions and hashes, no proofs, keys, user IPs or destinations.

## Delivery, operations and remaining owners

Default harness HTTP remains503 even when local DO policy is set; missing trusted
identity resolver also fails closed. No product route/binding, root Wrangler
configuration, dependency, D1/APNs/pairing, secret, consumer code or Cloudflare
resource changed. Rendezvous does not fetch/decrypt destinations centrally,
authenticate an HA owner, grant screen/session access or store HA/Profile/Session
credentials. Destination HTTPS/context checks remain consumer-owned under the
existing contract; a locally decrypted fixture does not prove a reachable HA route.

Public routing and verified edge identity, complete abuse coverage, provider fault
classification, configured-provider/full service proof, deployment manifest,
cleanup/retention/backups monitoring, numerical capacity/cost and rollback smoke
qualification remain OPEN. No product binding changed, so root type regeneration
is unnecessary. This local increment rolls back by reviewed source revert; no
provider rollback exists. Future deployed rollback must preserve compatible state
cleanup and original expiries.

Joint exact contract/security freeze is still required. Apple owns fresh supported
signed-iOS nonce/actions/genuine composed positive; its original capture/ACK is
delivered. Receiver's exact-generator crossrun is delivered, no unchanged repeat.
Core owns the real HA/proxy destination and separate screen admission. Real
HA/iPhone/TV acceptance and separately authorized production deployment remain
outstanding. Source review, CI or merge closes neither the function nor those gates.
