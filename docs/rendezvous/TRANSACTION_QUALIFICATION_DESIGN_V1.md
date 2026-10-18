# Local transaction qualification design

Profile `0.4.0-draft`, wire `djc-rendezvous/1`, existing API94 writer.
**DESIGN ONLY / NOT_FROZEN / NO_TRANSACTION_IMPLEMENTATION_OR_RUNTIME_GO.**
Registration producer `b191a9fa9cbde01bf3140728fbf40f954c1b4277` has
141/137 local workerd cases plus isolated TypeScript, with software initial
enrollment positives; that evidence does not implement the transaction below.

## State and authority

One SQLite row per server-generated UUIDv4 transaction. Generation is an integer
1..2147483647. The original server deadline is created_at+120000ms; equality is
expired, even with a late alarm. Persist the public browser JWK/thumbprint and
SHA256 commitments of the separate claim and QR capabilities, not the secrets.
Private browser keys remain browser-memory only. The service never fetches HA.

Only a valid submission may commit pending->ready. Browser claim alone authorizes
ready->consumed or pending/ready->cancelled. QR capability grants neither consume
nor cancel. First valid ready commit wins; another scan cannot replace it.
Cancel and consume compete within the same synchronous SQLite transaction.
Erase ciphertext on either terminal transition. Poll returns only status and the
original deadline, never ciphertext. Repeated authenticated cancel is idempotent;
cancel after consume conflicts. A lost consume response cannot redeliver anything.

Keep only capability commitments, original binding/deadline and minimal immutable
operation/request digest after termination, until original expiry. An exact
authenticated-capability retry can acknowledge historical submit acceptance,
including after coordinator revocation, but never report current ready or deliver
ciphertext. Changed proof, operation, bytes or binding cannot recover that receipt.
After original expiry delete all application rows. No request can recreate a
missing transaction. Physical provider erasure/backup retention remains unproven.

## Private coordinator composition

Copy complete input before awaits and calculate the retry digest server-side from
the exact validated request bytes. Do not accept a caller-supplied digest,
`verified` flag, counter grant or bearer authorization. The trusted server-local
coordinator adapter obtains authorization using the saved exact action proof.
Before ready, compare its operation/request digest, transaction, generation,
browser thumbprint, envelope digest and original expiry with the captured flow.

After the final await, synchronously recheck all original commitments/bindings,
pending state, absolute transaction deadline and original authorization deadline
inside the committing SQLite transaction. No await between that check and commit.
The authorization lease is at most5s and capped by key/policy/transaction expiry;
it is never renewed from receipt time. A burned counter does not make ready.
There is no cross-DO atomic transaction: a previously returned authorization may
still win within its bounded lease after key revocation. See
[KEY-STATE](KEY_STATE_V1.md) for this explicit window.

## Parser and infrastructure prerequisites

The generator/browser oracle is not a qualified reusable server compact-JWE
parser. Either independently qualify strict protected-header/framing validation
before composition, or explicitly label any injected trusted QA validator as a
software test seam. Never call such a seam parser or full service qualification.
Server framing checks cannot inspect or validate the encrypted destination;
Apple and browser retain the agreed raw HTTPS route/plaintext validation.
No new encryption scheme or handwritten OAEP/GCM/KDF is introduced.

Root Worker routing, strict streamed JSON/Origin/CORS validation, trusted private
namespace routing, aggregate admission, policy and operational cleanup monitoring
remain separate API work. Temporary local QA bindings do not authorize product
bindings, migrations, Cloudflare mutation or live traffic. First durable cleanup
alarm must be confirmed before creating sensitive state; alarm failure must fail
closed, while delayed delivery never extends logical access.

## Recovery correction and required tests

Independent UX review found the previous contract required cancellation even
after confirmed consume, while cancel-after-consume conflicts. The corrected
rule requires confirmed cancellation only for live pending/ready rotation.
Authenticated consumed/cancelled status or original expiry permits a new
transaction and new browser key. Unknown outcome and unavailable cancellation
still require waiting until the original deadline. No extra user step or renewed
deadline is introduced. CONTRACT and WIRE now retain the same historical receipt
metadata already specified by KEY-STATE.

Execute actual local workerd/SQLite tests for successful ready/consume, competing
scans and consumes, wrong claim/QR/generation/key/envelope, exact historical retries
after consume/cancel/revoke, changed retries, original expiry and lease equality,
cancel/consume while coordinator awaits, burned counter and RPC outage, lost
submit/consume response, before/after-commit SQL faults, restart, alarm failure
and cleanup without client retry. Verify stored rows contain no raw capabilities,
proofs, Apple key IDs or plaintext routes and no terminal ciphertext. Public RPC
must not expose engine/helper methods or trusted adapter controls. Model/software
positives must stay separate from real signed native and full HA/TV acceptance.

## Independent review and delivery boundary

On2026-10-18 independent security review of the supplied design returned scoped
design-GO/noP1P2, conditional on the complete context/digest/binding/lease checks
and race tests above. Independent UX/privacy review actually read KEY-STATE,
WIRE and relevant CONTRACT passages, raised the terminal-rotation P2 and returned
scoped design-GO for the corrected rule. Neither review executed transaction
code or tests; no such implementation is claimed here. Exact document readback
and final review are separate receipts.

Joint exact consumer freeze, fresh supported signed-iOS nonce/action integration
and genuine composed-positive evidence, full implementation/security review,
Core real HA/proxy/display admission, protected merge, separate Finalization and
explicit deployment authorization remain open. Existing receiver generator
crossrun is delivered and must not be requested again unchanged. API owns its
transaction/controller/admission implementation; Apple/Core do not inherit that
work. No additional writer is started.

Reference: [Cloudflare DO coordination rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/)
and [RPC visibility](https://developers.cloudflare.com/workers/runtime-apis/rpc/visibility/).
These explain implementation mechanisms, not acceptance of this service.
