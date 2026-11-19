# Fixed assertion WebCrypto failures

This bounded correction preserves exceptions from the assertion core's five fixed
WebCrypto operations: the application-prefix SHA256 digest, stored-point P256
import, saved-clientData SHA256 digest, nonce SHA256 digest and ECDSA verify.
Previously the core's blanket catch returned null for these exceptions, just as
for an actual invalid signature. The owning coordinator then reported
proof_rejected/401, losing its existing internal503 classification.

A module-private wrapper covers only each actual WebCrypto invocation. The core
rethrows the identical original cause; it never selects classification from an
exception name, message or lookalike object. Signature CBOR/DER decoding and all
successful proof predicates remain outside that wrapper. Actual verify=false,
invalid app/build/category/counter/clientData and malformed proof remain null.
The coordinator, HTTP mapper, wire, state, budget, retry and original-window
logic are unchanged. The shared prefix helper's default digest and the entire
attestation catch remain unchanged; only assertion calls supply the private
wrapped digest.

## Ownership and finite outcomes

The public point comes from previously owned stored key state, not the incoming
assertion. A correctly shaped stored point that the real P256 importer rejects
is an internal state/crypto failure, not a sender-signature verdict. A native
WebCrypto DOMException control exercises this case. Existing malformed type,
length and first-byte predicates remain unchanged. No generic DOMException
policy or new provider-outage claim is introduced.

A live fixed-operation exception reaches existing redacted service_unavailable503
with no Retry-After. Known original challenge/key expiry or clock rollback
remains401; the failure catch performs no SQL fallback. Failure installs no
grant/receipt, advances no counter and renews no nonce/deadline. The busy guard
still releases. Only a later explicit original request may repair; its budget
charge is not refunded. A successful repaired software proof is a trusted-fixture
control, not native enrollment or proof of a real crypto service outage.

## Actual local qualification

The same1539-case shared workerd test set first produced1499PASS/40FAIL against
unchanged runtime, then1539PASS after the core correction. Exactly20 direct
exception-identity and20 coordinator503 cases changed result. This is a
single-boundary causal counterproof, not whole-baseline requalification.

The final full shared set passes1543 cases/strict types,58 added cases total:
20 exact thrown identities over five calls/four thrown values;20 coordinator
failures/original explicit repair controls;9 actual-fault original
challenge/key expiry or rollback controls with zero catch-time SQL;5 malformed/
actual-invalid-signature/counter/app-prefix controls;1 actual invalid stored
curve-point import;3 guarded default-assertion HTTP cases. Each HTTP case
checks exact redacted503/no Retry-After, unchanged key/pending operation,
request+key-call charge1, then explicit original software-proof repair200/
counter1 and charge2 without changing original expiries. Enrollment in this
HTTP fixture is explicitly trusted software, not genuine App Attest.

Standalone shared attestation/assertion core44PASS, no private native inputs.
Its first post-fix run was43PASS/1FAIL because an old invalid-stored-point test
still expected null. That test now explicitly requires the actual import
exception; its malformed sender-proof controls remain unchanged.
Actual product bundle128 checks/100 forbidden private RPC/no egress, API78,
composition49, strict root types and diff checks pass.

The old offline preparation first returned PREPARATION_INVALID_NOT_AUTHORIZED
for changed source. New proof publication initially exceeded the existing1MiB
decoder limit because the full scenario traces are3,246,187bytes; no limit was
relaxed. Full executed summary is preserved privately. The committed218547-byte
summary uses the existing selected scenario fields/canonical observation hashes
and records the full-summary SHA256. Actual complete66shared/85root maps are
unchanged in shape. Four changed preparation inputs are pinned over protected
9261af97f9452b053468b1dbfc7275774b84a5ea,106 tracked inputs/32 installed hashes/
13 references. Separate core proof records its exact test/core inputs.
Historical proof bytes are retained. The preparation remains NOT_AUTHORIZED/
activationfalse with all22 gatesOPEN. Exact committed default/private40381
negative-preparation receipts belong in the PR/API90 delivery record.

## Delivery and remaining gates

Fresh independent security and UX reviews, exact protected CI/OwnerAuthorization,
normal source merge, own-main artifact/formal/durable readback and a separate
Finalization remain required. Executor tests are not independent reviews.
This document is not a deployment approval or complete taxonomy qualification.

Attestation, PKI, CMS, status-client and unexpected parser/library classification
remain separate open boundaries. Default40227/40228/40230 and fixed private40381
profiles, cryptography, wire and successful admission are unchanged.
No public activation, deployment, native/device/Keychain/provider/HA or paid call
is performed. Public root stays compiledOFF/503 and publicQR disabled.
Timer stays PAUSED. Current actual HA-dev source/payload/capabilities supplied by
Core remain separate from selected externalHTTPS/B-consent/native-chain proof.
