# Action challenge issuance internal failures

This bounded slice changes only `issueAction`/`AssertionKeyState.issue` failure
classification. Existing explicit input/canonicalization/validation rejections
remain `invalid_sender_proof`/401. Unexpected SQL/read/JSON/transaction/digest/
random/alarm exceptions become existing redacted `service_unavailable`/503,
without exception-text matching, details, Retry-After hints or new wire fields.
Input and binding object guards precede cloning/property access. Decoder-only
catches preserve invalid base64 rejection; they do not hide storage or hash faults.
Authorize, lookupSubmit, deletion, counters, verifier behavior, busy-return and
current assertion-policy classification remain unchanged. Complete policy/provider/
internal error taxonomy therefore remains OPEN, including the existing401 for an
unavailable assertion policy; no complete function closure is claimed.

The awaited locked issuance section retains its already calculated local original
requested creation/expiry window. A throwing callback after expiry or rollback
remains401 without a database fallback. When storage fails before a previously
coalesced operation can be read, its deadline is unknown and is never guessed.
Healthy management coalescing returns the saved original challenge/nonce/expiry.

503 is not rollback confirmation. A transaction-wrapper failure after commit can
leave one operation stored. Explicit management repair coalesces that original
operation; explicit submit repair is NOT idempotent and can consume a second
bounded slot/challenge while retaining the first. The original transaction expiry
and28submit/2recover/2delete/32total limits remain. No automatic retry, slot refund,
new key, counter reset or lifetime extension is introduced. This is server
classification, not SDK/provider outage diagnosis or new client recovery authority.

Actual local workerd passes1129 affected cases and isolated strict types; full
shared qualification passes1335; actual product export/private-RPC/default-genuine
qualification passes128 checks including100 forbidden RPC calls. Initial paired
counterproof on protected86 runtime with the new test set gives1083PASS/34FAIL;
the matching corrected run passes1117 before twelve additional regressions. These
are controlled local tests, not a whole-tree baseline delivery or native evidence.

Twenty-four actual HTTP fault cases cover three actions across eight phases,
requiring hit1, exact redacted503/nohint, request/key charge1 then explicit repair
charge2; submit also charges its transaction attempt twice. They distinguish no
precommit operation from unknown postcommit outcomes, management coalescing and
submit's second slot. Additional tests exercise actual SQLite INSERT abort,
corrupt stored JSON, malformed bindings/decoding, unknown thrown markers, exact
requested-window equality/rollback and refusal to guess an older stored deadline.
Existing authorization, immutable leases, counter monotonicity, deletion and
28/2/2 capacity tests run in the same suite.

Exact source preparation uses protected86 as immutable supplier plus a closed
three-input delta and separately hashed66shared/85root proof maps defining106
tracked inputs. All prior proof files remain unchanged.32 installed hashes and
13 references stay fixed; depth-one preparation tests retain fail-closed history
without currentHEAD fallback, PR object fetch or generic delta chains.

Root compiledOFF/serviceOFF/all22 full-service gatesOPEN. No actual SDK, native
key/capture, provider, Cloudflare, credential, installation, deployment, selected
HA or physicalTV effects are authorized by this qualification. Independent exact
source reviews, protected delivery, real own-main evidence and separate finalization
remain required outside this document.
