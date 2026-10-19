# Actual receiver/API source interoperability

This API-owned qualification executes the real receiver adapter from protected
receiverPR30/main `39844ebf8499261e26bfb59d4a871408957df4a8` against the actual
five product DOs and ordinary internal API module. The transport forwards the
adapter's exact POST body bytes through the local SDK. Canonical URL, Origin,
IP and cf values are fixtures, **not** network/browser/Cloudflare provenance.
It introduces no product dependency, receiver write, public endpoint or deployment.
Source/wire remains `djc-rendezvous/1-implementation.1` / `djc-rendezvous/1`.

## Two explicit phases

Public preparation needs internet access; execution does not contact the source
host or package registry. The preparer accepts one existing empty0700 directory,
owned by the current user, canonical and outside Git. It fetches exactly three
immutable public source URLs with no credentials, no redirects,5s/64KiB limits
and SHA256 verification before exclusive private writes. Partial failure leaves
private inputs for inspection and never retries or overwrites automatically.

The independent fixture package/lock contains only `jose6.2.12` and
`qrcode-generator2.0.4`, matching the receiver lock's exact package integrities.
Installation explicitly disables lifecycle scripts and audit/funding requests.
These are qualification dependencies, not root API production dependencies.

```sh
DJC_INTEROP_INPUTS="$(mktemp -d)"
chmod 700 "$DJC_INTEROP_INPUTS"
node qualification/rendezvous/prepare-receiver-interop.mjs "$DJC_INTEROP_INPUTS"
npm ci --prefix "$DJC_INTEROP_INPUTS" --ignore-scripts --no-audit --no-fund
node qualification/rendezvous/run-receiver-interop.mjs "$DJC_INTEROP_INPUTS"
```

The runner requires a clean source checkout. Before dynamic import it checks the
three source hashes, fixture/lock hashes, exact110 installed package files and
closed receiver import graph. Descriptor checks reject symlinks, hardlinks,
special/changing/missing files and drift; extra files/directories reject. Only
the regular owned `node_modules/.package-lock.json` install metadata is exempt
from content matching. This is a local developer tool, not a hostile same-user
sandbox. Source/dependency inputs are rechecked after the actual run.

Execution uses the unchanged default genuine verifier and existing private local
runtime. An explicit positive interception control verifies the Node global-fetch
guard, then its counter is reset before importing/executing receiver code. The
real workerd outbound guard independently has its own startup control. Actual
QR/cancel processing must produce zero further Node-fetch or Worker-outbound
attempts. This is not an OS-wide firewall or a zero-network claim about preparation
or internal SDK loopback communication. The inspector remains disabled.

## Measured boundary

Eight independent corruption cases must reject: changed receiver source, missing
schema, unexpected root file, changed package module, extra package file, source
symlink, source hardlink and package-directory symlink. They use private copied
fixtures and are separate from the following seven actual interop checks:

1. Receiver's actual generated RSA public key/claim request receives API201.
2. Actual response passes receiver wire/context checks and produces a boolean QR
   matrix using its real QR generator. No QR decoding, screen rendering or camera
   acceptance is claimed.
3. Receiver's exact browser-bound cancel request receives API200.
4. A second adapter cancel rejects locally with no additional API call. This is
   not a general server idempotency or transport-abort/rollback guarantee.
5. An explicit wrong browser secret receives API401.
6. The actual cancelled QR scan context receives API409.
7. Neither actual consumer/API path attempts external Node-fetch or Worker egress.

Only fixed scope/source hashes/counts/route-status results are printed. Console
methods are suppressed during consumer import/execution; failures are generic.
No matrix, payload, claim, capability, nonce, JWK, key handle or destination enters
the receipt. The simulator is disposed in finally; public fixture inputs are
retained privately. The existing supplemental read-only CI runs this check after
the ten local-native groups. Existing product API/module/RPC gates remain intact.

This proves `ACTUAL_RECEIVER_NODE_TO_ACTUAL_API_WORKER_FIXTURE_TRANSPORT_NO_NATIVE_BROWSER_EDGE_OR_HA_POSITIVE`.
No sender is enrolled or granted authority, no destination is submitted/decrypted,
and no fake genuine verifier or successful destination response is injected.
Real native/profile/rawData readiness, browser fetch/CORS/lifecycle/navigation,
direct-edge provenance, HA-owner/route/separate B-screen admission and physical TV
acceptance remain separate. Public root503, unmounted module, all22 full-service
operation gatesOPEN and timerOFF are unchanged. Prior producer/source Finalizations
and closed consumer ACKs are preserved; the full assignment remainsOPEN.
