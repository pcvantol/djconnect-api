# Enrollment callback source Finalization

This separate docs-only candidate records the protected-delivered saved-state
callback correction in PR116. It requires its own exact independent reviews,
protected merge, own-main evidence and final API90 receipt before Finalization
is complete. The entire rendezvous assignment remains OPEN.

## Source delivery and exact reviews

Source candidate 2ffa9bf19bd50a4b9e8b12b685a6b9689c9ab7e4 was squash-merged
normally as f88f237d73227981864b932cdd1d441df1276018 through
[PR116](https://github.com/pcvantol/djconnect-api/pull/116).
Both have tree a2740e6a87a367cffd3ffc40779363c3d73d9625.
[Two fresh independent read-only reviews](https://github.com/pcvantol/djconnect-api/pull/116#issuecomment-6309554865)
returned scoped security and UX GO with no findings after direct human
authorization. These are agent reviews recorded by the writer, not GitHub human
approval reviews. They inspected source/tests/stored evidence without rerunning
tests; no previous review was reused.

All seven recorded candidate workflows passed, including required
Trusted Delivery, Validate and Owner Authorization. All seven own-source-main
workflows also passed: Validate39555215008, CodeQL39555215517,
projection39555214641, observe39555214646, private/browser39555214642,
artifact39555349884 and formal39555350159. The private/browser workflow exercised
its real Chromium/WebKit and default-verifier/private Worker/receiver checks;
it is not native-positive or physical-device acceptance.

## Actual downloaded evidence

The companion machine record contains the full downloaded formal receipt,
artifact metadata and durable receipt. Actual provider ZIP bytes were hashed
and matched GitHub artifact digests, separately from their payload hashes.

| Evidence | Actual SHA256 |
|---|---|
| Release tar payload12325256590 | d730e58b8c565ed980a4740642494dc1a4b5ea1d4a33fad38b9fa7b80171ac9b |
| Main-stamped1258415-byte Worker | 9159c530328aed69ae788f627260e77873900ea3cff477fe41b83f5bbbf4b41c |
| Formal evidence digest | aeddafeda09eadbd6fde5e48810d7207b3a9740e8f37b98e0d19ad413ed27a56 |
| Durable asset661575066 | b7211778c94ea48cdac129f687a372d8b2f6e164237927f62aa3f927faec6730 |

The release payload hash matches the artifact evidence, its bundle contains
the exact main stamp, and all three licence sidecars equal source bytes.
Formal decision is POST_MERGE_RELEASE_EVIDENCE_QUALIFIED with zero findings.
The actual durable asset matches its provider digest and binds the same main
and formal evidence digest under internal-api-f88f237d73227981864b932cdd1d441df1276018.

The first download attempt used an unsupported Accept header and returned415
before downloading bytes. Corrected artifact GETs succeeded. ENOSPC also
prevented earlier shell heredoc reads; inline reads and small evidence receipts
succeeded. No local build, source test rerun or cleanup was used to hide either
environmental failure.

## Preserved behavior and remaining work

[The correction and executed local counterproofs](ENROLLMENT_CALLBACK_FAILURES_V1.md)
remain unchanged: callback exceptions retain original identity; the existing
coordinator preserves context401, internal/config503 and known original-window
precedence. No proof bypass, automatic retry, refund, nonce/deadline renewal or
state migration was added. The original1485 local shared tests and other local
qualification remain distinct from actual source-main CI.

This Finalization adds no runtime change, deployment, Cloudflare/D1/device/
Keychain/provider/HA effect or approval. Public root remains compiled OFF/503,
public QR disabled and all22 full-service gates OPEN. Complete core/CMS/status
and provider taxonomy, genuine native chain, HA and physical-TV acceptance remain
open. The separate sharp39 maintenance plan is not implemented by this slice.
Timer stays PAUSED. The expired night window is not extended; the user explicitly
requested this bounded follow-up closure and authorized the two reviewers.
