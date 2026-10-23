# One original clock sample for the trusted storage fixture

The assertion-state software fixture used three independent `Date.now()` samples for receipt creation, challenge creation and challenge expiry. A millisecond boundary between the latter two samples made the intended 120,000 ms interval become 120,001 ms. `ReceiptKeyStore` correctly rejects that interval before installing the trusted synthetic seed.

PR 143 candidate CI run `39974549604`, attempt 1, passed all 1,364 original shared cases but failed one of 1,590 QA-derived cases. The safe failed-case hash `621126f920ec051db9bc14fdcbb89dfeb57ed489e60d45caf70ab6a4a04099c5` identifies `fixed assertion crypto preserves exact thrown value: verify/1`. The recorded locations point to the fixture's install assertion, before crypto fault injection or the receiver HTTP phase. The exact original CI clock samples were not recorded; this identifies a reproduced fixture race without claiming it was the exclusive cause of that historical failure.

The fixture now finishes its asynchronous key-address digest, captures one original wall-clock sample, and derives all three synthetic timestamps from that sample. Its backdate remains 1,000 ms and its expiry offset remains 119,000 ms. This changes only test preparation. The runtime's 120,000 ms limit, expiry checks, exception classification, counters, state, rights and cleanup behavior are unchanged.

## Actual counterproof and regression

Four cases against the original local workerd/SQLite `ReceiptKeyStore` passed: the old fixture without a boundary is accepted; a one-millisecond boundary produces 120,001 ms and is rejected; one original sample produces 120,000 ms and is accepted; deliberately adding one millisecond to the repaired interval is still rejected. The actual store and assertion runtime bytes were joined to protected main `39ad722c253475bae7acd183bcc5e0688dced3e4`.

The committed regression advances `Date.now()` on every call, uses the actual shared `setup` helper, verifies its exact interval and original receipt/challenge creation coordinate, and exercises the actual store's overlong-material rejection. With the original helper substituted into the same staged regression, the selected case fails at the same install assertion (`0 PASS / 1 FAIL`); with the repaired helper it passes (`1 PASS / 0 FAIL`). Both targeted runs filter out 203 other registrations and are not full-suite qualification.

Local full original and QA-derived qualification results are recorded in the owning review packet. The counterproof receipt SHA256 is `12732c4f710a106bcee3f7f77452202e7df57991ebe21072e4175337fac8dc95`; its original results, probe and exact runtime hashes are retained separately. No historical failed run is relabeled PASS. The distinct `recover-key/set-alarm` classifier failure has no established causal resolution and remains open.

This fixture repair does not fix Apple's separately observed first-purpose-clock defect, admit native enrollment, enable public rendezvous or push, issue real rights, or perform provider/device actions. Existing production code, configuration, dependencies and all five locale files remain unchanged. Its source delivery and the later cumulative Finalization require their own exact independent reviews and normal protected qualification.
