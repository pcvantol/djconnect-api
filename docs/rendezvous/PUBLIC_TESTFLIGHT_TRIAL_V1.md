# Public VibeCast TestFlight trial

The central Worker can serve the existing VibeCast routes during an explicitly
configured trial for one verified TestFlight build. The source defaults to a
closed route. The release manifest binds the reviewed Worker configuration and
exact artifact.

Use the production App Attest policy `ios-testflight/1`, a single build (equal
minimum and maximum), an advancing release revision and the
`private-household/1` capacity policy. Set `RENDEZVOUS_PUBLIC_TRIAL_STARTS_AT` and
`ASSERTION_POLICY_EXPIRES_AT` to the agreed UTC epoch milliseconds. The window
must exceed 120 seconds and is capped at two hours. Creation stops with 120
seconds left. A successful QR response preserves the original 120-second expiry.
The route closes at the configured end.

Use the existing five production SQLite Durable Object bindings. Verify the
presence of `RENDEZVOUS_IP_HASH_KEY` and `RECEIPT_ACTIVE_KEY` in Cloudflare by name
only. Keep the last qualified Worker version with compatible bindings as the
rollback. Verify ordinary API health and the VibeCast 503 after rollback.

Before starting the trial, verify the signed build and its existing Core HA
pairing, the actual production edge and the exact artifact. Test direct browser
preflight and send same-zone and cross-zone Worker probes to the actual edge.
Verify rejected subrequests do not reach admission or storage. The local
fixtures exercise application-side rejection only.

Use the paired iPhone to scan the QR on vibecast.tv and separately approve that
screen. Verify no session data appears before consent, only the original browser
can consume access, replay and expiry are refused, and revocation closes the
screen while the DJ session continues.
