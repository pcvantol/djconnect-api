# VibeCast TestFlight release policy

The server policy is `ios-testflight/1`. It requires the DJConnect iOS App ID
`ZEML4LPXH4.dev.djconnect.ios`, production App Attest and validation category 2.
Enrollment and assertions verify the build number authenticated by Apple.

Set `RENDEZVOUS_TESTFLIGHT_MIN_BUILD` in the reviewed Worker configuration.
To admit one build, set `RENDEZVOUS_TESTFLIGHT_MAX_BUILD` to the same value.
For example, the first trial selects 40521 by setting both values to 40521.
To admit successors under the same policy, keep the minimum and omit the maximum.
Raise the minimum to withdraw older builds. Build numbers are canonical positive
decimal integers. Missing, malformed or reversed bounds close the route.

The policy and key address stay stable when the build advances. A changed range
invalidates outstanding enrollment challenges and stored authorization receipts
from the previous range. The configured expiry, Apple proof checks, request limits
and separate Core screen consent still apply. QA uses its own development policy.

The current source keeps public dispatch closed. Release approval and the
physical iPhone test on the public domain are separate from setting the range.
