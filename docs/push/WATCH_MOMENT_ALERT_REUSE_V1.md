# Watch V2 alert transport: initial source correction

Assignment `DJC-WATCH-COMPANION-V2-20261102` is owned across
[API #193](https://github.com/pcvantol/djconnect-api/issues/193),
[Core #1426](https://github.com/pcvantol/djconnect/issues/1426) and
[Apple #297](https://github.com/pcvantol/djconnect-app/issues/297).
Apple owns the integrated Watch experience. This initial change corrects only
the existing alert relay's configured Watch topic.

## Reuse audit before implementation

Baseline API main: `7ac9ad160e1a8b0109262ea61d79c00bc94d659a`.

| Disposition | Existing source | Result |
| --- | --- | --- |
| REUSE | `src/apns.ts`, `src/crypto.ts` | Alert transport, provider signing, fixed provider hosts and encrypted registration tokens. |
| ADAPT | `wrangler.jsonc`, generated environment types | Watch topic must match the actual app bundle, `dev.djconnect.ios.watch`. |
| REUSE / ADAPT | `src/auth.ts`, `src/repositories/registrations.ts` | Installation scoping and disabled/invalid markers exist. Exact Moment recipients, current pairing generation, preferences and old-token retirement need additional work. |
| GAP | `src/types.ts`, `src/validation.ts`, `src/apns.ts` | Only Ask DJ response/confirmation events exist. No agreed Moment publication identity, Session/detail destination, category, expiry or decoder capability. |
| GAP | `src/services/pushDelivery.ts`, `src/repositories/rateLimits.ts` | No durable Moment/recipient dedupe, bounded retry/UNKNOWN lifecycle or send timeout. Current rate limiting applies to bootstrap. |
| PRESERVE | Host-wake and rich surface modules | Distinct purpose/token families; they do not grant Watch alert authority. |

## Corrected topic and regression

The former configured topic `dev.djconnect.watch` differs from the Watch app
bundle `dev.djconnect.ios.watch` in both `project.yml` and the generated Xcode
project at Apple source `10ea3950e01dd0e7bf7b1d4a357ef2d90d34b624`.
The API's existing bootstrap bundle allowlist already uses the latter.

The multi-client registration/send test now consumes the real configured Watch
topic rather than overriding it with a fixture. It registers the Watch app
bundle and checks the actual outbound Watch topic while retaining the iOS
topic. The test fails on the old configuration and passes after correction.
Provider requests are mocked; this is no evidence of APNs or Watch delivery.

Environment declarations were regenerated with Wrangler's `--include-runtime=false`;
the existing runtime declarations remain unchanged. No toolchain update is part
of this correction.

Topic is persisted in each registration. Changing configuration does not repair
previous registration rows: an affected device must complete its ordinary
authenticated registration refresh after deployment. No database rewrite or
token re-registration is performed by this source change. Production configuration,
APNs environment, provider credentials and other client topics remain unchanged
until a separately qualified deployment.

## Remaining integrated outcome

Core must supply the original committed Moment/publication and authorized
recipient/preferences/revoke contract; Apple must confirm the selected Watch
app form, token/topic/environment and cold-start detail decoder. Agree one
versioned fixture before enabling a new event. The API still needs strict
recipient admission, generic five-language alerts, original expiry and durable
dedupe/retry handling. A locator grants no access; Apple reads the original
detail through Core and never starts a Session or TTS from notification-open.

The first physical test will separately distinguish API admission, provider
acceptance, a visible Watch notification and opening the original Moment.
This initial source correction does not complete that outcome.
