# Rich Session surfaces with push: contract v1

State: proposed canonical successor contract for bounded source preparation.
This is not a delivered producer, signed permission wire or positive factory.
Core base d5c85b2de690818fe2fd06cfe7e681eb3bb50c7a; Apple source236/237 and
separate Final238 are independently originally qualified. Neither qualifies
this successor. Product scope is the direct human correction: ONE rich Session
widget and ONE rich Session Live Activity with push. No second status-only
user variant, hidden loss of artwork/playback, new player or new settings UI.

## Precedence and exact reuse

This contract supersedes only the selected *product direction* in original
native lifecycle DESIGN96c7 that calls for a distinct status-only Activity.
That historical design, af201, private4515, status8, R2 principal DATA, the
existing widget background v2 and original v3 clock contract stay byte-frozen.
Their types and permissions MUST NOT be widened in place. Metadata/once/custody
preparation remains reusable within its own scope, never a display decision.

Reuse the current existing Session WidgetBundle entries, rich renderer and
Session Activity controller. Core keeps Runtime/Planner/Flow/Broadcast and
passive field/source selection. Apple owns native installation, display,
clock mapping, pixel staging and actual SDK invocation. API owns independently
admitted transport, registry and its real provider boundary. No owner moves.

Exact Apple source basis, same bytes at protected Final238:
- DJConnectLiveActivities.swift: 1d2733a6fd2a4e102a90a9e48db67a947c46aa7afc2b2e701bd45b12deb01f92.
- DJConnectPassiveSession.swift: 1c771bf3970547b0b9baccf4e3e1681f0fb2a30f48dacb26777b3921ba5092bb.
- DJConnectBackgroundSession.swift: 86b72a695bad9f66f5656c898bf131bbd4dd7e873d090571f9a468fed2feb8f1.
These pins identify existing formats, not a future implementation acceptance.

## Rights are per field, transport and original decision

Initial native creation requires a DISTINCT original rich-start/display
permission before SDK invocation. Bind the original accepted pair/source,
independently acknowledged purpose/policy and original immutable initial
projection including actual field-level rights, native installation/platform,
locked-display scope and conservative deadlines. An empty Activity, later B,
source provenance, token, SQL row or matching digest cannot supply that right.
The decision need not wait for its own future Activity ID or API A/B. The
actual returned ID/proof permits *subsequent* independently accepted A then B;
it does not retroactively authorize the start.

Keep the existing passive projection source/field matrix and additional v2
research attribution unchanged. Private Ask DJ/history/DNA, artist photos and
unqualified copy remain excluded. Existing passive_cache/os_snapshot rights
are not external_relay rights. In particular external_relay:false MUST NEVER
become permission to send rich text through API/APNs. A profile identifier,
operator agreement, a user request for the feature, or an accepted token does
not substitute for exact source-purpose relay permission. No new source
licence or global rights flag is selected here.

The first content-preserving connection is a content-free push invalidation
followed by an independently admitted original rich read and a local update of
the SAME existing rich widget/Activity. It is best effort: the OS can decline
background execution. This is one delivery path of the same product, not a
status-only alternate product. Actual message grammar and purpose/token family
must be separately canonical and independently implemented before use; do not
reuse an ordinary app token as an admitted surface token.
A WidgetKit timeline invalidation is NOT a host-app wake or evidence of a local
Live Activity refresh. Local Activity update requires its OWN actually admitted
host-app background token/purpose, current original native owner and actual OS
execution opportunity. No existing token is translated into that scope here.
If that host-app path is unavailable, do not report the Activity updated merely
because the widget reloaded or a notification was accepted.

The rich read is between the actually permitted source and recipient under its
independent transport rights. An API plaintext proxy/relay is NOT exempt from
external_relay:false by naming it background read. No private rich payload is
routed through API/APNs absent that exact original permission. Content-free
invalidation carries neither an artwork URL nor rich/private content.

Direct remote rich Activity content is a separate permitted transport ONLY
when its actual field-level external-relay rights, exact producer/codec/clock
mapping and complete original target admission are qualified. It is not enabled
by this design or by a content-free wake. No push-to-start is selected. Both
paths feed the same rich presentation; no second WidgetBundle/Activity type.

## Exact existing Activity format

Attributes: DJConnectSessionLiveActivityAttributes, exactly presentationID:String.
It is the actual original local presentation ID; a native/installation/source
counter or Session ID cannot replace it. Original presentation generation and
negative/restore witnesses remain separately bound by their own retained native
custody/proof; DO NOT silently add the status-design second UUID to these
attributes or infer that the one String proves the private relation.

ContentState is DJConnectSessionSurfaceSnapshot:
- Required observedAt and expiresAt: finite Foundation default Date numbers.
- Optional theme: existing DJConnectSessionMoodTheme raw value; optional rich.
- rich is DJConnectPassiveActivityContent with required bindingID, generation,
  sequence, receivedAt, receivedUptime, expiresAt; optional contribution,
  nowPlaying, playbackState, using the exact existing nested Codable shapes.
- Existing omission versus JSON-null behavior must follow original encoded
  fixtures and a closed successor preflight; unknown/duplicate fields, invalid
  UTF-8, nonfinite numbers, boolean-as-number, integer overflow and extra nested
  fields are rejected before any authority/SDK/transport stage. Codable alone
  ignores unknown keys and is not that preflight.
- Dates use seconds since Foundation reference date, not Unix milliseconds,
  Unix seconds or ISO8601. Never normalize a different representation into a
  positive display. Existing default encoder roundtrips are fixtures, not a
  permission or general cross-runtime canonical serializer.
- No image bytes, external fetch URL, credential, private Session/Profile or
  second permission envelope is added to ContentState/attributes. Existing
  identifiers/attribution retain their qualified existing display scope.

The existing rich initializer checks encoded rich data <=2800 bytes. Preserve
that guard. Independently enforce BOTH actual serialized attributes+complete
ContentState <=4096 bytes AND complete transmitted APNs JSON body <=4096 bytes
when direct content is actually permitted. Count original UTF-8 bytes with the
actual escaping/Date/optional rules, never characters or only the rich object.
Exactly equal to each cap is allowed, one byte over is rejected. Do not truncate
factual copy/attribution or drop required rights to fit. Omit only independently
optional unavailable fields according to the existing source contract; otherwise
close that content transaction. Payload fit never supplies display permission.

## Closed DATA carrier and exact relay serialization

The successor DATA profile identifier is `djconnect-session-rich-v1`, version1.
It selects a format, never an authority or an enabled public API profile.
The closed DATA carrier has exactly six keys:

    schema_version: integer1
    profile_id: string djconnect-session-rich-v1
    attributes_utf8_b64u: unpadded canonical base64url of original attributes JSON
    content_state_utf8_b64u: unpadded canonical base64url of original state JSON
    source_observed_at_ms: safe finite integer UTC milliseconds
    source_expires_at_ms: safe finite integer UTC milliseconds

No padding, whitespace in base64url, alternate alphabet, noncanonical trailing
bits, duplicate/extra carrier keys, negative/overflow/bool timestamp or unknown
version/profile is accepted. Decoded attributes/state are strict UTF-8 closed
JSON objects, not arbitrary bytes. Bound encoded input to16384 UTF-8 bytes
before decoding; decoded attributes+state together <=4096. Byte-budget success
never skips exact nested validation. Empty attributes/state are not valid.

The original fragment bytes are preserved through signature/digest validation,
closed preflight and actual final APNs construction. A final producer appends
ONLY validated original JSON object fragments, not raw unchecked text; it must
not parse and silently reserialize Foundation dates/escaping under an assumed
identical digest or size. Count the actual final output body as well. Existing
ActivityProfile.parseContent(JsonObject) cannot recover these original bytes:
its successor needs an independently qualified raw-input preflight/typed fragment
boundary before provider use, not a string-to-object cast or runtime schema.
No current public relay/af201 request is reinterpreted to accept this carrier.
Its separately authenticated transport/version and actual original owner port
must be delivered before a positive cross-process composition can use it.

Original accepted static attribute bytes MUST equal the independently captured
native creation attributes and exact Activity ID/presentation witness, not just
a type string or caller assertion. A required original composition port also
joins content to original source/field rights, clock/native mapping and lifetime.
No default owner, matching digest, signed DATA alone or source permission boolean
implements that port; absent original accepted attributes/currentness is CLOSED.

Carrier source_* values are conservative UTC projections of the independently
accepted ORIGINAL Core frame/field/purpose bounds. They are NOT calculated from
receivedAt, receivedUptime or a client-local render cap. Given an independently
qualified original UTC instant in seconds, observed milliseconds use exact
ceil(1000*instant), expiry uses exact floor(1000*instant). Require0<=observed<expiry
<=9007199254740991, and reject an empty interval. Use exact arithmetic on actual
represented values, never expiry roundup or observation backdating. The source
receipt must establish these instants and their per-field/purpose minimum;
caller-supplied integers or Foundation Date decoding cannot establish that.
Foundation Date numbers in the state stay byte-unchanged, with their distinct
local display semantics. No unqualified UTC/device-clock equality is assumed.

A transport profile is compiled from this pinned definition and qualified
fixtures, never request-provided code/schema/config. Production default profile
maps remain empty until original owner/rights/clock/provider admission is real.

## Original clock and publication guard

The original Core observation and field deadlines remain unchanged. Reads,
APNs arrival, paint, token rotation, semantic equality, process launch and SQL
commit are NOT new observations and cannot renew any original purpose/field.
A genuinely new original accepted observation may supply its own later field
deadline within the unchanged original purpose bound; an old field is never
relabelled as that new observation.

receivedAt/receivedUptime are ORIGINAL native clock anchors, not clocks Core
or API may invent. A direct producer cannot fabricate device uptime, convert
server monotonic seconds to device uptime or set receivedUptime on delivery.
The receiving rich renderer's current isCurrent is a necessary check, not an
independent qualified clock source or permission. Codable roundtrip preserves
the pin but proves no physical clock rate, suspend behavior or restart mapping.

Compose the canonical v3 ORIGINAL C0 before await and qualified rho_min mapping,
minimum across SAME original purpose/contexts/rotations and conservative final
addition. This reuses the mathematics and original constraints ONLY: the
current v3 runtime is WIDGET_ONLY and supplies no rich Activity admission or
cold-extension/restart C0 re-delegation. A cold process that lost the original
pin remains CLOSED until its separately versioned original read/clock/restore
adapter and permission are actually qualified; no v3 status GET repairs that. Also retain independently original per-field observations/deadlines.
Each displayed field is bounded by BOTH its original UTC/source eligibility and
its independently mapped conservative native monotonic deadline. Missing/lost
C0, boot/domain/rate/suspend/restore witness or ambiguous mapping -> no positive
rich publication, not a guessed TTL, new C0, or revived cached frame.

The successor Apple adapter must keep that mapped guard at the ACTUAL cache/
render/SDK boundary, including extension/cold-process delivery. The existing
receivedAt/receivedUptime pair alone does not implement arbitrary v3 cross-clock
mapping. If a safe mapped local cap is needed, retain the original source
receipt/deadline separately; a local conservative display cap is not a rewritten
source expiry or a new observation. No exact local-cap producer is yet qualified.
No direct remote rich profile is operational until the same original native
mapping and full local cap interpretation survive its real receiver path.

Immediately before every cache write, image publication or SDK update, the
same original runtime/pair/source/purpose/Session/observer and settings revision,
original target/generation, cancellation, deadlines and withdrawal witness must
still be current. No await or actor/executor hop after the final guard; a hop
requires its own guard at actual invocation. Late error/cancel/ABA cannot
restore an original pin, target or rights. Close local admission synchronously
before any withdrawal wait. Negative outcomes do not free earlier once slots.

## Rich read and artwork are a separate negotiated successor

Existing background schema2/widget hasValidFields requires artwork.isEmpty.
Existing scoped-read credentials and widget purpose cannot be relabelled into
Activity read, artwork authorization or an ordinary paired bearer. Therefore
neither adding an array to that response nor changing its version in place is
allowed. The successor needs an exact new negotiated schema/profile and original
producer admission; unavailable is truthful until both ends implement it.
This contract selects the semantic constraints, NOT a live new URL or already
signed HTTP response. A separate closed read/artwork wire increment is required
before client production composition; no generic raw dictionary adapter.

Reuse only already prepared exact cover bytes from the current qualified image
registry. A read MUST NOT fetch a provider/model or publish a Moment. Artwork
fetch uses its OWN bounded asset-scoped background authority and currentness,
not the ordinary app bearer, owner image URL or arbitrary supplied URL.
Each staged image binds original installation/purpose/surface, opaque binding,
generation/sequence, contribution-vs-now-playing slot, exact subject/item/album,
asset/media revision and original source/cache/display deadline. Attribution and
five-language alt-text survive. Never use track A pixels for track B or apply
an expired/late image to a newly current frame. Text remains independently valid
when art is missing; no false claim that a new cover was received.

An Activity cannot fetch an image itself. The authorized app/background route
stages appropriate AppGroup pixels before publishing that same original image
association; a direct content push cannot create those pixels. Wrong/missing/
expired artwork clears only its own association. No URL/network fetch in the
Activity view and no byte-packed image inside the state. Existing static
VibeScape remains. Widget reload requests coalesce and consume actual OS budgets;
no progress-driven spam, polling-as-new-observation or lease renewal.

## Platform, lifecycle and acceptance

Native initial rich Activity ownership is only the actual qualified existing
iOS/iPadOS ActivityKit target and supported OS/capability. macOS/watchOS mirrors
are not independently addressable rich start/update owners or new source rights.
WidgetKit push requires its actual platform/kind/environment support and proper
extension token; no token-family fallback or fabricated placement identity.
Gallery placements, user dismissal and OS retention remain real platform facts.
No immediate offline OS erasure or guaranteed wake/display is claimed.

Original native reserve/consume/once/UNKNOWN/terminal semantics remain. Use the
real returned Activity ID; inventory matches exact original private binding and
all existing attributes. An absent Activity or failed ACK never proves no effect,
restarts generation or authorizes another Activity. No first-match adoption.

Before positive production composition, qualify separately: original concrete
Core/Apple permission owners; exact signed cross-process permission/read wires;
real native VFS/storage/restore and nonrollback witnesses; actual clock mapping;
API enrollment/custody/registered original target and transport; actual permitted
content/artwork and attribution; and native background/locked/expiry/withdrawal
receipt. Actual key/provider/physical effects require their own concrete authority.
These are implementation gates, not a request for another end-user setup screen.

Required causal qualification includes absent initial rich display permission;
old status8 permission with rich bytes; all deadlines/clock offsets and suspend;
late read/token/image/error after withdrawal; A->B->A; cross-Session same-device;
cold restart/lost pin; duplicate/missing/overflow JSON fields; exact 2800/4096
UTF-8 boundaries with Unicode/escaping; Foundation-vs-Unix/ISO dates; original
attribute mismatch; actual once consume/lost-ACK/late native identity; independent
now-playing/contribution subjects; missing art and source withdrawal; no extra
publication/provider/model/playback effect on repeated pure reads. Reference
vectors and component tests are software evidence, not iPhone APNs acceptance.

Source and separate documentary Final need their OWN independent whole/exact
reviews, normal CI/protected merge and original formal/durable qualification.
All existing requests/Help EN/NL/free Ask DJ/VibeCast/HA production/Pi gates
remain retained. No installation, restart or provider redeploy is needed for
this contract; no current runtime availability is changed by source delivery.
