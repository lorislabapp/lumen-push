# lumen-push

Open-source Cloudflare Worker that relays [Frigate NVR](https://github.com/blakeblackshear/frigate) detection events to Apple Push Notifications for [Lumen for Frigate](https://apps.apple.com/app/id6760238729).

**No server to manage.** A Cloudflare Worker that signs APNs requests and delivers notifications. Delivery registrations, automation configuration and temporary functional state are persisted; notification usage analytics are not collected by this code.

## Architecture

```
Frigate NVR
      |
      |  MQTT: frigate/events + frigate/reviews
      v
lumen-push-relay (this is a small container you run on your network)
      |  https://github.com/lorislabapp/lumen-push-relay
      |  1. Correlates Review Items with raw detection evidence
      |  2. Filters: labels, zones, confidence, cooldown, schedule
      |  3. POSTs a canonical frigate-review-v1 envelope
      v
Cloudflare Worker (this repo)
      |  1. Validates the Review schema and freshness
      |  2. Server-side filters (stationary, top_score < 0.5)
      |  3. Rate limits: 5s per device token + camera (Cache API)
      |  4. Signs APNs JWT (ES256, cached 50min)
      |  5. Delivers to Apple APNs with 1h expiration retry
      v
Apple APNs (api.push.apple.com)
      v
Lumen app on iOS / iPadOS / macOS / watchOS / tvOS / visionOS
      |  Notification Service Extension applies user settings:
      |  per-camera filters, label whitelist, quiet hours, etc.
      v
User sees notification (typically <1s end-to-end)
```

## How it works

1. You run [`lumen-push-relay`](https://github.com/lorislabapp/lumen-push-relay) alongside Frigate — a small Python/Docker container that subscribes to Frigate's MQTT events.
2. When Frigate creates or updates a Review Item, the relay correlates it with the referenced detection, filters it, and POSTs a compact canonical payload to this Cloudflare Worker. Raw tracker events alone are never notification authority.
3. The Worker validates, rate limits, signs an APNs JWT, and delivers the push to Apple.
4. Your iPhone / iPad / Mac / Watch / Apple TV / Vision Pro receives the notification via Lumen.

> **Why two pieces?** Frigate publishes events over MQTT but does not send HTTP webhooks natively, so something has to subscribe to MQTT and forward to HTTPS. We split the work: the relay is tiny and stays on your network (sees your MQTT), the Worker holds delivery registrations and the APNs key (signs and delivers). Only the compact notification payload (camera, label, zone, confidence) leaves your network.

## Privacy & Security

- **No notification usage analytics.** No per-device/camera/country statistics, analytics dashboard, scheduled digest or delivery-history record. Application code does not log camera/event names or raw APNs/transport errors. Worker observability is disabled in the checked-in deployment configuration; infrastructure handling remains governed by Cloudflare and Apple.
- **Functional storage.** APNs registrations remain until unregistration or invalid-token pruning; no automatic expiry is asserted. Automation policy and cooldown state support user rules. Oversized notification snapshots expire within one hour and are removed on retrieval. Rate-limit state is short-lived; delivery-deduplication receipts in the development source expire within one day. An optional last-notify diagnostic (`LAST_NOTIFY_RETENTION="1"`, **off by default**) keeps one record per channel — HTTP status, Worker reason code and time, no camera/label/event/token/user agent — for 30 days so the in-app Push Doctor can show the last relay contact; enabling it changes the statement above and must be disclosed first.
- **Credentials.** v2 registration uses a bearer secret and hashed channel identifier. Legacy v1 URLs contain credentials: never log or share them. This Worker is not offline or zero-collection.
- **APNs JWT signing.** The worker signs requests using Apple's ES256 (P-256 ECDSA) algorithm. The APNs private key is stored as a Cloudflare encrypted secret, never accessible in code.
- **Source-tagged.** All notifications include `"source": "cloudflare-relay"` in the payload, so the Lumen app can identify and deduplicate them against local WebSocket notifications.

## Endpoints

### `POST /v1/notify/<secret>/<device_token>`

The push endpoint. `lumen-push-relay` POSTs here for each Frigate event that passes its filters. The URL is unique per Lumen device and is generated inside the app (Settings → Push Notifications → Copy URL).

Custom producers may POST to this endpoint only if they implement the validated Review contract below. Legacy raw `frigate/events` payloads are rejected.

**Query parameters:**
- `?cam=<camera_name>` — Only forward events from this camera (free tier restriction)
- `?sandbox=1` — Use APNs sandbox (development builds only)

**Request body:** Canonical correlated Review envelope:
```json
{
  "source": "cloudflare-relay",
  "sourceSchema": "frigate-review-v1",
  "reviewId": "review-1710756000",
  "reviewSeverity": "alert",
  "eventId": "1710756000.123-abc",
  "camera": "front_door",
  "label": "person",
  "detected_at": 1710756000.123,
  "score": 0.87,
  "zones": ["porch"],
  "camera_display_name": "Back Porch"
}
```

`camera_display_name` is optional: control/bidi characters are stripped, whitespace collapsed, and the value capped at 64 characters. When present it replaces the prettified camera id in the alert subtitle and is forwarded as `camera_display_name`; when absent or unusable the payload is unchanged.

**Response:** always HTTP 200 for a terminal outcome (relays retry non-2xx), 502 only if an APNs send failed. Body:
```json
{"ok":true,"delivered":1,"suppressed":1,"outcomes":[{"outcome":"sent","reason":"apns_accepted"},{"outcome":"rate_limited","reason":"same_camera_within_rate_limit"}]}
```
`outcome` is one of `sent`, `rate_limited`, `duplicate`, `filtered`, `cooldown`, `failed`; no tokens, ids or camera names are returned. Requests that end before fan-out return `outcomes: []` with a `reason` (`stale_event`, `camera_not_selected`, `review_ended`, `suppressed_by_automation_policy`).

**Filtering (server-side):**
- Missing/malformed Review authority is rejected before APNs
- Stale events and camera-route mismatches are rejected
- Rate limiting is applied per device token and camera (5 s default, `RATE_LIMIT_SECONDS`); another camera is never throttled
- Signed Automation V4 decisions are accepted only when their MAC and active policy revision/hash match; suppression never calls APNs

### `PUT /v2/channels/<channel-id>/automation-policy`

The Lumen app synchronizes the canonical Automation V4 policy to this endpoint
with the same `Bearer <push-secret>` proof used by device registration. The
Worker verifies the exact SHA-256 hash and rejects unsupported always-on
conditions or actions instead of applying a partial policy. Its per-channel
decision key is envelope-encrypted with AES-GCM before KV persistence; the
plaintext key and bearer are never logged or stored.

`DELETE` on the same authenticated resource removes the policy and cooldown
state when no always-on rule remains.

**APNs payload sent:**
```json
{
  "aps": {
    "alert": {
      "title": "Person Detected",
      "subtitle": "Front Door",
      "body": "Zone: porch | Confidence: 87%"
    },
    "sound": "default",
    "interruption-level": "time-sensitive",
    "category": "FRIGATE_EVENT",
    "thread-id": "front_door",
    "mutable-content": 1
  },
  "eventId": "1710756000.123-abc",
  "camera": "front_door",
  "label": "person",
  "zones": ["porch"],
  "source": "cloudflare-relay"
}
```

### `POST /v1/test/<secret>/<device_token>`

Sends a test push notification. Rate limited to 1 per 60 seconds per device token; a repeat inside that window returns `200 {"ok":true,"delivered":0,"reason":"test_recently_sent"}` (`POST /v2/channels/<id>/test` behaves the same and returns `{"ok":true,"delivered":n}` on success).

## Self-hosting

You can deploy your own instance of this worker to Cloudflare:

### Prerequisites
- Cloudflare account (free tier works)
- Apple Developer account with APNs key (.p8 file)
- Node.js 18+

### Setup

1. Clone this repo:
```bash
git clone https://github.com/lorislabapp/lumen-push.git
cd lumen-push
npm install
```

2. Create a KV namespace for rate limiting:
```bash
npx wrangler kv:namespace create RATE_LIMIT
```

3. Update `wrangler.toml` with the KV namespace ID from the output above.

4. Store your APNs secrets:
```bash
npx wrangler secret put APNS_KEY        # paste your .p8 key contents
npx wrangler secret put APNS_KEY_ID     # key ID from Apple Developer portal
npx wrangler secret put APNS_TEAM_ID    # your Apple Developer team ID
npx wrangler secret put APNS_BUNDLE_ID  # com.lorislab.lumenforfrigate (or your own bundle ID)
npx wrangler secret put KILL_SWITCH     # "0" (set to "1" to instantly disable all pushes)
npx wrangler secret put AUTOMATION_POLICY_KEK_B64 # base64 of 32 random bytes; wraps per-channel Automation keys in KV
```

5. Deploy:
```bash
npm run deploy
```

6. In Lumen, go to Settings > Push Notifications and replace the relay URL with your worker URL.

### Local development

```bash
npx wrangler dev --local
```

## Cost

On Cloudflare's free tier:
- 100,000 worker requests/day
- 100,000 KV reads/day, 1,000 KV writes/day

For a typical Frigate setup with 5-10 cameras, this handles thousands of events per day at zero cost.

## License

MIT

## Related

- [Lumen for Frigate](https://apps.apple.com/app/id6760238729) — Native Apple companion app for Frigate NVR
- [LumenTV](https://apps.apple.com/app/id6760317319) — Lumen for Apple TV
- [lumen-push-relay](https://github.com/lorislabapp/lumen-push-relay) — MQTT→Worker bridge (the thing most users need to run)
- [Frigate NVR](https://github.com/blakeblackshear/frigate) — Open-source AI-powered NVR
- [LorisLabs](https://lorislab.fr) — Developer website


## Device delivery filters (v1)

New app versions can register an allowlisted per-device delivery policy and its revision hash with the authenticated device registration. The acknowledgment confirms the revision stored by the service. Registered filters enforce labels, Frigate top_score, stationary/missing motion state and optional Review-alert-only selection before APNs. A configured cooldown is consumed only after APNs accepts a notification. Registrations and these settings remain until removal; they are functional configuration, not usage analytics. Device policies never contain full app settings, credentials or geolocation.

Migration: old raw-object producers remain a compatibility path for devices that have not selected Review-only filtering. They are never relabelled as Review items, never assigned invented Review IDs or scores, and cannot authorize critical presentation. The Worker tags its APNs payloads consistently so client filtering cannot be bypassed by the producer's source label. Review-alert-only rejects raw legacy objects: upgrade the local relay to its correlated Review contract before enabling that option. The old producer path is not evidence that an event appears in Frigate Review. New Review decisions continue to use producer-side persistent deduplication; Worker KV receipts/cooldowns are eventually consistent and do not promise global exactly-once delivery.
