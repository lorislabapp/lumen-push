# lumen-push

Open-source Cloudflare Worker that relays [Frigate NVR](https://github.com/blakeblackshear/frigate) detection events to Apple Push Notifications for [Lumen for Frigate](https://apps.apple.com/app/id6760238729).

**No server to manage. No database. No persistent storage.** A stateless Cloudflare Worker that signs APNs JWTs and delivers pushes in under 1 second.

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
      |  3. Rate limits: 30s per device token (Cloudflare KV)
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

> **Why two pieces?** Frigate publishes events over MQTT but does not send HTTP webhooks natively, so something has to subscribe to MQTT and forward to HTTPS. We split the work: the relay is tiny and stays on your network (sees your MQTT), the Worker is stateless and holds the APNs key (signs and delivers). Only the compact notification payload (camera, label, zone, confidence) leaves your network.

## Privacy & Security

- **No data stored.** The worker is stateless. The only KV writes are rate-limit timestamps (TTL: 120s, auto-deleted).
- **No accounts.** There is no user database, no registration, no tracking.
- **No logging.** Request bodies are not logged. Only APNs errors are logged to Cloudflare console.
- **URL-based security.** The webhook URL contains a 128-bit random secret generated on-device. The secret never leaves your device and Frigate instance. An attacker would need to guess a 32-character hex string (2^128 combinations) to send a push to your device.
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
  "zones": ["porch"]
}
```

**Filtering (server-side):**
- Missing/malformed Review authority is rejected before APNs
- Stale events and camera-route mismatches are rejected
- Rate limiting is applied per device token
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

Sends a test push notification. Rate limited to 1 per 60 seconds per device token.

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
