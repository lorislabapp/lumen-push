# lumen-push

Cloudflare Worker APNs relay for Lumen for Frigate.

Receives Frigate 0.15+ webhook events and delivers Apple Push Notifications to Lumen users' devices in < 1 second.

## Setup

1. Install dependencies: `npm install`
2. Create KV namespace: `npx wrangler kv:namespace create RATE_LIMIT`
3. Update `wrangler.toml` with the KV namespace ID
4. Store secrets:

```bash
npx wrangler secret put APNS_KEY        # paste .p8 key contents
npx wrangler secret put APNS_KEY_ID     # key ID from Apple Developer portal
npx wrangler secret put APNS_TEAM_ID    # team ID
npx wrangler secret put APNS_BUNDLE_ID  # app bundle ID
npx wrangler secret put KILL_SWITCH     # "0"
```

5. Deploy: `npm run deploy`

## Endpoints

- `POST /v1/notify/<secret>/<device_token>[?cam=<camera>]` — Frigate webhook -> APNs push
- `POST /v1/test/<secret>/<device_token>` — Send test push notification

## Local Development

```bash
npx wrangler dev --local
```
