export interface Env {
  APNS_KEY: string;
  APNS_KEY_ID: string;
  APNS_TEAM_ID: string;
  APNS_BUNDLE_ID: string;
  KILL_SWITCH: string;
  // Maximum age (seconds) of a Frigate event we will forward to APNs. Older
  // events are dropped as stale (MQTT replay, relay backlog, etc.). Set to "0"
  // to disable. Defaults to 120 if unset.
  MAX_EVENT_AGE_SECONDS?: string;
  // Minimum gap (seconds) between consecutive pushes to the same APNs token.
  // Prevents runaway notification loops without dropping legitimate
  // consecutive detections. Defaults to 5 if unset (was 30 historically;
  // 30 was too aggressive for security cameras — see commit message).
  RATE_LIMIT_SECONDS?: string;
  RATE_LIMIT: KVNamespace;
  // Phase 1 multi-device fan-out: maps `secret` -> list of registered devices.
  // Populated via POST /v1/register. Consumed by handleNotify to fan out
  // a single Frigate event to every device that shares the secret. If empty
  // for a given secret, handleNotify falls back to the single token in the
  // URL (backward compatibility with pre-fan-out clients).
  DEVICES: KVNamespace;
  // Workers Analytics Engine dataset for per-user / per-country notification
  // stats. Optional so deploys without the binding still work (we no-op).
  // Schema (see writeStat): blob1=tokenPrefix, blob2=country, blob3=camera,
  // blob4=label, blob5=outcome ("sent"|"rate_limited"), blob6=platform.
  // double1=count(=1), double2=top_score. index1=tokenPrefix.
  NOTIF_STATS?: AnalyticsEngineDataset;
}

/**
 * One device record stored in the DEVICES KV under key `devices:{secret}`.
 * Values are stored as a JSON array of RegisteredDevice.
 */
interface RegisteredDevice {
  token: string;        // APNs device token (hex)
  sandbox: boolean;     // true for DEBUG builds (APNs sandbox), false for App Store
  platform?: string;    // "ios" | "macos" | "watchos" | "visionos" | "tvos"
  registered_at: number; // Unix epoch seconds
}

interface FrigateEvent {
  id: string;
  camera: string;
  label: string;
  top_score: number;
  zones: string[];
  has_snapshot: boolean;
  has_clip: boolean;
  start_time: number;
  end_time: number | null;
  stationary: boolean;
  sub_label: string | null;
}

interface FrigateWebhook {
  type: string;
  before: FrigateEvent | null;
  after: FrigateEvent | null;
}

function parseRoute(url: URL): { endpoint: string; secret: string; token: string; cam: string | null; sandbox: boolean; platform: string | null } | null {
  const match = url.pathname.match(/^\/v1\/(notify|test|register|unregister)\/([0-9a-fA-F]{32})\/([0-9a-fA-F]{32,128})$/);
  if (!match) return null;
  return {
    endpoint: match[1],
    secret: match[2],
    token: match[3],
    cam: url.searchParams.get("cam"),
    sandbox: url.searchParams.get("sandbox") === "1",
    platform: url.searchParams.get("platform"),
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (env.KILL_SWITCH === "1") {
      return new Response("Service temporarily disabled", { status: 503 });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    const url = new URL(request.url);
    const route = parseRoute(url);
    if (!route) {
      return new Response("Bad request", { status: 400 });
    }

    const contentLength = request.headers.get("content-length");
    if (contentLength && parseInt(contentLength) > 4096) {
      return new Response("Payload too large", { status: 413 });
    }

    if (route.endpoint === "test") {
      return handleTest(route.token, route.sandbox, env);
    }

    if (route.endpoint === "register") {
      return handleRegister(route, env);
    }

    if (route.endpoint === "unregister") {
      return handleUnregister(route, env);
    }

    // CF-IPCountry is set by Cloudflare for the request's origin (Frigate
    // server). It approximates where the user's NVR — and so the user — is
    // located. Used for per-country notification stats.
    const country = request.headers.get("CF-IPCountry") ?? "??";
    return handleNotify(request, route, country, env);
  },
};

// --- Device registry (Phase 1 multi-device fan-out) ---

/** Max devices per secret. Guards against accidental runaway registration. */
const MAX_DEVICES_PER_SECRET = 16;

async function readDevices(secret: string, env: Env): Promise<RegisteredDevice[]> {
  const raw = await env.DEVICES.get(`devices:${secret}`);
  if (!raw) return [];
  try {
    const list = JSON.parse(raw) as RegisteredDevice[];
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

async function writeDevices(secret: string, list: RegisteredDevice[], env: Env): Promise<void> {
  await env.DEVICES.put(`devices:${secret}`, JSON.stringify(list));
}

async function handleRegister(
  route: { secret: string; token: string; sandbox: boolean; platform: string | null },
  env: Env
): Promise<Response> {
  const devices = await readDevices(route.secret, env);

  // Upsert: if token already in list, update its metadata; else append.
  const existingIdx = devices.findIndex((d) => d.token === route.token);
  const record: RegisteredDevice = {
    token: route.token,
    sandbox: route.sandbox,
    platform: route.platform ?? undefined,
    registered_at: Math.floor(Date.now() / 1000),
  };

  if (existingIdx >= 0) {
    devices[existingIdx] = record;
  } else {
    if (devices.length >= MAX_DEVICES_PER_SECRET) {
      // Evict oldest by registered_at to keep list bounded.
      devices.sort((a, b) => a.registered_at - b.registered_at);
      devices.shift();
    }
    devices.push(record);
  }

  await writeDevices(route.secret, devices, env);
  return new Response(
    JSON.stringify({ ok: true, device_count: devices.length }),
    { status: 200, headers: { "content-type": "application/json" } }
  );
}

async function handleUnregister(
  route: { secret: string; token: string },
  env: Env
): Promise<Response> {
  const devices = await readDevices(route.secret, env);
  const filtered = devices.filter((d) => d.token !== route.token);
  if (filtered.length !== devices.length) {
    await writeDevices(route.secret, filtered, env);
  }
  return new Response(
    JSON.stringify({ ok: true, device_count: filtered.length }),
    { status: 200, headers: { "content-type": "application/json" } }
  );
}

/**
 * Per-token rate-limit state, stored in the Workers Cache API instead of KV.
 *
 * Why: KV writes are capped at 1 000/day on the Workers Free plan and every
 * notification fan-out wrote one key, which pushed us close to the cap. The
 * Cache API has no such per-op quota.
 *
 * Trade-off: caches.default is per-data-center, not globally consistent. For
 * per-token rate limiting where requests for one device usually hit the same
 * colo (Frigate origin → APNs), this is effectively equivalent to KV with a
 * negligible chance of a duplicate notification slipping through.
 */
const RATE_LIMIT_BASE = "https://lumen-push.internal/rate";

function rateLimitURL(prefix: string, token: string): string {
  return `${RATE_LIMIT_BASE}/${prefix}/${encodeURIComponent(token)}`;
}

async function rateLimitGet(prefix: string, token: string): Promise<string | null> {
  const hit = await caches.default.match(rateLimitURL(prefix, token));
  return hit ? await hit.text() : null;
}

async function rateLimitPut(
  prefix: string,
  token: string,
  value: string,
  ttlSeconds: number
): Promise<void> {
  const res = new Response(value, {
    headers: { "Cache-Control": `max-age=${ttlSeconds}` },
  });
  await caches.default.put(rateLimitURL(prefix, token), res);
}

async function handleTest(token: string, sandbox: boolean, env: Env): Promise<Response> {
  const lastTest = await rateLimitGet("test", token);
  if (lastTest) {
    return new Response("OK", { status: 200 });
  }
  await rateLimitPut("test", token, String(Date.now()), 60);

  const payload = {
    aps: {
      alert: {
        title: "Test Push",
        subtitle: "Lumen for Frigate",
        body: "Push notifications are working!",
      },
      sound: "default",
    },
    source: "cloudflare-relay-test",
  };

  await sendAPNs(token, payload, sandbox, env);
  return new Response("OK", { status: 200 });
}

async function handleNotify(
  request: Request,
  route: { secret: string; token: string; cam: string | null; sandbox: boolean },
  country: string,
  env: Env
): Promise<Response> {
  let body: FrigateWebhook;
  try {
    body = await request.json<FrigateWebhook>();
  } catch {
    return new Response("Bad request", { status: 400 });
  }

  if (body.type !== "new") {
    return new Response("OK", { status: 200 });
  }

  const event = body.after;
  if (!event?.id || !event?.camera || !event?.label || event?.top_score === undefined) {
    return new Response("Bad request", { status: 400 });
  }

  if (route.cam && event.camera !== route.cam) {
    return new Response("OK", { status: 200 });
  }

  if (event.stationary) {
    return new Response("OK", { status: 200 });
  }

  if (event.top_score < 0.5) {
    return new Response("OK", { status: 200 });
  }

  // Drop stale events. Guards against MQTT replay, relay backlog, or any
  // upstream queue that could produce a "fake-fresh" push for something that
  // actually happened hours ago. `start_time` is Unix epoch seconds. We skip
  // the check when start_time is missing/zero so malformed events still get
  // forwarded (matches relay.py behavior).
  const maxAgeStr = env.MAX_EVENT_AGE_SECONDS ?? "120";
  const maxAge = parseInt(maxAgeStr, 10);
  if (maxAge > 0 && typeof event.start_time === "number" && event.start_time > 0) {
    const ageSeconds = Date.now() / 1000 - event.start_time;
    if (ageSeconds > maxAge) {
      console.log(`Dropping stale event ${event.id}: age=${ageSeconds.toFixed(0)}s max=${maxAge}s`);
      return new Response("OK", { status: 200 });
    }
  }

  // Build APNs payload
  const cameraName = event.camera.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  const label = event.label.replace(/\b\w/g, (c) => c.toUpperCase());

  const bodyParts: string[] = [];
  if (event.zones?.length) {
    bodyParts.push(`Zone: ${event.zones.join(", ")}`);
  }
  bodyParts.push(`Confidence: ${Math.round(event.top_score * 100)}%`);

  const apnsPayload = {
    aps: {
      alert: {
        title: `${label} Detected`,
        subtitle: cameraName,
        body: bodyParts.join(" | "),
      },
      sound: "default",
      "interruption-level": "time-sensitive",
      category: "FRIGATE_EVENT",
      "thread-id": event.camera,
      "mutable-content": 1,
    },
    eventId: event.id,
    camera: event.camera,
    label: event.label,
    zones: event.zones || [],
    // Forwarded so the NSE rules engine can evaluate scoreAtLeast and
    // subLabelEquals leaves on closed-app pushes (rules engine is otherwise
    // limited to camera/label/zones/time when running in the extension).
    top_score: event.top_score,
    sub_label: event.sub_label,
    // Unix epoch seconds of Frigate detection. The NSE uses this to show the
    // user "detected Xs ago" so real-time pushes can be visually distinguished
    // from pushes APNs held while the device was unreachable.
    detected_at: event.start_time,
    source: "cloudflare-relay",
  };

  // Phase 1 fan-out: look up all devices registered under this secret. If the
  // user has registered via POST /v1/register (iPhone + iPad + Mac + Watch...),
  // fan out to every one in parallel. Each device has its own 30s rate-limit
  // bucket so one spammy camera doesn't block a new device from receiving.
  //
  // If no devices are registered (pre-fan-out client still using the single
  // URL token), fall back to that URL token so existing setups keep working.
  const registered = await readDevices(route.secret, env);
  const targets: RegisteredDevice[] = registered.length > 0
    ? registered
    : [{ token: route.token, sandbox: route.sandbox, registered_at: 0 }];

  const meta: NotifyMeta = {
    camera: event.camera,
    label: event.label,
    topScore: event.top_score,
    country,
  };

  await Promise.all(
    targets.map((device) => sendToDeviceRateLimited(device, apnsPayload, meta, env))
  );

  return new Response("OK", { status: 200 });
}

interface NotifyMeta {
  camera: string;
  label: string;
  topScore: number;
  country: string;
}

/**
 * Records one data point in Workers Analytics Engine. No-op if the binding is
 * missing (e.g. on first deploy after adding the binding to wrangler.toml).
 *
 * Privacy: the device token is truncated to its first 8 hex chars before
 * being stored. That's a stable per-device pseudonym (sufficient to count
 * unique users) but not the actual APNs token — we never expose the full
 * token in stats logs. CF-IPCountry is a 2-letter country code (or "??").
 */
function writeStat(
  env: Env,
  device: RegisteredDevice,
  meta: NotifyMeta,
  outcome: "sent" | "rate_limited"
): void {
  if (!env.NOTIF_STATS) return;
  const userKey = device.token.slice(0, 8);
  env.NOTIF_STATS.writeDataPoint({
    blobs: [
      userKey,
      meta.country,
      meta.camera,
      meta.label,
      outcome,
      device.platform ?? "unknown",
    ],
    doubles: [1, meta.topScore],
    indexes: [userKey],
  });
}

/**
 * Send the APNs payload to one device, honouring a per-token 30s rate limit.
 * Returns silently if rate-limited or if APNs errors — errors are logged in
 * sendAPNs. This way one failing device does not block other targets in the
 * same Promise.all fan-out.
 */
async function sendToDeviceRateLimited(
  device: RegisteredDevice,
  payload: unknown,
  meta: NotifyMeta,
  env: Env
): Promise<void> {
  // Per-device rate limit: 5s minimum gap between pushes to the same
  // APNs token. Was 30s — too aggressive for security cameras where
  // a single intrusion can fire 5+ legitimate events in <30s. Users
  // were perceiving 30s+ latency because the FIRST event hit, the
  // rate-limit blocked the next 5 detections, and they only saw the
  // 6th detection ~30s later than their visible event.
  //
  // 5s still suppresses runaway loops (one camera firing every second
  // for hours) without dropping legitimate consecutive detections.
  // Override via env.RATE_LIMIT_SECONDS for deployments that want a
  // different cadence.
  const minIntervalSeconds = parseInt(env.RATE_LIMIT_SECONDS ?? "5", 10);
  const lastPush = await rateLimitGet("rl", device.token);
  if (lastPush) {
    const elapsed = (Date.now() - parseInt(lastPush)) / 1000;
    if (elapsed < minIntervalSeconds) {
      writeStat(env, device, meta, "rate_limited");
      return;
    }
  }
  await rateLimitPut("rl", device.token, String(Date.now()), 60);
  await sendAPNs(device.token, payload, device.sandbox, env);
  writeStat(env, device, meta, "sent");
}

// --- APNs JWT signing and delivery ---

let cachedJWT: { token: string; expiry: number } | null = null;

function base64url(data: Uint8Array): string {
  let binary = "";
  for (const byte of data) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function getAPNsJWT(env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  if (cachedJWT && cachedJWT.expiry > now + 600) {
    return cachedJWT.token;
  }

  const header = base64url(new TextEncoder().encode(JSON.stringify({
    alg: "ES256",
    kid: env.APNS_KEY_ID,
  })));

  const payload = base64url(new TextEncoder().encode(JSON.stringify({
    iss: env.APNS_TEAM_ID,
    iat: now,
  })));

  const signingInput = `${header}.${payload}`;

  const pemContents = env.APNS_KEY
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");

  const keyData = Uint8Array.from(atob(pemContents), (c) => c.charCodeAt(0));

  const key = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(signingInput)
  );

  const sigBytes = new Uint8Array(signature);
  // Web Crypto may return raw r||s (64 bytes) or DER-encoded (70-72 bytes)
  const rawSig = sigBytes.length === 64 ? sigBytes : derToRaw(sigBytes);
  const jwt = `${signingInput}.${base64url(rawSig)}`;

  cachedJWT = { token: jwt, expiry: now + 3000 };
  return jwt;
}

function derToRaw(der: Uint8Array): Uint8Array {
  const raw = new Uint8Array(64);
  let offset = 2;

  offset++;
  const rLen = der[offset++];
  const rStart = rLen > 32 ? offset + (rLen - 32) : offset;
  const rDest = rLen < 32 ? 32 - rLen : 0;
  raw.set(der.slice(rStart, offset + rLen), rDest);
  offset += rLen;

  offset++;
  const sLen = der[offset++];
  const sStart = sLen > 32 ? offset + (sLen - 32) : offset;
  const sDest = sLen < 32 ? 64 - sLen : 32;
  raw.set(der.slice(sStart, offset + sLen), sDest);

  return raw;
}

async function sendAPNs(token: string, payload: unknown, sandbox: boolean, env: Env): Promise<void> {
  try {
    const jwt = await getAPNsJWT(env);
    const apnsHost = sandbox ? "api.sandbox.push.apple.com" : "api.push.apple.com";

    // apns-expiration: retry for 1h on transient delivery failures
    // (device offline, asleep, low-power). `0` would drop immediately.
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;

    const response = await fetch(
      `https://${apnsHost}/3/device/${token}`,
      {
        method: "POST",
        headers: {
          authorization: `bearer ${jwt}`,
          "apns-push-type": "alert",
          "apns-topic": env.APNS_BUNDLE_ID,
          "apns-priority": "10",
          "apns-expiration": String(expiresAt),
          "content-type": "application/json",
        },
        body: JSON.stringify(payload),
      }
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      console.error(`APNs error ${response.status}: ${errText}`);
    }
  } catch (e) {
    console.error(`APNs request failed: ${e}`);
  }
}

