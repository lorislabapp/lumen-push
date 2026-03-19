export interface Env {
  APNS_KEY: string;
  APNS_KEY_ID: string;
  APNS_TEAM_ID: string;
  APNS_BUNDLE_ID: string;
  KILL_SWITCH: string;
  RATE_LIMIT: KVNamespace;
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

function parseRoute(url: URL): { endpoint: string; secret: string; token: string; cam: string | null } | null {
  const match = url.pathname.match(/^\/v1\/(notify|test)\/([0-9a-fA-F]{32})\/([0-9a-fA-F]{32,128})$/);
  if (!match) return null;
  return {
    endpoint: match[1],
    secret: match[2],
    token: match[3],
    cam: url.searchParams.get("cam"),
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
      return handleTest(route.token, env);
    }

    return handleNotify(request, route, env);
  },
};

async function handleTest(token: string, env: Env): Promise<Response> {
  const testKey = `test:${token}`;
  const lastTest = await env.RATE_LIMIT.get(testKey);
  if (lastTest) {
    return new Response("OK", { status: 200 });
  }
  await env.RATE_LIMIT.put(testKey, String(Date.now()), { expirationTtl: 60 });

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

  await sendAPNs(token, payload, env);
  return new Response("OK", { status: 200 });
}

async function handleNotify(
  request: Request,
  route: { secret: string; token: string; cam: string | null },
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

  // Rate limit via KV (30s per token)
  const rateKey = `rl:${route.token}`;
  const lastPush = await env.RATE_LIMIT.get(rateKey);
  if (lastPush) {
    const elapsed = (Date.now() - parseInt(lastPush)) / 1000;
    if (elapsed < 30) {
      return new Response("OK", { status: 200 });
    }
  }
  await env.RATE_LIMIT.put(rateKey, String(Date.now()), { expirationTtl: 120 });

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
    source: "cloudflare-relay",
  };

  await sendAPNs(route.token, apnsPayload, env);
  return new Response("OK", { status: 200 });
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

  const rawSig = derToRaw(new Uint8Array(signature));
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

async function sendAPNs(token: string, payload: unknown, env: Env): Promise<void> {
  try {
    const jwt = await getAPNsJWT(env);

    const response = await fetch(
      `https://api.push.apple.com/3/device/${token}`,
      {
        method: "POST",
        headers: {
          authorization: `bearer ${jwt}`,
          "apns-push-type": "alert",
          "apns-topic": env.APNS_BUNDLE_ID,
          "apns-priority": "10",
          "apns-expiration": "0",
          "content-type": "application/json",
        },
        body: JSON.stringify(payload),
      }
    );

    if (!response.ok) {
      console.error(`APNs error: ${response.status}`);
    }
  } catch (e) {
    console.error(`APNs request failed: ${e}`);
  }
}
