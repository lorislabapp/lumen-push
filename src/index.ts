import { classifyEvent } from "./classifier";
import {
  evaluateAndSignPolicy,
  StoredAutomationPolicy,
  validatePolicyUpload,
} from "./automation";

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
  /** Corrections resolve minutes later; judged on their own clock. */
  LATE_IDENTITY_MAX_AGE_SECONDS?: string;
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
  // blob4=label, blob5=outcome ("sent"|"rate_limited"|"failed"), blob6=platform.
  // double1=count(=1), double2=top_score. index1=tokenPrefix.
  NOTIF_STATS?: AnalyticsEngineDataset;
  // GET /stats?token=… page. Required for the HTML dashboard. Generated with
  // openssl rand -hex 32 and set via `wrangler secret put STATS_TOKEN`.
  STATS_TOKEN?: string;
  // Account ID used to call the Analytics Engine SQL API. Plain var (not a
  // secret — it's already in the URL of any wrangler deploy).
  CF_ACCOUNT_ID?: string;
  // CF API token with Account Analytics:Read scope. Used by /stats and the
  // daily Cron digest to query the NOTIF_STATS dataset. Set via
  // `wrangler secret put CF_ANALYTICS_TOKEN`.
  CF_ANALYTICS_TOKEN?: string;
  // Slack incoming webhook URL. Optional — if absent, the Cron handler
  // skips Slack delivery (no-op). Set via
  // `wrangler secret put SLACK_WEBHOOK_URL` once the webhook is created.
  SLACK_WEBHOOK_URL?: string;
  // Shared only with the always-on policy authority. Required before a
  // lumen-automation-decision-v1 envelope can affect APNs presentation.
  AUTOMATION_DECISION_KEY?: string;
  // Preferred binary-safe representation for manually provisioned legacy
  // authorities. Per-channel policies carry their own 32-byte base64 key.
  AUTOMATION_DECISION_KEY_B64?: string;
  // 32-byte base64 AES-GCM key used only to envelope per-channel decision
  // keys before they enter KV. Must be provisioned as a Worker secret.
  AUTOMATION_POLICY_KEK_B64?: string;
  // Active policy acknowledgment from the authority. Automation decisions
  // fail closed unless both values exactly match the signed envelope.
  AUTOMATION_POLICY_REVISION?: string;
  AUTOMATION_POLICY_HASH?: string;
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

export interface ReviewEnvelope {
  source: string;
  sourceSchema: "frigate-review-v1";
  reviewId: string;
  reviewSeverity: "detection" | "alert";
  eventId: string;
  camera: string;
  label: string;
  detected_at: number;
  score: number;
  zones?: string[];
  sub_label?: string | null;
  stationary?: boolean | null;
  has_clip?: boolean;
  recognized_plate?: string | null;
  compressed_snapshot?: string;  // Base64-encoded JPEG from relay pre-compression
  /** Short human summary from Frigate (GenAI description or review title). */
  description?: string | null;
  /**
   * A correction to a notification already on screen: a face resolved or a
   * description written after the fact. Reuses the original collapse id so the
   * banner is rewritten instead of alerting again.
   */
  isEnrichment?: boolean;
  /** Set only by normalizeNotifyBody for a published relay's lumen_critical flag. */
  legacyCritical?: boolean;
  custom_title?: string;
  custom_body?: string;
  automationSchema?: string;
  policyRevision?: number;
  policyHash?: string;
  ruleId?: string;
  branchId?: string;
  decisionId?: string;
  presentation?: AutomationPresentation;
  decisionMAC?: string;
}

interface AutomationPresentation {
  disposition: "normal" | "critical" | "suppress";
  priority: "normal" | "timeSensitive";
  category?: string;
  spokenTemplate?: string;
  criticalVolume?: number;
}

function canonicalVolume(value: number | undefined): string {
  if (value === undefined) return "";
  return value.toFixed(6).replace(/0+$/, "").replace(/\.$/, "");
}

function automationSigningInput(event: ReviewEnvelope): string | null {
  if (event.automationSchema !== "lumen-automation-decision-v1") return null;
  if (!Number.isInteger(event.policyRevision) || (event.policyRevision ?? -1) < 0) return null;
  if (!event.policyHash?.match(/^sha256:[0-9a-f]{64}$/)) return null;
  if (!event.ruleId || !event.branchId || !event.decisionId || !event.presentation) return null;
  if (event.decisionId !== `${event.reviewId}/${event.reviewSeverity}/${event.policyRevision}`) return null;
  const p = event.presentation;
  if (!["normal", "critical", "suppress"].includes(p.disposition)) return null;
  if (!["normal", "timeSensitive"].includes(p.priority)) return null;
  if (p.criticalVolume !== undefined && (!Number.isFinite(p.criticalVolume) || p.criticalVolume < 0 || p.criticalVolume > 1)) return null;
  if (p.disposition === "critical" && (p.priority !== "timeSensitive" || p.criticalVolume === undefined)) return null;
  if (p.disposition !== "critical" && p.criticalVolume !== undefined) return null;
  if (p.category !== undefined && (p.category.length === 0 || p.category.length > 64)) return null;
  if (p.spokenTemplate !== undefined && (p.spokenTemplate.length === 0 || p.spokenTemplate.length > 64)) return null;
  return [
    event.reviewId, event.reviewSeverity, event.eventId,
    String(event.policyRevision), event.policyHash,
    event.ruleId, event.branchId, event.decisionId,
    p.disposition, p.priority, p.category ?? "", p.spokenTemplate ?? "",
    canonicalVolume(p.criticalVolume),
  ].join("\n");
}

function decodeBase64Key(value: string): Uint8Array | null {
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return bytes.byteLength === 32 ? bytes : null;
  } catch { return null; }
}

export async function verifyAutomationDecision(
  event: ReviewEnvelope,
  key: string | undefined,
  keyBase64?: string,
): Promise<boolean> {
  const input = automationSigningInput(event);
  const keyBytes = keyBase64 ? decodeBase64Key(keyBase64) : (key ? new TextEncoder().encode(key) : null);
  if (!input || !keyBytes || !event.decisionMAC?.match(/^[0-9a-f]{64}$/)) return false;
  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
  );
  const signature = Uint8Array.from(event.decisionMAC.match(/../g) ?? [], (hex) => parseInt(hex, 16));
  return crypto.subtle.verify("HMAC", cryptoKey, signature, new TextEncoder().encode(input));
}

export function validateReviewEnvelope(value: unknown): ReviewEnvelope | null {
  if (!value || typeof value !== "object") return null;
  const body = value as Record<string, unknown>;
  if (body.sourceSchema !== "frigate-review-v1") return null;
  if (body.reviewSeverity !== "detection" && body.reviewSeverity !== "alert") return null;
  for (const key of ["source", "reviewId", "eventId", "camera", "label"] as const) {
    if (typeof body[key] !== "string" || body[key].length === 0 || body[key].length > 256) return null;
  }
  if (typeof body.detected_at !== "number" || !Number.isFinite(body.detected_at) || body.detected_at <= 0) return null;
  if (typeof body.score !== "number" || !Number.isFinite(body.score) || body.score < 0 || body.score > 1) return null;
  if (body.zones !== undefined && (!Array.isArray(body.zones) || body.zones.length > 32 || body.zones.some((zone) => typeof zone !== "string" || zone.length === 0 || zone.length > 128))) return null;
  if (body.sub_label !== undefined && body.sub_label !== null
      && (typeof body.sub_label !== "string" || body.sub_label.length === 0 || body.sub_label.length > 128)) return null;
  if (body.stationary !== undefined && body.stationary !== null && typeof body.stationary !== "boolean") return null;
  if (body.has_clip !== undefined && typeof body.has_clip !== "boolean") return null;
  if (body.recognized_plate !== undefined && body.recognized_plate !== null
      && (typeof body.recognized_plate !== "string" || body.recognized_plate.length === 0 || body.recognized_plate.length > 64)) return null;
  if (body.description !== undefined && body.description !== null
      && (typeof body.description !== "string" || body.description.length === 0 || body.description.length > 500)) return null;
  if (body.isEnrichment !== undefined && typeof body.isEnrichment !== "boolean") return null;
  if (body.legacyCritical !== undefined) return null;
  return body as unknown as ReviewEnvelope;
}

function optionalString(value: unknown, max: number): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length <= max ? value : undefined;
}

/**
 * Relays already running in the field post snake_case Frigate events
 * (`top_score`, `start_time`, optional `review_id` / `source_schema`), not the
 * camelCase Review envelope. Map them onto the envelope so one Worker serves
 * both; returns "drop" for low-confidence events the v1 Worker also ignored.
 */
export function normalizeNotifyBody(value: unknown): ReviewEnvelope | "drop" | null {
  const envelope = validateReviewEnvelope(value);
  if (envelope) return envelope;
  if (!value || typeof value !== "object") return null;
  let body = value as Record<string, unknown>;
  // The published relay forwards Frigate's MQTT shape verbatim:
  // {"type":"new","before":null,"after":{...event}}. Unwrap it.
  if (typeof body.type === "string" && body.after && typeof body.after === "object") {
    if (body.type === "end") return "drop";
    body = body.after as Record<string, unknown>;
  }
  if ("sourceSchema" in body || "legacyCritical" in body) return null;
  const id = optionalString(body.id, 256);
  const camera = optionalString(body.camera, 256);
  const label = optionalString(body.label, 256);
  if (!id || !camera || !label) return null;
  const score = body.top_score;
  if (score !== undefined && (typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 1)) return null;
  const isReview = body.source_schema === "frigate-review-v1";
  if (score === undefined && !isReview) return null;
  if (typeof score === "number" && score < 0.5) return "drop";
  const detectedAt = typeof body.detected_at === "number" ? body.detected_at : body.start_time;
  const rawSubLabel = Array.isArray(body.sub_label) ? body.sub_label[0] : body.sub_label;
  const severity = body.review_severity === "detection" ? "detection" : "alert";
  const candidate: Record<string, unknown> = {
    source: optionalString(body.source, 256) ?? "legacy-relay",
    sourceSchema: "frigate-review-v1",
    reviewId: optionalString(body.review_id, 256) ?? id,
    reviewSeverity: severity,
    eventId: id,
    camera,
    label,
    detected_at: detectedAt,
    score: typeof score === "number" ? score : 1,
  };
  if (Array.isArray(body.zones)) candidate.zones = body.zones;
  const subLabel = optionalString(rawSubLabel, 128);
  if (subLabel) candidate.sub_label = subLabel;
  if (typeof body.stationary === "boolean") candidate.stationary = body.stationary;
  if (typeof body.has_clip === "boolean") candidate.has_clip = body.has_clip;
  const plate = optionalString(body.recognized_license_plate ?? body.recognized_plate, 64);
  if (plate) candidate.recognized_plate = plate;
  const description = optionalString(body.description, 500);
  if (description) candidate.description = description;
  if (typeof body.isEnrichment === "boolean") candidate.isEnrichment = body.isEnrichment;
  const normalized = validateReviewEnvelope(candidate);
  if (!normalized) return null;
  const snapshot = optionalString(body.compressed_snapshot, 2_000_000);
  if (snapshot) normalized.compressed_snapshot = snapshot;
  const title = optionalString(body.custom_title, 256);
  if (title) normalized.custom_title = title;
  const text = optionalString(body.custom_body, 1024);
  if (text) normalized.custom_body = text;
  if (body.lumen_critical === true) normalized.legacyCritical = true;
  return normalized;
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

function parseV2Route(url: URL): { endpoint: "notify" | "devices" | "test" | "automation-policy" | "status"; channelID: string; cam: string | null } | null {
  let match = url.pathname.match(/^\/v2\/notify\/([0-9a-f]{64})$/i);
  if (match) return { endpoint: "notify", channelID: match[1].toLowerCase(), cam: url.searchParams.get("cam") };
  match = url.pathname.match(/^\/v2\/channels\/([0-9a-f]{64})\/(devices|test|automation-policy|status)$/i);
  if (!match) return null;
  return { endpoint: match[2] as "devices" | "test" | "automation-policy" | "status", channelID: match[1].toLowerCase(), cam: null };
}

export async function channelIDForSecret(secret: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function authorizeChannel(request: Request, channelID: string): Promise<boolean> {
  const authorization = request.headers.get("Authorization") ?? "";
  if (!authorization.startsWith("Bearer ")) return false;
  const secret = authorization.slice(7);
  if (!/^[0-9a-f]{32}$/i.test(secret)) return false;
  return (await channelIDForSecret(secret)) === channelID;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (env.KILL_SWITCH === "1") {
      return new Response("Service temporarily disabled", { status: 503 });
    }

    const url = new URL(request.url);

    // V2 snapshot URLs are random bearer capabilities, single-use, and
    // explicitly non-cacheable. Event ids are never exposed in the URL.
    if (request.method === "GET") {
      const snapshot = url.pathname.match(/^\/v2\/snapshots\/([0-9a-f]{64})$/i);
      if (snapshot) {
        const key = `snapshot-v2:${snapshot[1].toLowerCase()}`;
        const compressed = await env.RATE_LIMIT.get(key);
        if (!compressed) return new Response("Not found", { status: 404 });
        await env.RATE_LIMIT.delete(key);
        return new Response(compressed, {
          headers: { "Content-Type": "text/plain", "Cache-Control": "no-store, private" },
        });
      }
    }

    // Stats dashboard (GET, secret-guarded). Lives outside the POST-only
    // /v1/* surface because it's a read-only diagnostic page.
    if (request.method === "GET" && url.pathname === "/stats") {
      return handleStats(request, env);
    }

    // Compressed snapshot retrieval (GET, public). Used by NSE when the
    // compressed snapshot was too large to embed in the APNs payload.
    // Shape: /snapshot/<event-id>
    if (request.method === "GET" && url.pathname.startsWith("/snapshot/")) {
      return new Response("Legacy snapshot endpoint removed", { status: 410 });
    }

    const v2 = parseV2Route(url);
    if (v2) {
      if (v2.endpoint === "automation-policy" && request.method === "PUT") {
        return handleAutomationPolicyPut(request, v2.channelID, env);
      }
      if (v2.endpoint === "automation-policy" && request.method === "DELETE") {
        return handleAutomationPolicyDelete(request, v2.channelID, env);
      }
      if (request.method === "POST" && v2.endpoint === "devices") {
        return handleV2Device(request, v2.channelID, env, false);
      }
      if (request.method === "DELETE" && v2.endpoint === "devices") {
        return handleV2Device(request, v2.channelID, env, true);
      }
      if (request.method === "POST" && v2.endpoint === "test") {
        if (!(await authorizeChannel(request, v2.channelID))) return new Response("Unauthorized", { status: 401 });
        const devices = await readDevices(v2.channelID, env);
        if (devices.length === 0) return new Response("No registered devices", { status: 409 });
        const results = await Promise.all(
          devices.map((device) => handleTest(device.token, device.sandbox, env))
        );
        return results.some((result) => result.ok)
          ? new Response("OK", { status: 200 })
          : new Response("APNs test delivery failed", { status: 502 });
      }
      if (request.method === "GET" && v2.endpoint === "status") {
        if (!(await authorizeChannel(request, v2.channelID))) return new Response("Unauthorized", { status: 401 });
        return handleChannelStatus(v2.channelID, url.searchParams.get("token"), env);
      }
      if (request.method === "POST" && v2.endpoint === "notify") {
        const country = request.headers.get("CF-IPCountry") ?? "??";
        const response = await handleNotify(request, {
          secret: v2.channelID, token: "", cam: v2.cam, sandbox: false,
        }, country, env);
        await recordNotifyOutcome(v2.channelID, response, request.headers.get("User-Agent"), env);
        return response;
      }
      return new Response("Method not allowed", { status: 405 });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    const route = parseRoute(url);
    if (!route) {
      return new Response("Bad request", { status: 400 });
    }

    const contentLength = request.headers.get("content-length");
    // Increased from 4KB to 128KB to accommodate relay-compressed snapshots
    // (~40KB base64 + metadata). The Worker will decide whether to embed
    // in the APNs payload or store in KV.
    if (contentLength && parseInt(contentLength) > 131072) {
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
    const response = await handleNotify(request, route, country, env);
    await recordNotifyOutcome(await channelIDForSecret(route.secret), response, request.headers.get("User-Agent"), env);
    return response;
  },

  // Daily Cron-triggered Slack digest. Wired in wrangler.toml as
  // `0 8 * * *` (08:00 UTC = 09:00 Paris winter / 10:00 summer).
  // No-ops if SLACK_WEBHOOK_URL is unset, which is the safe default
  // until the operator adds the secret.
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    if (!env.SLACK_WEBHOOK_URL) return;
    if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return;
    try {
      await postSlackDigest(env);
    } catch (e) {
      console.error(`Slack digest failed: ${e}`);
    }
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

// --- Channel status (what the app's push doctor reads) ---

export interface NotifyOutcomeRecord {
  status: number;
  reason: string;
  at: number;
  userAgent: string | null;
}

const notifyStatusKey = (channelID: string) => `notify-status:${channelID}`;

/**
 * Remembers the latest answer the Worker gave a relay for this channel,
 * including the silent 200 drops (stale event, low score, camera filter,
 * suppressed). Written only when the outcome changes or once a minute, so a
 * busy camera does not turn every event into a KV write.
 */
export async function recordNotifyOutcome(channelID: string, response: Response, userAgent: string | null, env: Env): Promise<void> {
  try {
    const reason = (await response.clone().text()).slice(0, 120);
    const now = Date.now();
    const key = notifyStatusKey(channelID.toLowerCase());
    const previousRaw = await env.DEVICES.get(key);
    if (previousRaw) {
      const previous = JSON.parse(previousRaw) as NotifyOutcomeRecord;
      if (previous.status === response.status && previous.reason === reason && now - previous.at < 60_000) return;
    }
    const record: NotifyOutcomeRecord = { status: response.status, reason, at: now, userAgent: userAgent?.slice(0, 120) ?? null };
    await env.DEVICES.put(key, JSON.stringify(record), { expirationTtl: 30 * 24 * 3600 });
  } catch {
    // Diagnostics must never affect delivery.
  }
}

async function handleChannelStatus(channelID: string, token: string | null, env: Env): Promise<Response> {
  const devices = await readDevices(channelID, env);
  const lastRaw = await env.DEVICES.get(notifyStatusKey(channelID));
  let lastNotify: NotifyOutcomeRecord | null = null;
  try { lastNotify = lastRaw ? JSON.parse(lastRaw) as NotifyOutcomeRecord : null; } catch { lastNotify = null; }
  const body = {
    channel: channelID.slice(0, 8),
    deviceCount: devices.length,
    devices: devices.map((device) => ({
      platform: device.platform ?? null,
      sandbox: device.sandbox,
      registeredAt: device.registered_at,
      tokenSuffix: device.token.slice(-6),
    })),
    thisDevice: token
      ? (() => {
          const match = devices.find((device) => device.token === token);
          return { registered: Boolean(match), sandbox: match?.sandbox ?? null };
        })()
      : null,
    lastNotify,
  };
  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store, private" },
  });
}

/** APNs says the token will never work again: stop fanning out to it. */
export function isDeadTokenResponse(status: number, reason: string): boolean {
  return status === 410 || (status === 400 && /"BadDeviceToken"/.test(reason));
}

const automationPolicyKey = (channelID: string) => `automation-policy:${channelID}`;
const automationCooldownKey = (channelID: string) => `automation-cooldown:${channelID}`;

type PersistedAutomationPolicy = Omit<StoredAutomationPolicy, "decisionKeyBase64"> & {
  decisionKeyCiphertext: string;
  decisionKeyIV: string;
};

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(value: string): Uint8Array | null {
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  } catch { return null; }
}

function policyAAD(
  channelID: string,
  policy: Pick<StoredAutomationPolicy, "revision" | "hash" | "timeZone">
): Uint8Array {
  return new TextEncoder().encode(`${channelID}\n${policy.revision}\n${policy.hash}\n${policy.timeZone}`);
}

async function encryptAutomationPolicy(
  channelID: string, policy: StoredAutomationPolicy, env: Env,
): Promise<PersistedAutomationPolicy | null> {
  const kek = env.AUTOMATION_POLICY_KEK_B64 ? base64ToBytes(env.AUTOMATION_POLICY_KEK_B64) : null;
  const decisionKey = base64ToBytes(policy.decisionKeyBase64);
  if (!kek || kek.byteLength !== 32 || !decisionKey || decisionKey.byteLength !== 32) return null;
  const cryptoKey = await crypto.subtle.importKey("raw", kek, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: policyAAD(channelID, policy) }, cryptoKey, decisionKey,
  );
  const { decisionKeyBase64: _, ...safe } = policy;
  return {
    ...safe,
    decisionKeyCiphertext: bytesToBase64(new Uint8Array(ciphertext)),
    decisionKeyIV: bytesToBase64(iv),
  };
}

async function decryptAutomationPolicy(
  channelID: string, policy: PersistedAutomationPolicy, env: Env,
): Promise<StoredAutomationPolicy | null> {
  const kek = env.AUTOMATION_POLICY_KEK_B64 ? base64ToBytes(env.AUTOMATION_POLICY_KEK_B64) : null;
  const iv = base64ToBytes(policy.decisionKeyIV);
  const ciphertext = base64ToBytes(policy.decisionKeyCiphertext);
  if (!kek || kek.byteLength !== 32 || !iv || iv.byteLength !== 12 || !ciphertext) return null;
  try {
    const cryptoKey = await crypto.subtle.importKey("raw", kek, "AES-GCM", false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: policyAAD(channelID, policy) }, cryptoKey, ciphertext,
    );
    const decisionKey = new Uint8Array(plaintext);
    if (decisionKey.byteLength !== 32) return null;
    const { decisionKeyCiphertext: _, decisionKeyIV: __, ...record } = policy;
    return { ...record, decisionKeyBase64: bytesToBase64(decisionKey) };
  } catch { return null; }
}

async function readAutomationPolicy(channelID: string, env: Env): Promise<StoredAutomationPolicy | null> {
  const raw = await env.DEVICES.get(automationPolicyKey(channelID));
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as PersistedAutomationPolicy;
    return value.schema === "lumen-automation-policy-v1"
      ? await decryptAutomationPolicy(channelID, value, env) : null;
  } catch { return null; }
}

async function handleAutomationPolicyPut(request: Request, channelID: string, env: Env): Promise<Response> {
  if (!(await authorizeChannel(request, channelID))) return new Response("Unauthorized", { status: 401 });
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (contentLength > 180_000) return new Response("Payload too large", { status: 413 });
  let body: unknown;
  try { body = await request.json(); } catch { return new Response("Bad request", { status: 400 }); }
  const record = await validatePolicyUpload(body);
  if (!record) return new Response("Unsupported or invalid automation policy", { status: 422 });
  const encrypted = await encryptAutomationPolicy(channelID, record, env);
  if (!encrypted) return new Response("Automation key encryption unavailable", { status: 503 });
  await env.DEVICES.put(automationPolicyKey(channelID), JSON.stringify(encrypted));
  await env.DEVICES.delete(automationCooldownKey(channelID));
  return new Response(JSON.stringify({ ok: true, revision: record.revision, hash: record.hash }), {
    status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

async function handleAutomationPolicyDelete(request: Request, channelID: string, env: Env): Promise<Response> {
  if (!(await authorizeChannel(request, channelID))) return new Response("Unauthorized", { status: 401 });
  await Promise.all([
    env.DEVICES.delete(automationPolicyKey(channelID)),
    env.DEVICES.delete(automationCooldownKey(channelID)),
  ]);
  return new Response(null, { status: 204 });
}

async function readAutomationCooldown(channelID: string, env: Env): Promise<Map<string, number>> {
  const raw = await env.DEVICES.get(automationCooldownKey(channelID));
  if (!raw) return new Map();
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    return new Map(Object.entries(value).filter((entry): entry is [string, number] => typeof entry[1] === "number"));
  } catch { return new Map(); }
}

async function writeAutomationCooldown(channelID: string, state: Map<string, number>, env: Env): Promise<void> {
  await env.DEVICES.put(automationCooldownKey(channelID), JSON.stringify(Object.fromEntries(state)));
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

async function handleV2Device(
  request: Request,
  channelID: string,
  env: Env,
  remove: boolean
): Promise<Response> {
  if (!(await authorizeChannel(request, channelID))) return new Response("Unauthorized", { status: 401 });
  let body: { token?: unknown; sandbox?: unknown; platform?: unknown };
  try { body = await request.json<typeof body>(); } catch { return new Response("Bad request", { status: 400 }); }
  if (typeof body.token !== "string" || !/^[0-9a-f]{32,128}$/i.test(body.token)) {
    return new Response("Bad request", { status: 400 });
  }
  const devices = await readDevices(channelID, env);
  if (remove) {
    await writeDevices(channelID, devices.filter((device) => device.token !== body.token), env);
    return new Response(null, { status: 204 });
  }
  if (typeof body.sandbox !== "boolean") return new Response("Bad request", { status: 400 });
  const record: RegisteredDevice = {
    token: body.token,
    sandbox: body.sandbox,
    platform: typeof body.platform === "string" ? body.platform.slice(0, 16) : undefined,
    registered_at: Math.floor(Date.now() / 1000),
  };
  const index = devices.findIndex((device) => device.token === record.token);
  if (index >= 0) devices[index] = record;
  else {
    if (devices.length >= MAX_DEVICES_PER_SECRET) {
      devices.sort((a, b) => a.registered_at - b.registered_at);
      devices.shift();
    }
    devices.push(record);
  }
  await writeDevices(channelID, devices, env);
  return new Response(JSON.stringify({ ok: true, device_count: devices.length }), {
    status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
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

  return await sendAPNs(token, payload, sandbox, env)
    ? new Response("OK", { status: 200 })
    : new Response("APNs test delivery failed", { status: 502 });
}

/**
 * Determine if a detection should be delivered as a critical alert.
 *
 * Critical alerts bypass Do Not Disturb and require the critical-alerts
 * entitlement (granted 2026-04-28).
 *
 * Criticality is now driven by the USER's configuration, not a hardcoded
 * heuristic. The relay (which holds the per-user config — critical cameras,
 * zones, schedules) sets `lumen_critical: true` on events that match the
 * user's critical rule. The previous "person >= 85% => critical" heuristic
 * made benign detections (e.g. a mail delivery) bypass Do Not Disturb, which
 * is wrong — only the user's own rules should decide. Default: never critical.
 */
function shouldBeCritical(event: ReviewEnvelope, automationVerified: boolean): boolean {
  if (automationVerified) return event.presentation?.disposition === "critical";
  // Published relays flag the user's own critical rule; keep honouring it
  // until they send signed automation decisions.
  return event.legacyCritical === true && event.automationSchema === undefined;
}

async function handleNotify(
  request: Request,
  route: { secret: string; token: string; cam: string | null; sandbox: boolean },
  country: string,
  env: Env
): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return new Response("Bad request", { status: 400 });
  }
  const normalized = normalizeNotifyBody(body);
  if (normalized === "drop") {
    return new Response("OK", { status: 200 });
  }
  if (!normalized) {
    return new Response("Bad request", { status: 400 });
  }
  const event = normalized;

  if (route.cam && event.camera !== route.cam) {
    return new Response("OK", { status: 200 });
  }

  const policyChannelID = /^[0-9a-f]{64}$/i.test(route.secret) ? route.secret.toLowerCase() : null;
  const storedChannelPolicy = policyChannelID
    ? await env.DEVICES.get(automationPolicyKey(policyChannelID)) : null;
  const channelPolicy = policyChannelID && storedChannelPolicy
    ? await readAutomationPolicy(policyChannelID, env) : null;
  // Stored policy corruption, AAD tampering, or a missing KEK must fail closed.
  // Falling back to unsigned delivery would turn a storage/configuration fault
  // into an automation bypass.
  if (storedChannelPolicy && !channelPolicy) {
    return new Response("Automation policy unavailable", { status: 503 });
  }
  let cooldownState: Map<string, number> | null = null;
  if (channelPolicy) {
    cooldownState = await readAutomationCooldown(route.secret.toLowerCase(), env);
    let decision;
    try {
      decision = await evaluateAndSignPolicy(channelPolicy, event, cooldownState);
    } catch {
      return new Response("Automation policy cannot evaluate this event", { status: 422 });
    }
    if (!decision) return new Response("Automation policy unavailable", { status: 503 });
    Object.assign(event, decision);
    if (decision.presentation.disposition === "suppress") {
      await writeAutomationCooldown(route.secret.toLowerCase(), cooldownState, env);
      return new Response("Suppressed by automation policy", { status: 200 });
    }
  }

  const carriesAutomation = event.automationSchema !== undefined
    || event.decisionMAC !== undefined || event.presentation !== undefined;
  const automationPolicyActive = channelPolicy !== null || env.AUTOMATION_POLICY_REVISION !== undefined
    || env.AUTOMATION_POLICY_HASH !== undefined;
  if (automationPolicyActive && !carriesAutomation) {
    return new Response("Automation decision required", { status: 428 });
  }
  const automationVerified = carriesAutomation
    ? await verifyAutomationDecision(
      event,
      channelPolicy ? undefined : env.AUTOMATION_DECISION_KEY,
      channelPolicy?.decisionKeyBase64 ?? env.AUTOMATION_DECISION_KEY_B64,
    )
    : false;
  if (carriesAutomation && !automationVerified) {
    return new Response("Invalid automation decision", { status: 400 });
  }
  if (automationVerified) {
    const activeRevision = channelPolicy?.revision ?? Number(env.AUTOMATION_POLICY_REVISION);
    const activeHash = channelPolicy?.hash ?? env.AUTOMATION_POLICY_HASH;
    if (!Number.isInteger(activeRevision)
        || activeRevision !== event.policyRevision
        || !activeHash
        || activeHash !== event.policyHash) {
      return new Response("Automation policy out of date", { status: 409 });
    }
  }
  // A suppress decision is an invariant violation: the authority must never
  // submit it to the Worker and the Worker must never call APNs for it.
  if (automationVerified && event.presentation?.disposition === "suppress") {
    return new Response("Suppressed", { status: 422 });
  }

  // Reject stale and future-dated envelopes again at the APNs boundary.
  // A correction is asynchronous by nature: Frigate can take a minute to put a
  // name to a face. Judging it by the detection's age would drop exactly the
  // messages this feature exists to deliver.
  const maxAgeStr = event.isEnrichment
    ? (env.LATE_IDENTITY_MAX_AGE_SECONDS ?? "600")
    : (env.MAX_EVENT_AGE_SECONDS ?? "120");
  const maxAge = parseInt(maxAgeStr, 10);
  if (maxAge > 0) {
    const ageSeconds = Date.now() / 1000 - event.detected_at;
    if (ageSeconds > maxAge || ageSeconds < -30) {
      console.log(`Dropping stale/future Review ${event.reviewId}: age=${ageSeconds.toFixed(0)}s max=${maxAge}s`);
      return new Response("OK", { status: 200 });
    }
  }

  // AI Classification (Phase 1: rule-based)
  // NSE will use this to render bilingual templates instead of the default alert below.
  const classification = classifyEvent({
    label: event.label,
    camera: event.camera,
    zones: event.zones || [],
    top_score: event.score,
    start_time: event.detected_at,
    stationary: false,
  });

  // Build APNs payload
  const cameraName = event.camera.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  const label = event.label.replace(/\b\w/g, (c) => c.toUpperCase());

  const bodyParts: string[] = [];
  if (event.zones?.length) {
    bodyParts.push(`Zone: ${event.zones.join(", ")}`);
  }
  bodyParts.push(`Confidence: ${Math.round(event.score * 100)}%`);

  // Determine priority and interruption level based on detection characteristics.
  // Critical alerts bypass Do Not Disturb and require the entitlement (granted 2026-04-28).
  const isCritical = shouldBeCritical(event, automationVerified);
  const interruptionLevel = isCritical
    ? "critical"
    : (automationVerified && event.presentation?.priority === "normal" ? "active" : "time-sensitive");
  const sound: string | Record<string, unknown> = isCritical
    ? {
      critical: 1,
      name: "default",
      volume: event.presentation?.criticalVolume ?? 1,
    }
    : "default";
  const priority = isCritical ? 10 : 10;  // Both use highest priority for now

  const apnsPayload: Record<string, unknown> = {
    aps: {
      alert: {
        title: event.custom_title ?? `${label} Detected`,
        subtitle: cameraName,
        // A sentence describing what happened beats a list of zone/score
        // fragments; the NSE still gets both and decides for itself.
        body: event.custom_body ?? event.description ?? bodyParts.join(" | "),
      },
      sound: event.isEnrichment ? undefined : sound,
      "interruption-level": event.isEnrichment ? "passive" : interruptionLevel,
      category: automationVerified ? (event.presentation?.category ?? "FRIGATE_EVENT") : "FRIGATE_EVENT",
      "thread-id": event.camera,
      "mutable-content": 1,
    },
    eventId: event.eventId,
    sourceSchema: event.sourceSchema,
    reviewId: event.reviewId,
    reviewSeverity: event.reviewSeverity,
    ...(automationVerified ? {
      automationSchema: event.automationSchema,
      policyRevision: event.policyRevision,
      policyHash: event.policyHash,
      ruleId: event.ruleId,
      branchId: event.branchId,
      decisionId: event.decisionId,
      presentation: event.presentation,
      decisionMAC: event.decisionMAC,
    } : {}),
    camera: event.camera,
    label: event.label,
    zones: event.zones || [],
    // Forwarded so the NSE rules engine can evaluate scoreAtLeast and
    // subLabelEquals leaves on closed-app pushes (rules engine is otherwise
    // limited to camera/label/zones/time when running in the extension).
    top_score: event.score,
    sub_label: event.sub_label,
    stationary: event.stationary,
    has_clip: event.has_clip,
    recognized_plate: event.recognized_plate,
    description: event.description,
    isEnrichment: event.isEnrichment ?? false,
    // Unix epoch seconds of Frigate detection. The NSE uses this to show the
    // user "detected Xs ago" so real-time pushes can be visually distinguished
    // from pushes APNs held while the device was unreachable.
    detected_at: event.detected_at,
    source: event.source,
    // AI classification (Phase 1: rule-based, Phase 2: Worker AI)
    // NSE applyAIClassification() uses this to render bilingual templates
    classification,
  };

  // Pre-compressed snapshot from relay: either embed directly (if under 4KB
  // total) or store in KV and include URL. This reduces NSE download latency
  // from ~500ms (full-size from Frigate) to 0ms (embedded) or ~50ms (CDN).
  if (event.compressed_snapshot) {
    // Try embedding first
    const withSnapshot = { ...apnsPayload, compressed_snapshot: event.compressed_snapshot };
    const payloadSize = new TextEncoder().encode(JSON.stringify(withSnapshot)).length;

    if (payloadSize < 4096) {
      // Fits in APNs payload — embed directly (zero NSE download latency)
      apnsPayload.compressed_snapshot = event.compressed_snapshot;
      console.log(`Embedded snapshot for ${event.camera}/${event.eventId}: ${payloadSize} bytes`);
    } else {
      // Too large — store behind a random, single-use, non-cacheable URL.
      const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
      const nonce = Array.from(nonceBytes).map((byte) => byte.toString(16).padStart(2, "0")).join("");
      const snapshotKey = `snapshot-v2:${nonce}`;
      await env.RATE_LIMIT.put(snapshotKey, event.compressed_snapshot, { expirationTtl: 3600 });
      const workerOrigin = new URL(request.url).origin;
      const snapshotURL = `${workerOrigin}/v2/snapshots/${nonce}`;
      apnsPayload.compressed_snapshot_url = snapshotURL;
      console.log(`Stored one-time snapshot for ${event.camera}: ${payloadSize} bytes`);
    }
  }

  // Phase 1 fan-out: look up all devices registered under this secret. If the
  // user has registered via POST /v1/register (iPhone + iPad + Mac + Watch...),
  // fan out to every one in parallel. Each device has its own 30s rate-limit
  // bucket so one spammy camera doesn't block a new device from receiving.
  //
  // If no devices are registered (pre-fan-out client still using the single
  // URL token), fall back to that URL token so existing setups keep working.
  const registered = await readDevices(route.secret, env);
  if (registered.length === 0 && route.token.length === 0) {
    return new Response("No registered devices", { status: 409 });
  }
  const targets: RegisteredDevice[] = registered.length > 0
    ? registered
    : [{ token: route.token, sandbox: route.sandbox, registered_at: 0 }];

  const meta: NotifyMeta = {
    camera: event.camera,
    label: event.label,
    topScore: event.score,
    country,
  };

  // apns-collapse-id: coalesce notifications for the SAME Frigate event so the
  // user never sees one detection twice (Michel L 2026-06: "notifications
  // coming in duplicate"). Matches the app's local-notification identifier
  // ("lumen-<eventId>"), so iOS also replaces a WebSocket-path local notif
  // with this remote push instead of stacking them. Loss-free: only merges
  // identical-event notifications, never drops a distinct alert. 64-byte APNs cap.
  const collapseId = `lumen-${event.reviewId}-${event.reviewSeverity}`.slice(0, 64);

  const deliveryOutcomes = await Promise.all(
    targets.map((device) => sendToDeviceRateLimited(device, apnsPayload, meta, env, priority, collapseId))
  );
  const deadTokens = new Set(targets.filter((_, index) => deliveryOutcomes[index] === "dead").map((device) => device.token));
  if (deadTokens.size > 0 && registered.length > 0) {
    await writeDevices(route.secret, registered.filter((device) => !deadTokens.has(device.token)), env);
  }
  const terminalDelivery = deliveryOutcomes.some((outcome) => outcome === "sent" || outcome === "rate_limited");
  if (channelPolicy && cooldownState && terminalDelivery) {
    await writeAutomationCooldown(route.secret.toLowerCase(), cooldownState, env);
  }

  return terminalDelivery
    ? new Response("OK", { status: 200 })
    : new Response("APNs delivery failed", { status: 502 });
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
  outcome: DeliveryOutcome
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
 * Returns a typed outcome so the request boundary can distinguish intentional
 * rate limiting from an actual APNs failure. One failing device still does not
 * block successful targets in the same Promise.all fan-out.
 */
export type DeliveryOutcome = "sent" | "rate_limited" | "failed" | "dead";

async function sendToDeviceRateLimited(
  device: RegisteredDevice,
  payload: unknown,
  meta: NotifyMeta,
  env: Env,
  priority: number = 10,
  collapseId?: string
): Promise<DeliveryOutcome> {
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
      return "rate_limited";
    }
  }
  const result = await sendAPNsDetailed(device.token, payload, device.sandbox, env, priority, collapseId);
  const delivered = result.ok;
  const outcome: DeliveryOutcome = delivered ? "sent" : (isDeadTokenResponse(result.status, result.reason) ? "dead" : "failed");
  if (delivered) {
    // A failed attempt must remain retryable. Consuming the rate-limit token
    // before APNs accepts the request silently loses the relay retry.
    await rateLimitPut("rl", device.token, String(Date.now()), 60);
  }
  writeStat(env, device, meta, outcome === "dead" ? "failed" : outcome);
  return outcome;
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

export async function sendAPNs(
  token: string,
  payload: unknown,
  sandbox: boolean,
  env: Env,
  priority: number = 10,
  collapseId?: string
): Promise<boolean> {
  return (await sendAPNsDetailed(token, payload, sandbox, env, priority, collapseId)).ok;
}

async function sendAPNsDetailed(
  token: string,
  payload: unknown,
  sandbox: boolean,
  env: Env,
  priority: number = 10,
  collapseId?: string
): Promise<{ ok: boolean; status: number; reason: string }> {
  try {
    const jwt = await getAPNsJWT(env);
    const apnsHost = sandbox ? "api.sandbox.push.apple.com" : "api.push.apple.com";

    // apns-expiration: retry for 1h on transient delivery failures
    // (device offline, asleep, low-power). `0` would drop immediately.
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;

    const headers: Record<string, string> = {
      authorization: `bearer ${jwt}`,
      "apns-push-type": "alert",
      "apns-topic": env.APNS_BUNDLE_ID,
      "apns-priority": String(priority),
      "apns-expiration": String(expiresAt),
      "content-type": "application/json",
    };
    // Dedupe: pushes for the same Frigate event replace each other (and the
    // app's matching local notification) instead of stacking. See the notify
    // handler where collapseId is derived.
    if (collapseId) {
      headers["apns-collapse-id"] = collapseId;
    }

    const response = await fetch(
      `https://${apnsHost}/3/device/${token}`,
      {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
      }
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => "");
      console.error(`APNs error ${response.status}: ${errText}`);
      return { ok: false, status: response.status, reason: errText };
    }
    return { ok: true, status: response.status, reason: "" };
  } catch (e) {
    console.error(`APNs request failed: ${e}`);
    return { ok: false, status: 0, reason: String(e) };
  }
}

// --- Stats dashboard + Slack digest ---

/**
 * Run a SQL query against the Workers Analytics Engine HTTP API and return
 * the parsed `data` rows. Returns [] on any failure (network, auth, schema
 * drift). Errors are logged but never propagated — the dashboard falls back
 * to an empty section rather than 500'ing.
 */
async function runAnalyticsQuery<T = Record<string, unknown>>(
  env: Env,
  sql: string
): Promise<T[]> {
  if (!env.CF_ACCOUNT_ID || !env.CF_ANALYTICS_TOKEN) return [];
  try {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/analytics_engine/sql`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}`,
          "Content-Type": "text/plain",
        },
        body: sql,
      }
    );
    if (!res.ok) {
      console.error(`Analytics query failed ${res.status}: ${await res.text().catch(() => "")}`);
      return [];
    }
    const json = await res.json<{ data?: T[] }>();
    return Array.isArray(json.data) ? json.data : [];
  } catch (e) {
    console.error(`Analytics query exception: ${e}`);
    return [];
  }
}

interface StatsBundle {
  totals: { sent: number; rate_limited: number; users: number };
  perCountry: Array<{ country: string; notifs: number }>;
  perDay: Array<{ day: string; notifs: number; users: number }>;
  perPlatform: Array<{ platform: string; notifs: number }>;
  topCameras: Array<{ camera: string; notifs: number }>;
  topUsers: Array<{ user: string; country: string; notifs: number }>;
}

async function loadStats(env: Env): Promise<StatsBundle> {
  // Note: Workers Analytics Engine reweights sampled rows via _sample_interval.
  // For our tokenPrefix-indexed dataset (low cardinality) sampling is rare,
  // but using SUM(_sample_interval) is the supported correct-count idiom.
  const ds = "lumen_push_notif_stats";

  const [totalsRows, perCountry, perDay, perPlatform, topCameras, topUsers] =
    await Promise.all([
      // Cloudflare Analytics Engine SQL only supports a small subset of
      // ClickHouse — `uniq()` and `any()` are NOT in it. Use
      // `count(DISTINCT ...)` for unique counts and `min(...)` (which IS
      // supported) for the "pick one representative value per group" trick.
      runAnalyticsQuery<{ outcome: string; n: number; users: number }>(
        env,
        `SELECT blob5 AS outcome,
                SUM(_sample_interval) AS n,
                count(DISTINCT blob1) AS users
         FROM ${ds}
         WHERE timestamp > NOW() - INTERVAL '7' DAY
         GROUP BY outcome`
      ),
      runAnalyticsQuery<{ country: string; notifs: number }>(
        env,
        `SELECT blob2 AS country, SUM(_sample_interval) AS notifs
         FROM ${ds}
         WHERE timestamp > NOW() - INTERVAL '7' DAY AND blob5 = 'sent'
         GROUP BY country ORDER BY notifs DESC LIMIT 20`
      ),
      runAnalyticsQuery<{ day: string; notifs: number; users: number }>(
        env,
        `SELECT toStartOfDay(timestamp) AS day,
                SUM(_sample_interval) AS notifs,
                count(DISTINCT blob1) AS users
         FROM ${ds}
         WHERE timestamp > NOW() - INTERVAL '30' DAY AND blob5 = 'sent'
         GROUP BY day ORDER BY day`
      ),
      runAnalyticsQuery<{ platform: string; notifs: number }>(
        env,
        `SELECT blob6 AS platform, SUM(_sample_interval) AS notifs
         FROM ${ds}
         WHERE timestamp > NOW() - INTERVAL '7' DAY AND blob5 = 'sent'
         GROUP BY platform ORDER BY notifs DESC`
      ),
      runAnalyticsQuery<{ camera: string; notifs: number }>(
        env,
        `SELECT blob3 AS camera, SUM(_sample_interval) AS notifs
         FROM ${ds}
         WHERE timestamp > NOW() - INTERVAL '7' DAY AND blob5 = 'sent'
         GROUP BY camera ORDER BY notifs DESC LIMIT 10`
      ),
      // CF Analytics Engine min/max don't accept String args (they only
      // work on numbers), so we can't pick a representative country per
      // user the cheap way. Drop the country column — the per-country
      // table above is the source of truth for geographic distribution.
      runAnalyticsQuery<{ user: string; country: string; notifs: number }>(
        env,
        `SELECT blob1 AS user, '' AS country, SUM(_sample_interval) AS notifs
         FROM ${ds}
         WHERE timestamp > NOW() - INTERVAL '7' DAY AND blob5 = 'sent'
         GROUP BY user ORDER BY notifs DESC LIMIT 20`
      ),
    ]);

  let sent = 0,
    rateLimited = 0,
    users = 0;
  for (const r of totalsRows) {
    if (r.outcome === "sent") {
      sent = Number(r.n) || 0;
      users = Number(r.users) || 0;
    } else if (r.outcome === "rate_limited") {
      rateLimited = Number(r.n) || 0;
    }
  }

  return {
    totals: { sent, rate_limited: rateLimited, users },
    perCountry,
    perDay,
    perPlatform,
    topCameras,
    topUsers,
  };
}

async function handleStats(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const provided = url.searchParams.get("token");
  if (!env.STATS_TOKEN || provided !== env.STATS_TOKEN) {
    return new Response("Forbidden", { status: 403 });
  }

  // JSON view for tooling/automation
  if (url.searchParams.get("format") === "json") {
    const stats = await loadStats(env);
    return new Response(JSON.stringify(stats, null, 2), {
      headers: { "Content-Type": "application/json" },
    });
  }

  const stats = await loadStats(env);
  const html = renderStatsHTML(stats);
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
    },
  });
}

function escapeHTML(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderStatsHTML(s: StatsBundle): string {
  const t = s.totals;
  const dropPct = t.sent + t.rate_limited > 0
    ? ((t.rate_limited / (t.sent + t.rate_limited)) * 100).toFixed(1)
    : "0.0";

  const j = (x: unknown) => JSON.stringify(x);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Lumen Push — Stats</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" integrity="sha384-mpe1RaT6FBvxyrM9Pq5IiqsB7mcOQunEyjoDyW3nPOM48v6yKnmkHX+oyU2u8M3v" crossorigin="anonymous" defer></script>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0; font: 14px/1.5 -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif;
  background: #0a0c10; color: #e7eaee; padding: 24px; max-width: 1200px; margin: 0 auto;
}
h1 { font-size: 22px; margin: 0 0 4px; font-weight: 600; }
.sub { color: #8a93a3; font-size: 13px; margin-bottom: 24px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; margin-bottom: 24px; }
.card {
  background: #131720; border: 1px solid #20262f; border-radius: 12px; padding: 16px;
}
.card h2 { font-size: 12px; font-weight: 500; color: #8a93a3; margin: 0 0 6px; text-transform: uppercase; letter-spacing: 0.5px; }
.kpi { font-size: 28px; font-weight: 600; color: #f5f7fa; }
.kpi small { font-size: 13px; color: #8a93a3; font-weight: 400; margin-left: 6px; }
.section { background: #131720; border: 1px solid #20262f; border-radius: 12px; padding: 18px; margin-bottom: 18px; }
.section h2 { font-size: 13px; font-weight: 600; color: #c9cfd8; margin: 0 0 14px; text-transform: uppercase; letter-spacing: 0.5px; }
.section .chart-wrap { position: relative; height: 240px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #20262f; }
th { color: #8a93a3; font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; }
td.num { text-align: right; font-variant-numeric: tabular-nums; color: #f5f7fa; }
tr:last-child td { border-bottom: none; }
.empty { color: #5a6373; font-style: italic; padding: 12px 0; }
.flag { display: inline-block; min-width: 32px; font-weight: 600; }
.row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
@media (max-width: 720px) { .row-2 { grid-template-columns: 1fr; } }
.token { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12px; color: #c9cfd8; }
footer { color: #5a6373; font-size: 12px; text-align: center; margin-top: 24px; }
</style>
</head>
<body>
<h1>Lumen Push — Notification Stats</h1>
<div class="sub">Last 7 days · auto-refreshes when you reload.</div>

<div class="grid">
  <div class="card"><h2>Sent</h2><div class="kpi">${t.sent.toLocaleString()}<small>pushes</small></div></div>
  <div class="card"><h2>Unique Users</h2><div class="kpi">${t.users.toLocaleString()}<small>devices</small></div></div>
  <div class="card"><h2>Rate-Limited</h2><div class="kpi">${t.rate_limited.toLocaleString()}<small>${dropPct}% drop</small></div></div>
</div>

<div class="row-2">
  <div class="section">
    <h2>Daily Trend (30d)</h2>
    <div class="chart-wrap"><canvas id="dailyChart"></canvas></div>
  </div>
  <div class="section">
    <h2>By Platform</h2>
    <div class="chart-wrap"><canvas id="platformChart"></canvas></div>
  </div>
</div>

<div class="section">
  <h2>By Country</h2>
  ${
    s.perCountry.length === 0
      ? '<div class="empty">No data yet.</div>'
      : `<table><thead><tr><th>Country</th><th class="num">Notifs (7d)</th></tr></thead><tbody>${s.perCountry
          .map(
            (r) =>
              `<tr><td><span class="flag">${escapeHTML(r.country)}</span></td><td class="num">${Number(r.notifs).toLocaleString()}</td></tr>`
          )
          .join("")}</tbody></table>`
  }
</div>

<div class="row-2">
  <div class="section">
    <h2>Top Cameras (7d)</h2>
    ${
      s.topCameras.length === 0
        ? '<div class="empty">No data yet.</div>'
        : `<table><thead><tr><th>Camera</th><th class="num">Notifs</th></tr></thead><tbody>${s.topCameras
            .map(
              (r) =>
                `<tr><td>${escapeHTML(r.camera)}</td><td class="num">${Number(r.notifs).toLocaleString()}</td></tr>`
            )
            .join("")}</tbody></table>`
    }
  </div>
  <div class="section">
    <h2>Top Users (7d)</h2>
    ${
      s.topUsers.length === 0
        ? '<div class="empty">No data yet.</div>'
        : `<table><thead><tr><th>User</th><th>Country</th><th class="num">Notifs</th></tr></thead><tbody>${s.topUsers
            .map(
              (r) =>
                `<tr><td class="token">${escapeHTML(r.user)}</td><td>${escapeHTML(r.country)}</td><td class="num">${Number(r.notifs).toLocaleString()}</td></tr>`
            )
            .join("")}</tbody></table>`
    }
  </div>
</div>

<footer>lumen-push · stats are pseudonymous (token prefix only) · data via Workers Analytics Engine</footer>

<script>
const DAILY = ${j(s.perDay)};
const PLATFORMS = ${j(s.perPlatform)};

window.addEventListener('load', () => {
  if (typeof Chart === 'undefined') return;
  const grid = '#20262f';
  const tick = '#8a93a3';
  Chart.defaults.color = tick;
  Chart.defaults.borderColor = grid;
  Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, system-ui, sans-serif';

  if (DAILY.length > 0) {
    new Chart(document.getElementById('dailyChart'), {
      type: 'line',
      data: {
        labels: DAILY.map(d => d.day),
        datasets: [
          { label: 'Notifs', data: DAILY.map(d => Number(d.notifs)),
            borderColor: '#5b8def', backgroundColor: 'rgba(91,141,239,0.15)',
            fill: true, tension: 0.3, pointRadius: 2 },
          { label: 'Users', data: DAILY.map(d => Number(d.users)),
            borderColor: '#3ddc97', backgroundColor: 'rgba(61,220,151,0.10)',
            fill: false, tension: 0.3, pointRadius: 2, yAxisID: 'y2' },
        ]
      },
      options: {
        maintainAspectRatio: false,
        scales: {
          y:  { beginAtZero: true, grid: { color: grid } },
          y2: { beginAtZero: true, position: 'right', grid: { display: false } },
          x:  { grid: { color: grid } },
        },
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } }
      }
    });
  }

  if (PLATFORMS.length > 0) {
    new Chart(document.getElementById('platformChart'), {
      type: 'doughnut',
      data: {
        labels: PLATFORMS.map(p => p.platform),
        datasets: [{
          data: PLATFORMS.map(p => Number(p.notifs)),
          backgroundColor: ['#5b8def','#3ddc97','#f5a623','#e25555','#a78bfa','#64748b'],
          borderColor: '#0a0c10', borderWidth: 2,
        }]
      },
      options: {
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } }
      }
    });
  }
});
</script>
</body>
</html>`;
}

/**
 * Daily Slack digest. Posts a summary of the past 24 hours to the configured
 * incoming-webhook URL. Format is plain Slack blocks for readability.
 */
async function postSlackDigest(env: Env): Promise<void> {
  const ds = "lumen_push_notif_stats";
  const [totalsRows, perCountry] = await Promise.all([
    runAnalyticsQuery<{ outcome: string; n: number; users: number }>(
      env,
      `SELECT blob5 AS outcome, SUM(_sample_interval) AS n, count(DISTINCT blob1) AS users
       FROM ${ds} WHERE timestamp > NOW() - INTERVAL '24' HOUR GROUP BY outcome`
    ),
    runAnalyticsQuery<{ country: string; notifs: number }>(
      env,
      `SELECT blob2 AS country, SUM(_sample_interval) AS notifs
       FROM ${ds} WHERE timestamp > NOW() - INTERVAL '24' HOUR AND blob5='sent'
       GROUP BY country ORDER BY notifs DESC LIMIT 5`
    ),
  ]);

  let sent = 0, rateLimited = 0, users = 0;
  for (const r of totalsRows) {
    if (r.outcome === "sent") { sent = Number(r.n) || 0; users = Number(r.users) || 0; }
    else if (r.outcome === "rate_limited") { rateLimited = Number(r.n) || 0; }
  }
  const dropPct = sent + rateLimited > 0
    ? ((rateLimited / (sent + rateLimited)) * 100).toFixed(1)
    : "0.0";

  const countryLines = perCountry.length > 0
    ? perCountry.map(c => `• ${c.country}: ${Number(c.notifs).toLocaleString()}`).join("\n")
    : "_no traffic_";

  const text = `*Lumen Push — last 24h*
:bell: ${sent.toLocaleString()} pushes sent · :busts_in_silhouette: ${users} users · :no_entry_sign: ${rateLimited} rate-limited (${dropPct}%)

*Top countries*
${countryLines}`;

  await fetch(env.SLACK_WEBHOOK_URL!, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
}
