import { deliveryFilterDecision, validateDeliveryFilterPolicy, type DeliveryFilterPolicy } from "./deliveryFilter";
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
  // Minimum gap (seconds) between consecutive pushes to the same APNs token
  // FOR THE SAME CAMERA. Prevents runaway notification loops without dropping
  // legitimate detections; another camera is never throttled by this one.
  // Defaults to 5 if unset (was 30 historically; 30 was too aggressive).
  RATE_LIMIT_SECONDS?: string;
  RATE_LIMIT: KVNamespace;
  // "1" opts in to keeping ONE last-notify record per channel (HTTP status,
  // Worker reason code, time; 30-day TTL) for the in-app Push Doctor. Off by
  // default: the published privacy statement says no delivery history is kept,
  // so enabling it needs that statement updated first.
  LAST_NOTIFY_RETENTION?: string;
  // Phase 1 multi-device fan-out: maps `secret` -> list of registered devices.
  // Populated via POST /v1/register. Consumed by handleNotify to fan out
  // a single Frigate event to every device that shares the secret. If empty
  // for a given secret, handleNotify falls back to the single token in the
  // URL (backward compatibility with pre-fan-out clients).
  DEVICES: KVNamespace;
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
  filterPolicy?: DeliveryFilterPolicy;
  filterPolicyHash?: string;
  registered_at: number; // Unix epoch seconds
}

const ALLOWED_PLATFORMS = new Set([
  "ios", "ipados", "macos", "watchos", "tvos", "visionos", "unknown",
]);

function normalizedPlatform(value: unknown): string {
  return typeof value === "string" && ALLOWED_PLATFORMS.has(value.toLowerCase())
    ? value.toLowerCase()
    : "unknown";
}

function strictBoundedInteger(
  value: string | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  if (value === undefined || !/^\d+$/.test(value)) return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max
    ? parsed
    : fallback;
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
  custom_title?: string;
  custom_body?: string;
  /**
   * Optional human camera name chosen by the user (e.g. "Back Porch"). Sanitized
   * on receipt; when absent the prettified camera id is used as before.
   */
  camera_display_name?: string;
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

const CAMERA_DISPLAY_NAME_MAX = 64;

/**
 * Bounded, presentation-safe camera display name. Control and bidi-override
 * characters become spaces, whitespace collapses, result is trimmed and capped
 * at 64 code points. Anything unusable yields undefined so the alert still
 * goes out with the prettified camera id (an optional cosmetic field must
 * never drop a security notification).
 */
export function sanitizeCameraDisplayName(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 1024) return undefined;
  const cleaned = value
    .replace(/[\p{Cc}\u200E\u200F\u202A-\u202E\u2066-\u2069]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
  const bounded = Array.from(cleaned).slice(0, CAMERA_DISPLAY_NAME_MAX).join("").trim();
  return bounded.length > 0 ? bounded : undefined;
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
  if (body.custom_title !== undefined
      && (typeof body.custom_title !== "string" || body.custom_title.length === 0 || body.custom_title.length > 256)) return null;
  if (body.custom_body !== undefined
      && (typeof body.custom_body !== "string" || body.custom_body.length === 0 || body.custom_body.length > 1024)) return null;
  if (body.compressed_snapshot !== undefined
      && (typeof body.compressed_snapshot !== "string" || body.compressed_snapshot.length === 0
        || body.compressed_snapshot.length > 131_072)) return null;
  if (body.legacyCritical !== undefined) return null;
  if ("camera_display_name" in body) {
    const displayName = sanitizeCameraDisplayName(body.camera_display_name);
    if (displayName) body.camera_display_name = displayName;
    else delete body.camera_display_name;
  }
  return body as unknown as ReviewEnvelope;
}

type LegacyEnvelope = Omit<ReviewEnvelope, "sourceSchema" | "reviewId" | "reviewSeverity"> & {
  sourceSchema?: never; reviewId?: never; reviewSeverity?: never;
};
type DeliveryEvent = ReviewEnvelope | LegacyEnvelope;
function isCorrelatedReview(event: DeliveryEvent): event is ReviewEnvelope {
  return event.sourceSchema === "frigate-review-v1";
}

/** Preserve old producers without ever inventing a Review identity or confidence. */
function legacyObject(value: unknown): LegacyEnvelope | null {
  if (!value || typeof value !== "object") return null;
  let body = value as Record<string, unknown>;
  if (typeof body.type === "string" && body.after && typeof body.after === "object") {
    if (body.type !== "new") return null; // raw updates and ends are not new alerts
    body = body.after as Record<string, unknown>;
  }
  if (["sourceSchema", "source_schema", "reviewId", "review_id", "reviewSeverity", "review_severity"].some(key => key in body)) return null;
  const eventId = optionalString(body.id, 256), camera = optionalString(body.camera, 256), label = optionalString(body.label, 256);
  const score = body.top_score, detectedAt = body.detected_at ?? body.start_time;
  if (!eventId || !camera || !label || typeof score !== "number" || !Number.isFinite(score) || score < .5 || score > 1
      || typeof detectedAt !== "number" || !Number.isFinite(detectedAt) || detectedAt <= 0) return null;
  const event: LegacyEnvelope = { eventId, camera, label, score, detected_at: detectedAt, source: "legacy-relay" };
  if (typeof body.stationary === "boolean") event.stationary = body.stationary;
  if (Array.isArray(body.zones) && body.zones.length <= 32 && body.zones.every(z => typeof z === "string" && z.length <= 128)) event.zones = body.zones;
  // Legacy compatibility carries no critical privilege, automation authority or Review claim.
  return event;
}

function optionalString(value: unknown, max: number): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length <= max ? value : undefined;
}

/**
 * Relays already running in the field post snake_case Frigate events
 * (`top_score`, `start_time`, optional `review_id` / `source_schema`), not the
 * camelCase Review envelope. Map them onto the envelope so one Worker serves
 * both without manufacturing Review IDs, severity or confidence. Raw relays
 * must migrate to correlated Review envelopes before this Worker is deployed.
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
  // Compatibility changes spelling only: raw objects are never Review authority.
  if (body.source_schema !== "frigate-review-v1"
      || !optionalString(body.review_id, 256)
      || (body.review_severity !== "alert" && body.review_severity !== "detection")
      || typeof score !== "number") return null;
  const detectedAt = typeof body.detected_at === "number" ? body.detected_at : body.start_time;
  const rawSubLabel = Array.isArray(body.sub_label) ? body.sub_label[0] : body.sub_label;
  const severity = body.review_severity;
  const candidate: Record<string, unknown> = {
    source: optionalString(body.source, 256) ?? "legacy-relay",
    sourceSchema: "frigate-review-v1",
    reviewId: body.review_id,
    reviewSeverity: severity,
    eventId: id,
    camera,
    label,
    detected_at: detectedAt,
    score,
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
  if (body.camera_display_name !== undefined) candidate.camera_display_name = body.camera_display_name;
  const normalized = validateReviewEnvelope(candidate);
  if (!normalized) return null;
  const snapshot = optionalString(body.compressed_snapshot, 2_000_000);
  if (snapshot) normalized.compressed_snapshot = snapshot;
  const title = optionalString(body.custom_title, 256);
  if (title) normalized.custom_title = title;
  const text = optionalString(body.custom_body, 1024);
  if (text) normalized.custom_body = text;
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

type BoundedJsonResult =
  | { ok: true; value: unknown }
  | { ok: false; response: Response };

/** Parse JSON without buffering an attacker-controlled request body unboundedly. */
async function readBoundedJson(request: Request, maxBytes: number): Promise<BoundedJsonResult> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (!Number.isSafeInteger(parsedLength) || parsedLength < 0) {
      return { ok: false, response: new Response("Bad request", { status: 400 }) };
    }
    if (parsedLength > maxBytes) {
      return { ok: false, response: new Response("Payload too large", { status: 413 }) };
    }
  }
  if (!request.body) {
    return { ok: false, response: new Response("Bad request", { status: 400 }) };
  }

  const reader = request.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
  let totalBytes = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel("body too large");
        return { ok: false, response: new Response("Payload too large", { status: 413 }) };
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false, response: new Response("Bad request", { status: 400 }) };
  } finally {
    reader.releaseLock();
  }
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
      return new Response("Notification usage analytics have been removed", { status: 410, headers: { "Cache-Control": "no-store", "Content-Type": "text/plain" } });
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
          devices.map((device) => runTest(device.token, device.sandbox, env))
        );
        return testResponse(results);
      }
      if (request.method === "GET" && v2.endpoint === "status") {
        if (!(await authorizeChannel(request, v2.channelID))) return new Response("Unauthorized", { status: 401 });
        return handleChannelStatus(v2.channelID, url.searchParams.get("token"), env);
      }
      if (request.method === "POST" && v2.endpoint === "notify") {

        const response = await handleNotify(request, {
          secret: v2.channelID, token: "", cam: v2.cam, sandbox: false,
        }, env);
        await recordLastNotify(v2.channelID, response, env);
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
      return testResponse([await runTest(route.token, route.sandbox, env)]);
    }

    if (route.endpoint === "register") {
      return handleRegister(route, env);
    }

    if (route.endpoint === "unregister") {
      return handleUnregister(route, env);
    }


    const response = await handleNotify(request, route, env);

    return response;
  },

  async scheduled() { /* Usage analytics and exports are retired. */ }
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

async function handleChannelStatus(channelID: string, token: string | null, env: Env): Promise<Response> {
  const devices = await readDevices(channelID, env);
  const retained = lastNotifyRetentionEnabled(env);
  const lastNotify = retained ? await readLastNotify(channelID, env) : null;
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
    // When opted in, only the single most recent notify outcome is kept (status,
    // Worker reason code, time) - no camera, label, event id, token or user agent.
    deliveryHistoryRetained: retained,
    ...(retained ? { lastNotifyRetentionSeconds: LAST_NOTIFY_TTL_SECONDS } : {}),
  };
  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store, private" },
  });
}

// --- Last notify outcome (Push Doctor) ---

const lastNotifyKey = (channelID: string) => `last-notify:${channelID}`;
const LAST_NOTIFY_TTL_SECONDS = 30 * 86_400;
const LAST_NOTIFY_WRITE_INTERVAL_SECONDS = 60;

interface LastNotifyRecord { status: number; reason: string; at: number }

function lastNotifyRetentionEnabled(env: Env): boolean {
  return env.LAST_NOTIFY_RETENTION === "1";
}

async function readLastNotify(channelID: string, env: Env): Promise<(LastNotifyRecord & { userAgent: null }) | null> {
  const raw = await env.DEVICES.get(lastNotifyKey(channelID));
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as Partial<LastNotifyRecord>;
    if (typeof value.status !== "number" || typeof value.reason !== "string" || typeof value.at !== "number") return null;
    return { status: value.status, reason: value.reason, at: value.at, userAgent: null };
  } catch { return null; }
}

/** Worker-authored reason only: JSON `reason`, else first outcome, else the fixed error text. */
async function lastNotifyReason(response: Response): Promise<string> {
  const text = await response.clone().text().catch(() => "");
  try {
    const body = JSON.parse(text) as { reason?: unknown; delivered?: unknown; outcomes?: Array<{ outcome?: unknown; reason?: unknown }> };
    if (typeof body.reason === "string") return body.reason.slice(0, 120);
    if (typeof body.delivered === "number" && body.delivered > 0) return "delivered";
    const first = body.outcomes?.find((entry) => entry.outcome !== "sent");
    if (first && typeof first.outcome === "string") {
      return `${first.outcome}${typeof first.reason === "string" ? `:${first.reason}` : ""}`.slice(0, 120);
    }
    return "no_targets";
  } catch {
    return text.slice(0, 120);
  }
}

/**
 * Persist the latest notify outcome for the channel's Push Doctor. At most one
 * KV write per channel per minute (per colo, gated by the Cache API), never
 * for a channel with no registered devices, and never able to affect delivery.
 */
async function recordLastNotify(channelID: string, response: Response, env: Env): Promise<void> {
  if (!lastNotifyRetentionEnabled(env)) return;
  try {
    if (await rateLimitGet("last-notify", channelID)) return;
    if ((await readDevices(channelID, env)).length === 0) return;
    const record: LastNotifyRecord = { status: response.status, reason: await lastNotifyReason(response), at: Date.now() };
    await env.DEVICES.put(lastNotifyKey(channelID), JSON.stringify(record), { expirationTtl: LAST_NOTIFY_TTL_SECONDS });
    await rateLimitPut("last-notify", channelID, String(record.at), LAST_NOTIFY_WRITE_INTERVAL_SECONDS);
  } catch { /* diagnostics only */ }
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
  const parsed = await readBoundedJson(request, 180_000);
  if (!parsed.ok) return parsed.response;
  const record = await validatePolicyUpload(parsed.value);
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
    ...(existingIdx >= 0 ? { filterPolicy: devices[existingIdx].filterPolicy, filterPolicyHash: devices[existingIdx].filterPolicyHash } : {}),
    token: route.token,
    sandbox: route.sandbox,
    platform: normalizedPlatform(route.platform),
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
  const parsed = await readBoundedJson(request, 32 * 1024);
  if (!parsed.ok) return parsed.response;
  if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
    return new Response("Bad request", { status: 400 });
  }
  const body = parsed.value as { token?: unknown; sandbox?: unknown; platform?: unknown; filterPolicy?: unknown; filterPolicyHash?: unknown };
  if (typeof body.token !== "string" || !/^[0-9a-f]{32,128}$/i.test(body.token)) {
    return new Response("Bad request", { status: 400 });
  }
  const devices = await readDevices(channelID, env);
  if (remove) {
    await writeDevices(channelID, devices.filter((device) => device.token !== body.token), env);
    return new Response(null, { status: 204 });
  }
  if (typeof body.sandbox !== "boolean") return new Response("Bad request", { status: 400 });
  const existing = devices.find((device) => device.token === body.token);
  const filterPolicy = body.filterPolicy === undefined ? existing?.filterPolicy : validateDeliveryFilterPolicy(body.filterPolicy);
  if (body.filterPolicy !== undefined && !filterPolicy) return new Response("Invalid delivery filter", { status: 400 });
  const filterPolicyHash = body.filterPolicy === undefined ? existing?.filterPolicyHash : body.filterPolicyHash;
  if (filterPolicy && (typeof filterPolicyHash !== "string" || !/^[0-9a-f]{64}$/.test(filterPolicyHash))) {
    return new Response("Invalid filter revision", { status: 400 });
  }
  const record: RegisteredDevice = {
    ...(filterPolicy ? { filterPolicy, filterPolicyHash: filterPolicyHash as string } : {}),
    token: body.token,
    sandbox: body.sandbox,
    platform: normalizedPlatform(body.platform),
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
  return new Response(JSON.stringify({ ok: true, device_count: devices.length, filter_policy_version: filterPolicy ? 1 : null, filter_policy_hash: filterPolicyHash ?? null }), {
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

type TestResult = "sent" | "recent" | "failed";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status, headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

/** Any accepted send wins; otherwise a deduplicated test is a 200 with an explicit reason. */
function testResponse(results: TestResult[]): Response {
  const delivered = results.filter((result) => result === "sent").length;
  if (delivered > 0) return jsonResponse({ ok: true, delivered });
  if (results.includes("recent")) return jsonResponse({ ok: true, delivered: 0, reason: "test_recently_sent" });
  return new Response("APNs test delivery failed", { status: 502 });
}

async function runTest(token: string, sandbox: boolean, env: Env): Promise<TestResult> {
  const lastTest = await rateLimitGet("test", token);
  if (lastTest) {
    return "recent";
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

  return await sendAPNs(token, payload, sandbox, env) ? "sent" : "failed";
}

// --- Notify response (relay-facing; contains no tokens, ids or camera names) ---

export type PublicOutcome = "sent" | "rate_limited" | "duplicate" | "filtered" | "cooldown" | "failed";

function publicResult(result: DeliveryResult): { outcome: PublicOutcome; reason: string } {
  return result.outcome === "dead"
    ? { outcome: "failed", reason: "apns_token_invalid" }
    : { outcome: result.outcome, reason: result.reason };
}

/** Request ended before fan-out on purpose: terminal, nothing to retry. */
function notifySkipped(reason: string): Response {
  return jsonResponse({ ok: true, delivered: 0, suppressed: 0, outcomes: [], reason });
}

/**
 * HTTP 200 for every terminal outcome (relay 1.2.1 retries any non-2xx, which
 * could duplicate alerts); 502 only when at least one APNs send failed.
 */
function notifyResponse(results: DeliveryResult[]): Response {
  const outcomes = results.map(publicResult);
  const delivered = outcomes.filter((entry) => entry.outcome === "sent").length;
  const failed = outcomes.filter((entry) => entry.outcome === "failed").length;
  const ok = failed === 0;
  return jsonResponse({ ok, delivered, suppressed: outcomes.length - delivered - failed, outcomes }, ok ? 200 : 502);
}

/** Critical presentation requires an authenticated policy decision. */
function shouldBeCritical(event: ReviewEnvelope, automationVerified: boolean): boolean {
  return automationVerified && event.presentation?.disposition === "critical";
}

async function handleNotify(
  request: Request,
  route: { secret: string; token: string; cam: string | null; sandbox: boolean },
  env: Env
): Promise<Response> {
  const parsed = await readBoundedJson(request, 128 * 1024);
  if (!parsed.ok) return parsed.response;
  const normalized = normalizeNotifyBody(parsed.value);
  if (normalized === "drop") {
    return notifySkipped("review_ended");
  }
  const event: DeliveryEvent | null = normalized ?? legacyObject(parsed.value);
  if (!event) {
    return new Response("Invalid event; correlated Frigate Review envelope recommended", { status: 400 });
  }

  if (route.cam && event.camera !== route.cam) {
    return notifySkipped("camera_not_selected");
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
    if (!isCorrelatedReview(event)) return new Response("Review relay required for automation policy", { status: 428 });
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
      return notifySkipped("suppressed_by_automation_policy");
    }
  }

  const carriesAutomation = event.automationSchema !== undefined
    || event.decisionMAC !== undefined || event.presentation !== undefined;
  const automationPolicyActive = channelPolicy !== null || env.AUTOMATION_POLICY_REVISION !== undefined
    || env.AUTOMATION_POLICY_HASH !== undefined;
  if (automationPolicyActive && !carriesAutomation) {
    return new Response("Automation decision required", { status: 428 });
  }
  const automationVerified = carriesAutomation && isCorrelatedReview(event)
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
  const maxAge = strictBoundedInteger(maxAgeStr, event.isEnrichment ? 600 : 120, 0, 86_400);
  if (maxAge > 0) {
    const ageSeconds = Date.now() / 1000 - event.detected_at;
    if (ageSeconds > maxAge || ageSeconds < -30) {
      return notifySkipped("stale_event");
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
    stationary: event.stationary ?? false,
  });

  // Build APNs payload
  const cameraName = (isCorrelatedReview(event) ? event.camera_display_name : undefined)
    ?? event.camera.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  const label = event.label.replace(/\b\w/g, (c) => c.toUpperCase());

  const bodyParts: string[] = [];
  if (event.zones?.length) {
    bodyParts.push(`Zone: ${event.zones.join(", ")}`);
  }
  bodyParts.push(`Confidence: ${Math.round(event.score * 100)}%`);

  // Determine priority and interruption level based on detection characteristics.
  // Critical alerts bypass Do Not Disturb and require the entitlement (granted 2026-04-28).
  const isCritical = isCorrelatedReview(event) && shouldBeCritical(event, automationVerified);
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
    ...(isCorrelatedReview(event) && event.camera_display_name
      ? { camera_display_name: event.camera_display_name } : {}),
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
    source: "cloudflare-relay",
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

    } else {
      // Too large — store behind a random, single-use, non-cacheable URL.
      const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
      const nonce = Array.from(nonceBytes).map((byte) => byte.toString(16).padStart(2, "0")).join("");
      const snapshotKey = `snapshot-v2:${nonce}`;
      await env.RATE_LIMIT.put(snapshotKey, event.compressed_snapshot, { expirationTtl: 3600 });
      const workerOrigin = new URL(request.url).origin;
      const snapshotURL = `${workerOrigin}/v2/snapshots/${nonce}`;
      apnsPayload.compressed_snapshot_url = snapshotURL;

    }
  }

  // Phase 1 fan-out: look up all devices registered under this secret. If the
  // user has registered via POST /v1/register (iPhone + iPad + Mac + Watch...),
  // fan out to every one in parallel. Each device has its own per-camera
  // rate-limit bucket so one spammy camera blocks neither another device nor
  // another camera.
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

  // Stable 64-byte identity per channel, Review and severity. APNs may coalesce
  // remote notifications; this does not deduplicate independently scheduled
  // local notifications or guarantee exactly-once delivery. Receipts below
  // prevent repeat sends after a known successful acceptance.
  const collapseId = await channelIDForSecret(JSON.stringify(isCorrelatedReview(event) ? [route.secret, event.reviewId, event.reviewSeverity] : [route.secret, "legacy", event.eventId]));

  // Rate-limit bucket is per APNs token AND camera: one camera's burst never
  // hides another camera's alert (two cameras 2.6 s apart must both arrive).
  const rateLimitScope = event.camera.trim().toLowerCase();
  const deliveryOutcomes = await Promise.all(
    targets.map(async (device) => {
      const filtered = deliveryFilterDecision(device.filterPolicy, { ...event, reviewSeverity: event.reviewSeverity ?? "legacy" });
      if (filtered) return { outcome: "filtered", reason: filtered } as DeliveryResult;
      const filter = device.filterPolicy && !device.filterPolicy.isPassthrough
        ? (device.filterPolicy.cameras[event.camera] ?? device.filterPolicy.globalDefaults) : undefined;
      const cooldownKey = `delivery-filter-cooldown:${await channelIDForSecret(JSON.stringify([device.token, event.camera, event.label]))}`;
      if (filter && filter.cooldownSeconds > 0 && !event.isEnrichment) {
        const last = Number(await env.RATE_LIMIT.get(cooldownKey));
        if (Number.isFinite(last) && last > 0 && Date.now() / 1000 - last < filter.cooldownSeconds) {
          return { outcome: "cooldown", reason: "camera_label_cooldown" } as DeliveryResult;
        }
      }
      const payload = structuredClone(apnsPayload);
      if (filter && isCritical && event.score < filter.criticalMinScore) {
        const aps = payload.aps as Record<string, unknown>;
        aps["interruption-level"] = "time-sensitive";
        aps.sound = "default";
      }
      const result = await sendToDeviceRateLimited(device, payload, env, priority, collapseId, event.isEnrichment === true, rateLimitScope);
      if (result.outcome === "sent" && filter && filter.cooldownSeconds > 0 && !event.isEnrichment) {
        await env.RATE_LIMIT.put(cooldownKey, String(Date.now() / 1000), { expirationTtl: Math.max(60, filter.cooldownSeconds) });
      }
      return result;
    })
  );
  const deadTokens = new Set(targets.filter((_, index) => deliveryOutcomes[index].outcome === "dead").map((device) => device.token));
  if (deadTokens.size > 0 && registered.length > 0) {
    await writeDevices(route.secret, registered.filter((device) => !deadTokens.has(device.token)), env);
  }
  const terminalDelivery = deliveryOutcomes.every((result) => result.outcome !== "failed" && result.outcome !== "dead");
  if (channelPolicy && cooldownState && terminalDelivery) {
    await writeAutomationCooldown(route.secret.toLowerCase(), cooldownState, env);
  }

  return notifyResponse(deliveryOutcomes);
}

/**
 * Send the APNs payload to one device, honouring a per-token, per-camera rate limit.
 * Returns a typed outcome so the request boundary can distinguish intentional
 * rate limiting from an actual APNs failure. One failing device still does not
 * block successful targets in the same Promise.all fan-out.
 */
export type DeliveryOutcome = "sent" | "rate_limited" | "duplicate" | "filtered" | "cooldown" | "failed" | "dead";
export interface DeliveryResult { outcome: DeliveryOutcome; reason: string }

// Coalesce simultaneous retries in one isolate. Persisted receipts cover
// later retries; cross-region exactly-once delivery is not provided by KV.
const inFlightDeliveries = new Map<string, Promise<DeliveryResult>>();
async function sendToDeviceRateLimited(
  device: RegisteredDevice, payload: unknown, env: Env,
  priority = 10, collapseId?: string, enrichment = false, rateLimitScope = "",
): Promise<DeliveryResult> {
  if (!collapseId) return deliverToDevice(device, payload, env, priority, collapseId, enrichment, rateLimitScope);
  const key = JSON.stringify([env.APNS_BUNDLE_ID, device.token, device.sandbox, collapseId, enrichment]);
  const existing = inFlightDeliveries.get(key);
  if (existing) return existing;
  if (inFlightDeliveries.size >= 4096) return { outcome: "failed", reason: "worker_busy" };
  const delivery = deliverToDevice(device, payload, env, priority, collapseId, enrichment, rateLimitScope);
  inFlightDeliveries.set(key, delivery);
  try { return await delivery; }
  finally { inFlightDeliveries.delete(key); }
}

async function deliverToDevice(
  device: RegisteredDevice,
  payload: unknown,
  env: Env,
  priority: number = 10,
  collapseId?: string,
  enrichment = false,
  rateLimitScope = "",
): Promise<DeliveryResult> {
  // Per-device receipts keep retries from re-alerting devices that already
  // succeeded during partial fan-out. KV is eventually consistent; the relay's
  // persisted Review dedupe remains the primary authority across regions.
  const receipt = collapseId ? `review-delivered:${device.token}:${collapseId}` : null;
  const deliveryKey = receipt ? `${receipt}:${enrichment ? "enrichment" : "initial"}` : null;
  if (enrichment && receipt && !await env.RATE_LIMIT.get(`${receipt}:initial`)) {
    // A correction must never create a previously suppressed alert.
    return { outcome: "duplicate", reason: "enrichment_without_initial_alert" };
  }
  if (deliveryKey && await env.RATE_LIMIT.get(deliveryKey)) return { outcome: "duplicate", reason: "already_delivered" };
  // Per-device, per-camera rate limit: 5s minimum gap between pushes to the
  // same APNs token for the same camera (keyed token + normalized camera, so
  // a second camera firing 2.6 s later is never swallowed). Was 30s — too aggressive for security cameras where
  // a single intrusion can fire 5+ legitimate events in <30s. Users
  // were perceiving 30s+ latency because the FIRST event hit, the
  // rate-limit blocked the next 5 detections, and they only saw the
  // 6th detection ~30s later than their visible event.
  //
  // 5s still suppresses runaway loops (one camera firing every second
  // for hours) without dropping legitimate consecutive detections.
  // Override via env.RATE_LIMIT_SECONDS for deployments that want a
  // different cadence.
  const minIntervalSeconds = strictBoundedInteger(env.RATE_LIMIT_SECONDS, 5, 0, 3_600);
  const rateLimitKey = `${device.token}:${rateLimitScope}`;
  const lastPush = await rateLimitGet("rl", rateLimitKey);
  if (lastPush && !enrichment) {
    const elapsed = (Date.now() - parseInt(lastPush)) / 1000;
    if (elapsed < minIntervalSeconds) {
      return { outcome: "rate_limited", reason: "same_camera_within_rate_limit" };
    }
  }
  const result = await sendAPNsDetailed(device.token, payload, device.sandbox, env, priority, collapseId);
  const delivered = result.ok;
  const outcome: DeliveryResult = delivered
    ? { outcome: "sent", reason: "apns_accepted" }
    : isDeadTokenResponse(result.status, result.reason)
      ? { outcome: "dead", reason: "apns_token_invalid" }
      : { outcome: "failed", reason: result.status === 0 ? "apns_unreachable" : `apns_status_${result.status}` };
  if (delivered) {
    if (deliveryKey) await env.RATE_LIMIT.put(deliveryKey, "1", { expirationTtl: 86400 });
    // A failed attempt must remain retryable. Consuming the rate-limit token
    // before APNs accepts the request silently loses the relay retry.
    if (!enrichment) await rateLimitPut("rl", rateLimitKey, String(Date.now()), 60);
  }

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
    // Allow APNs to coalesce this Review's remote notifications. This header
    // does not cancel a separately scheduled local notification.
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

      return { ok: false, status: response.status, reason: errText };
    }
    return { ok: true, status: response.status, reason: "" };
  } catch (e) {

    return { ok: false, status: 0, reason: String(e) };
  }
}

// Usage analytics, dashboards and daily exports intentionally removed.
