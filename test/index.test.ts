import { describe, expect, it, vi } from "vitest";
import worker, { channelIDForSecret, isDeadTokenResponse, normalizeNotifyBody, sendAPNs, validateReviewEnvelope, verifyAutomationDecision, type Env } from "../src/index";
import { evaluateAndSignPolicy, validatePolicyUpload } from "../src/automation";
import authorityFixture from "./fixtures/automation-authority-v1.json";

class FakeKV {
  values = new Map<string, string>();
  async get(key: string) { return this.values.get(key) ?? null; }
  async put(key: string, value: string) { this.values.set(key, value); }
  async delete(key: string) { this.values.delete(key); }
}

function makeEnv(): { env: Env; devices: FakeKV; rateLimit: FakeKV } {
  const devices = new FakeKV();
  const rateLimit = new FakeKV();
  const env = {
    APNS_KEY: "", APNS_KEY_ID: "", APNS_TEAM_ID: "", APNS_BUNDLE_ID: "",
    KILL_SWITCH: "0", DEVICES: devices, RATE_LIMIT: rateLimit,
    AUTOMATION_POLICY_KEK_B64: btoa(String.fromCharCode(...Array(32).fill(0x42))),
  } as unknown as Env;
  return { env, devices, rateLimit };
}

describe("push v2", () => {
  it("registers an APNs token in the body with bearer authentication", async () => {
    const { env, devices } = makeEnv();
    const secret = "0123456789abcdef0123456789abcdef";
    const channel = await channelIDForSecret(secret);
    const token = "ab".repeat(32);
    const response = await worker.fetch(new Request(
      `https://push.test/v2/channels/${channel}/devices`,
      {
        method: "POST",
        headers: { "Authorization": `Bearer ${secret}`, "Content-Type": "application/json" },
        body: JSON.stringify({ token, sandbox: true, platform: "ios" }),
      }
    ), env);

    expect(response.status).toBe(200);
    expect(response.url).not.toContain(token);
    expect(await devices.get(`devices:${channel}`)).toContain(token);
  });

  it("rejects a bearer that does not derive the channel", async () => {
    const { env } = makeEnv();
    const channel = await channelIDForSecret("0123456789abcdef0123456789abcdef");
    const response = await worker.fetch(new Request(
      `https://push.test/v2/channels/${channel}/devices`,
      {
        method: "POST",
        headers: { "Authorization": "Bearer ffffffffffffffffffffffffffffffff", "Content-Type": "application/json" },
        body: JSON.stringify({ token: "ab".repeat(32), sandbox: false }),
      }
    ), env);
    expect(response.status).toBe(401);
  });

  it("serves snapshots once with no-store and retires the predictable endpoint", async () => {
    const { env, rateLimit } = makeEnv();
    const nonce = "cd".repeat(32);
    await rateLimit.put(`snapshot-v2:${nonce}`, "base64-jpeg");

    const first = await worker.fetch(new Request(`https://push.test/v2/snapshots/${nonce}`), env);
    expect(first.status).toBe(200);
    expect(first.headers.get("cache-control")).toContain("no-store");
    expect(await first.text()).toBe("base64-jpeg");
    expect((await worker.fetch(new Request(`https://push.test/v2/snapshots/${nonce}`), env)).status).toBe(404);
    expect((await worker.fetch(new Request("https://push.test/snapshot/predictable-event-id"), env)).status).toBe(410);
  });

  it("authenticates, hashes, and stores a binary-key automation policy", async () => {
    const { env, devices } = makeEnv();
    const secret = "0123456789abcdef0123456789abcdef";
    const channel = await channelIDForSecret(secret);
    const rules = [{
      id: "rule-1", name: "Door", schemaVersion: 4, enabled: true, sideEffectAuthority: "bridgeRequired",
      branches: [{ id: "branch-1", kind: "if", expression: { kind: "condition", condition: { camera: { name: "front_door" } } }, actions: [{ notification: { priority: "timeSensitive" } }] }],
    }];
    const bytes = new TextEncoder().encode(JSON.stringify(rules));
    const hash = `sha256:${Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    const payload = {
      schema: "lumen-automation-policy-v1", revision: 7, hash,
      policyBase64: btoa(String.fromCharCode(...bytes)),
      decisionKeyBase64: btoa(String.fromCharCode(...Array(32).fill(7))),
      timeZone: "Europe/Paris",
    };
    const response = await worker.fetch(new Request(`https://push.test/v2/channels/${channel}/automation-policy`, {
      method: "PUT", headers: { Authorization: `Bearer ${secret}`, "Content-Type": "application/json" }, body: JSON.stringify(payload),
    }), env);
    expect(response.status).toBe(200);
    const storedPolicy = await devices.get(`automation-policy:${channel}`);
    expect(storedPolicy).toContain(hash);
    expect(storedPolicy).not.toContain("decisionKeyBase64");

    const tamperedStorage = JSON.parse(storedPolicy!);
    tamperedStorage.timeZone = "UTC";
    await devices.put(`automation-policy:${channel}`, JSON.stringify(tamperedStorage));
    const tamperedNotify = await worker.fetch(new Request(`https://push.test/v2/notify/${channel}`, {
      method: "POST", body: JSON.stringify({
        source: "relay", sourceSchema: "frigate-review-v1", reviewId: "review-aad",
        reviewSeverity: "alert", eventId: "event-aad", camera: "front", label: "person",
        detected_at: Date.now() / 1000, score: 0.9,
      }),
    }), env);
    expect(tamperedNotify.status).toBe(503);

    const noKEK = makeEnv();
    noKEK.env.AUTOMATION_POLICY_KEK_B64 = undefined;
    expect((await worker.fetch(new Request(`https://push.test/v2/channels/${channel}/automation-policy`, {
      method: "PUT", headers: { Authorization: `Bearer ${secret}` }, body: JSON.stringify(payload),
    }), noKEK.env)).status).toBe(503);

    const tampered = { ...payload, hash: `sha256:${"00".repeat(32)}` };
    expect((await worker.fetch(new Request(`https://push.test/v2/channels/${channel}/automation-policy`, {
      method: "PUT", headers: { Authorization: `Bearer ${secret}` }, body: JSON.stringify(tampered),
    }), env)).status).toBe(422);
  });

  it("evaluates a stored suppression before APNs and persists its cooldown", async () => {
    const { env, devices } = makeEnv();
    const secret = "0123456789abcdef0123456789abcdef";
    const channel = await channelIDForSecret(secret);
    const rules = [{
      id: "rule-suppress", name: "Quiet porch", schemaVersion: 4, enabled: true,
      sideEffectAuthority: "bridgeRequired", cooldownSeconds: 60,
      branches: [{ id: "branch-suppress", kind: "if", expression: { kind: "condition", condition: { zone: { camera: "front_door", zone: "porch" } } }, actions: [{ suppressNotification: {} }] }],
    }];
    const bytes = new TextEncoder().encode(JSON.stringify(rules));
    const hash = `sha256:${Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    const policy = { schema: "lumen-automation-policy-v1", revision: 4, hash,
      policyBase64: btoa(String.fromCharCode(...bytes)), decisionKeyBase64: btoa(String.fromCharCode(...Array(32).fill(9))), timeZone: "Europe/Paris" };
    expect((await worker.fetch(new Request(`https://push.test/v2/channels/${channel}/automation-policy`, {
      method: "PUT", headers: { Authorization: `Bearer ${secret}` }, body: JSON.stringify(policy),
    }), env)).status).toBe(200);
    const envelope = {
      source: "relay", sourceSchema: "frigate-review-v1", reviewId: "review-s", reviewSeverity: "alert",
      eventId: "event-s", camera: "front_door", label: "person", detected_at: Date.now() / 1000,
      score: 0.9, zones: ["porch"],
    };
    const response = await worker.fetch(new Request(`https://push.test/v2/notify/${channel}`, {
      method: "POST", body: JSON.stringify(envelope),
    }), env);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("Suppressed");
    expect(await devices.get(`automation-cooldown:${channel}`)).toContain("rule-suppress");
  });
});

describe("identity and description enrichment", () => {
  function envelope(extra: Record<string, unknown> = {}) {
    return {
      source: "relay",
      sourceSchema: "frigate-review-v1",
      reviewId: "review-1",
      reviewSeverity: "alert",
      eventId: "event-1",
      camera: "front_door",
      label: "person",
      detected_at: Date.now() / 1000,
      score: 0.9,
      zones: ["mailbox"],
      ...extra,
    };
  }

  it("accepts a description within its length bound", () => {
    expect(validateReviewEnvelope(envelope({ description: "Someone at the mailbox." }))).not.toBeNull();
    expect(validateReviewEnvelope(envelope({ description: null }))).not.toBeNull();
  });

  it("rejects an empty or oversized description", () => {
    expect(validateReviewEnvelope(envelope({ description: "" }))).toBeNull();
    expect(validateReviewEnvelope(envelope({ description: "x".repeat(501) }))).toBeNull();
    expect(validateReviewEnvelope(envelope({ description: 42 }))).toBeNull();
  });

  it("accepts the enrichment marker only as a boolean", () => {
    expect(validateReviewEnvelope(envelope({ isEnrichment: true }))).not.toBeNull();
    expect(validateReviewEnvelope(envelope({ isEnrichment: "yes" }))).toBeNull();
  });

  it("keeps a recognised name within its existing bound", () => {
    expect(validateReviewEnvelope(envelope({ sub_label: "Facteur" }))).not.toBeNull();
    expect(validateReviewEnvelope(envelope({ sub_label: "n".repeat(129) }))).toBeNull();
  });

  it("does not drop a correction that arrives minutes after the detection", async () => {
    const { env } = makeEnv();
    const secret = "0123456789abcdef0123456789abcdef";
    const channel = await channelIDForSecret(secret);
    // Older than MAX_EVENT_AGE_SECONDS, which would drop a fresh detection.
    const late = envelope({
      isEnrichment: true,
      sub_label: "Facteur",
      detected_at: Date.now() / 1000 - 300,
    });
    const response = await worker.fetch(new Request(`https://push.test/v2/notify/${channel}`, {
      method: "POST", body: JSON.stringify(late),
    }), env);
    // "No registered devices" means the correction reached the delivery stage.
    // A stale drop would have returned a silent 200 "OK" long before that.
    expect(response.status).toBe(409);

    // The same envelope without the marker is dropped for being too old.
    const stale = { ...late, isEnrichment: false };
    const staleResponse = await worker.fetch(new Request(`https://push.test/v2/notify/${channel}`, {
      method: "POST", body: JSON.stringify(stale),
    }), env);
    expect(staleResponse.status).toBe(200);
  });
});

describe("APNs delivery contract", () => {
  async function apnsEnv(): Promise<Env> {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]
    );
    const privateKey = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const base64 = btoa(String.fromCharCode(...privateKey));
    const { env } = makeEnv();
    env.APNS_KEY = `-----BEGIN PRIVATE KEY-----\n${base64}\n-----END PRIVATE KEY-----`;
    env.APNS_KEY_ID = "LOCALTEST1";
    env.APNS_TEAM_ID = "LOCALTEST2";
    env.APNS_BUNDLE_ID = "com.lorislabs.lumen.test";
    return env;
  }

  it("reports APNs rejection and transport failure as retryable failures", async () => {
    const env = await apnsEnv();
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = vi.fn(async () => new Response('{"reason":"ServiceUnavailable"}', { status: 503 })) as typeof fetch;
      expect(await sendAPNs("ab".repeat(32), {}, true, env)).toBe(false);
      globalThis.fetch = vi.fn(async () => { throw new Error("offline"); }) as typeof fetch;
      expect(await sendAPNs("ab".repeat(32), {}, true, env)).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("reports success only after APNs accepts the request", async () => {
    const env = await apnsEnv();
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = vi.fn(async () => new Response(null, { status: 200 })) as typeof fetch;
      expect(await sendAPNs("ab".repeat(32), {}, false, env, 10, "review-1")).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("Automation V4 authority", () => {
  it("matches the repository cross-runtime policy evaluation fixture", async () => {
    const bytes = new TextEncoder().encode(authorityFixture.policyJSON);
    const upload = await validatePolicyUpload({
      schema: "lumen-automation-policy-v1",
      revision: authorityFixture.revision,
      hash: authorityFixture.policyHash,
      policyBase64: btoa(String.fromCharCode(...bytes)),
      decisionKeyBase64: authorityFixture.decisionKeyBase64,
      timeZone: authorityFixture.timeZone,
    });
    expect(upload).not.toBeNull();
    const decision = await evaluateAndSignPolicy(
      upload!,
      { ...authorityFixture.event, reviewSeverity: "alert" as const },
      new Map(),
      new Date(authorityFixture.now),
    );
    expect(decision).toEqual({
      automationSchema: "lumen-automation-decision-v1",
      policyRevision: authorityFixture.revision,
      policyHash: authorityFixture.policyHash,
      ruleId: authorityFixture.expected.ruleId,
      branchId: authorityFixture.expected.branchId,
      decisionId: authorityFixture.expected.decisionId,
      presentation: {
        disposition: authorityFixture.expected.disposition,
        priority: authorityFixture.expected.priority,
        category: authorityFixture.expected.category,
        spokenTemplate: authorityFixture.expected.spokenTemplate,
        criticalVolume: authorityFixture.expected.criticalVolume,
      },
      decisionMAC: authorityFixture.expected.decisionMAC,
    });
  });

  it("evaluates nested predicates and emits a binary-key MAC", async () => {
    const rules = [{
      id: "rule-1", name: "Door", schemaVersion: 4, enabled: true, sideEffectAuthority: "bridgeRequired",
      branches: [{
        id: "branch-1", kind: "if",
        expression: { kind: "all", parts: [
          { kind: "condition", condition: { camera: { name: "front_door" } } },
          { kind: "not", expression: { kind: "condition", condition: { stationary: { stationary: true } } } },
        ] },
        actions: [{ criticalAlert: { volume: 0.75, category: "door" } }],
      }],
    }];
    const bytes = new TextEncoder().encode(JSON.stringify(rules));
    const hash = `sha256:${Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    const upload = await validatePolicyUpload({
      schema: "lumen-automation-policy-v1", revision: 9, hash,
      policyBase64: btoa(String.fromCharCode(...bytes)),
      decisionKeyBase64: btoa(String.fromCharCode(...Array(32).fill(7))),
      timeZone: "Europe/Paris",
    });
    expect(upload).not.toBeNull();
    const event = {
      reviewId: "review-1", reviewSeverity: "alert" as const, eventId: "event-1",
      camera: "front_door", label: "person", score: 0.9, stationary: false,
    };
    const decision = await evaluateAndSignPolicy(upload!, event, new Map(), new Date("2026-09-01T12:00:00Z"));
    expect(decision?.presentation).toEqual({ disposition: "critical", priority: "timeSensitive", criticalVolume: 0.75, category: "door" });
    expect(await verifyAutomationDecision({
      ...event, source: "relay", sourceSchema: "frigate-review-v1", detected_at: 1,
      ...decision!,
    }, undefined, upload!.decisionKeyBase64)).toBe(true);
  });

  it("accepts and evaluates Swift NumericComparison wire values", async () => {
    const rules = [{
      id: "rule-confidence", name: "High confidence", schemaVersion: 4, enabled: true,
      sideEffectAuthority: "bridgeRequired",
      branches: [{ id: "branch-confidence", kind: "if", expression: {
        kind: "condition", condition: { confidence: { comparison: "gte", value: 0.85 } },
      }, actions: [{ notification: { priority: "timeSensitive" } }] }],
    }];
    const bytes = new TextEncoder().encode(JSON.stringify(rules));
    const hash = `sha256:${Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    const upload = await validatePolicyUpload({
      schema: "lumen-automation-policy-v1", revision: 10, hash,
      policyBase64: btoa(String.fromCharCode(...bytes)),
      decisionKeyBase64: btoa(String.fromCharCode(...Array(32).fill(7))), timeZone: "Europe/Paris",
    });
    expect(upload).not.toBeNull();
    expect((await evaluateAndSignPolicy(upload!, {
      reviewId: "review-confidence", reviewSeverity: "alert", eventId: "event-confidence",
      camera: "front", label: "person", score: 0.85,
    }, new Map()))?.ruleId).toBe("rule-confidence");
  });

  it("enforces an inline per-rule cooldown using persisted authority state", async () => {
    const rules = [{
      id: "rule-cooldown", name: "Cooldown", schemaVersion: 4, enabled: true,
      sideEffectAuthority: "bridgeRequired",
      branches: [{ id: "branch-cooldown", kind: "if", expression: { kind: "condition",
        condition: { perRuleCooldown: { seconds: 300 } },
      }, actions: [{ notification: { priority: "timeSensitive" } }] }],
    }];
    const bytes = new TextEncoder().encode(JSON.stringify(rules));
    const hash = `sha256:${Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    const upload = (await validatePolicyUpload({
      schema: "lumen-automation-policy-v1", revision: 11, hash,
      policyBase64: btoa(String.fromCharCode(...bytes)),
      decisionKeyBase64: btoa(String.fromCharCode(...Array(32).fill(7))), timeZone: "Europe/Paris",
    }))!;
    const state = new Map<string, number>();
    const event = { reviewId: "review-cooldown", reviewSeverity: "alert" as const,
      eventId: "event-cooldown", camera: "front", label: "person", score: 0.9 };
    const first = await evaluateAndSignPolicy(upload, event, state, new Date(1_800_000_000_000));
    expect(first?.ruleId).toBe("rule-cooldown");
    const blocked = await evaluateAndSignPolicy(upload, { ...event, reviewId: "review-2", eventId: "event-2" }, state,
      new Date(1_800_000_100_000));
    expect(blocked?.ruleId).toBe("00000000-0000-0000-0000-000000000000");
  });

  it("rejects unsupported always-on actions instead of acknowledging partial execution", async () => {
    const rules = [{
      id: "rule-1", name: "Webhook", schemaVersion: 4, enabled: true, sideEffectAuthority: "bridgeRequired",
      branches: [{ id: "branch-1", kind: "if", expression: { kind: "condition", condition: { camera: { name: "front" } } }, actions: [{ webhook: { endpointID: "x" } }] }],
    }];
    const bytes = new TextEncoder().encode(JSON.stringify(rules));
    const hash = `sha256:${Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    expect(await validatePolicyUpload({ schema: "lumen-automation-policy-v1", revision: 1, hash,
      policyBase64: btoa(String.fromCharCode(...bytes)), decisionKeyBase64: btoa(String.fromCharCode(...Array(32).fill(1))),
      timeZone: "Europe/Paris",
    })).toBeNull();
  });
});

describe("Frigate Review producer contract", () => {
  const valid = {
    source: "cloudflare-relay",
    sourceSchema: "frigate-review-v1",
    reviewId: "review-1",
    reviewSeverity: "alert",
    eventId: "event-1",
    camera: "front_door",
    label: "person",
    detected_at: 1_712_345_678,
    score: 0.94,
    zones: ["porch"],
  } as const;

  it("accepts a canonical correlated envelope", () => {
    expect(validateReviewEnvelope(valid)?.eventId).toBe("event-1");
  });

  it("rejects raw and identity/severity drift", () => {
    expect(validateReviewEnvelope({ type: "new", after: { id: "event-1" } })).toBeNull();
    expect(validateReviewEnvelope({ ...valid, sourceSchema: "raw-event-v1" })).toBeNull();
    expect(validateReviewEnvelope({ ...valid, reviewSeverity: "critical" })).toBeNull();
    expect(validateReviewEnvelope({ ...valid, score: 1.1 })).toBeNull();
  });

  it("verifies a revision-bound automation MAC and rejects tampering", async () => {
    const key = "local-test-automation-key";
    const decision = {
      ...valid,
      automationSchema: "lumen-automation-decision-v1",
      policyRevision: 42,
      policyHash: `sha256:${"ab".repeat(32)}`,
      ruleId: "rule-1",
      branchId: "branch-1",
      decisionId: "review-1/alert/42",
      presentation: { disposition: "normal", priority: "timeSensitive" },
    } as const;
    const input = [
      "review-1", "alert", "event-1", "42", `sha256:${"ab".repeat(32)}`,
      "rule-1", "branch-1", "review-1/alert/42", "normal", "timeSensitive", "", "", "",
    ].join("\n");
    const cryptoKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const mac = Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(input))))
      .map((byte) => byte.toString(16).padStart(2, "0")).join("");
    expect(await verifyAutomationDecision({ ...decision, decisionMAC: mac }, key)).toBe(true);
    expect(await verifyAutomationDecision({ ...decision, eventId: "tampered", decisionMAC: mac }, key)).toBe(false);
    expect(await verifyAutomationDecision({ ...decision, decisionId: "wrong", decisionMAC: mac }, key)).toBe(false);
    expect(await verifyAutomationDecision({
      ...decision,
      presentation: { disposition: "critical", priority: "timeSensitive" },
      decisionMAC: mac,
    }, key)).toBe(false);
  });

  it("blocks a signed suppression before APNs and rejects stale policy", async () => {
    const key = "local-test-automation-key";
    const policyHash = `sha256:${"ab".repeat(32)}`;
    const base = {
      ...valid,
      detected_at: Date.now() / 1000,
      automationSchema: "lumen-automation-decision-v1",
      policyRevision: 42,
      policyHash,
      ruleId: "rule-1",
      branchId: "branch-1",
      decisionId: "review-1/alert/42",
      presentation: { disposition: "suppress", priority: "normal" },
    } as const;
    const input = [
      "review-1", "alert", "event-1", "42", policyHash,
      "rule-1", "branch-1", "review-1/alert/42", "suppress", "normal", "", "", "",
    ].join("\n");
    const cryptoKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const decisionMAC = Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(input))))
      .map((byte) => byte.toString(16).padStart(2, "0")).join("");
    const { env } = makeEnv();
    env.AUTOMATION_DECISION_KEY = key;
    env.AUTOMATION_POLICY_REVISION = "42";
    env.AUTOMATION_POLICY_HASH = policyHash;
    const request = new Request(`https://push.test/v1/notify/${"01".repeat(16)}/${"ab".repeat(32)}`, {
      method: "POST", body: JSON.stringify({ ...base, decisionMAC }),
    });
    expect((await worker.fetch(request, env)).status).toBe(422);

    env.AUTOMATION_POLICY_REVISION = "43";
    const stale = new Request(`https://push.test/v1/notify/${"01".repeat(16)}/${"ab".repeat(32)}`, {
      method: "POST", body: JSON.stringify({ ...base, decisionMAC }),
    });
    expect((await worker.fetch(stale, env)).status).toBe(409);
  });

  it("requires a signed decision whenever an automation policy is active", async () => {
    const { env } = makeEnv();
    env.AUTOMATION_POLICY_REVISION = "42";
    env.AUTOMATION_POLICY_HASH = `sha256:${"ab".repeat(32)}`;
    const request = new Request(`https://push.test/v1/notify/${"01".repeat(16)}/${"ab".repeat(32)}`, {
      method: "POST",
      body: JSON.stringify({ ...valid, detected_at: Date.now() / 1000 }),
    });
    expect((await worker.fetch(request, env)).status).toBe(428);
  });

  it("matches the Swift critical-decision MAC fixture", async () => {
    const event = {
      ...valid,
      automationSchema: "lumen-automation-decision-v1",
      policyRevision: 42,
      policyHash: `sha256:${"ab".repeat(32)}`,
      ruleId: "rule-1",
      branchId: "branch-1",
      decisionId: "review-1/alert/42",
      presentation: {
        disposition: "critical",
        priority: "timeSensitive",
        category: "door",
        spokenTemplate: "personAtDoor",
        criticalVolume: 1.0,
      },
      decisionMAC: "0145b383409570bdd4577694daa4257eebd82efee8294d456c397f48810b3f30",
    } as const;
    expect(await verifyAutomationDecision(event, String.fromCharCode(...Array(32).fill(7)))).toBe(true);
  });
});

describe("published relay payloads", () => {
  const now = () => Date.now() / 1000;
  const rawEvent = () => ({
    id: "1726500000.1-abc", camera: "front_door", label: "person", top_score: 0.91,
    zones: ["porch"], has_snapshot: true, has_clip: false, start_time: now(),
    end_time: null, stationary: false, sub_label: ["Postman", 0.93],
  });
  const reviewEvent = () => ({
    id: "1726500000.2-def", camera: "driveway", label: "car", top_score: 0.8, zones: [],
    start_time: now(), detected_at: now(), review_id: "review-9", review_severity: "detection",
    source_schema: "frigate-review-v1", recognized_license_plate: "AB123CD", lumen_critical: true,
  });

  it("maps a raw Frigate event onto the Review envelope", () => {
    const event = normalizeNotifyBody(rawEvent());
    expect(event).not.toBeNull();
    expect(event).not.toBe("drop");
    const envelope = event as Exclude<typeof event, "drop" | null>;
    expect(envelope.reviewId).toBe("1726500000.1-abc");
    expect(envelope.reviewSeverity).toBe("alert");
    expect(envelope.score).toBe(0.91);
    expect(envelope.sub_label).toBe("Postman");
    expect(envelope.legacyCritical).toBeUndefined();
  });

  it("maps a snake_case review event and keeps the relay critical flag", () => {
    const envelope = normalizeNotifyBody(reviewEvent()) as Exclude<ReturnType<typeof normalizeNotifyBody>, "drop" | null>;
    expect(envelope.reviewId).toBe("review-9");
    expect(envelope.reviewSeverity).toBe("detection");
    expect(envelope.recognized_plate).toBe("AB123CD");
    expect(envelope.legacyCritical).toBe(true);
  });

  it("drops low-confidence raw events like the v1 Worker", () => {
    expect(normalizeNotifyBody({ ...rawEvent(), top_score: 0.3 })).toBe("drop");
  });

  it("never accepts the internal critical flag from a camelCase sender", () => {
    expect(validateReviewEnvelope({
      source: "relay", sourceSchema: "frigate-review-v1", reviewId: "r", reviewSeverity: "alert",
      eventId: "e", camera: "c", label: "person", detected_at: now(), score: 0.9, legacyCritical: true,
    })).toBeNull();
  });

  it("unwraps the published relay's MQTT envelope", () => {
    const wrapped = { type: "new", before: null, after: rawEvent() };
    const envelope = normalizeNotifyBody(wrapped) as Exclude<ReturnType<typeof normalizeNotifyBody>, "drop" | null>;
    expect(envelope?.eventId).toBe("1726500000.1-abc");
    expect(normalizeNotifyBody({ type: "update", before: rawEvent(), after: reviewEvent() })).not.toBeNull();
    expect(normalizeNotifyBody({ type: "end", before: rawEvent(), after: rawEvent() })).toBe("drop");
  });

  it("v1 and v2 notify routes accept published relay payloads", async () => {
    vi.stubGlobal("caches", { default: { match: async () => undefined, put: async () => undefined } });
    for (const body of [rawEvent(), reviewEvent(),
      { type: "new", before: null, after: rawEvent() },
      { type: "new", before: null, after: reviewEvent() }]) {
      const { env } = makeEnv();
      const v1 = await worker.fetch(new Request(`https://push.test/v1/notify/${"01".repeat(16)}/${"ab".repeat(32)}`, {
        method: "POST", body: JSON.stringify(body),
      }), env);
      expect(v1.status).not.toBe(400);
      const channel = await channelIDForSecret("0123456789abcdef0123456789abcdef");
      const v2 = await worker.fetch(new Request(`https://push.test/v2/notify/${channel}`, {
        method: "POST", body: JSON.stringify(body),
      }), env);
      expect(v2.status).not.toBe(400);
    }
    vi.unstubAllGlobals();
  });
});

describe("channel status", () => {
  const secret = "0123456789abcdef0123456789abcdef";

  it("requires the channel secret", async () => {
    const { env } = makeEnv();
    const channel = await channelIDForSecret(secret);
    const response = await worker.fetch(new Request(`https://push.test/v2/channels/${channel}/status`), env);
    expect(response.status).toBe(401);
  });

  it("reports devices, this device and the last relay outcome, including silent drops", async () => {
    const { env, devices } = makeEnv();
    const channel = await channelIDForSecret(secret);
    await devices.put(`devices:${channel}`, JSON.stringify([{ token: "ab".repeat(32), sandbox: false, platform: "ios", registered_at: 1 }]));
    const stale = { type: "new", before: null, after: {
      id: "old-1", camera: "front", label: "person", top_score: 0.9, zones: [], start_time: Date.now() / 1000 - 3600,
    } };
    const notify = await worker.fetch(new Request(`https://push.test/v2/notify/${channel}`, {
      method: "POST", headers: { "User-Agent": "lumen-push-relay/test" }, body: JSON.stringify(stale),
    }), env);
    expect(notify.status).toBe(200);

    const response = await worker.fetch(new Request(`https://push.test/v2/channels/${channel}/status?token=${"ab".repeat(32)}`, {
      headers: { Authorization: `Bearer ${secret}` },
    }), env);
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, any>;
    expect(body.deviceCount).toBe(1);
    expect(body.thisDevice).toEqual({ registered: true, sandbox: false });
    expect(body.devices[0].tokenSuffix).toBe("ababab");
    expect(body.lastNotify.status).toBe(200);
    expect(body.lastNotify.userAgent).toBe("lumen-push-relay/test");
  });

  it("recognises tokens APNs will never accept again", () => {
    expect(isDeadTokenResponse(410, '{"reason":"Unregistered"}')).toBe(true);
    expect(isDeadTokenResponse(400, '{"reason":"BadDeviceToken"}')).toBe(true);
    expect(isDeadTokenResponse(400, '{"reason":"DeviceTokenNotForTopic"}')).toBe(false);
    expect(isDeadTokenResponse(503, "")).toBe(false);
  });
});
