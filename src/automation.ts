export interface AutomationPresentation {
  disposition: "normal" | "critical" | "suppress";
  priority: "normal" | "timeSensitive";
  category?: string;
  spokenTemplate?: string;
  criticalVolume?: number;
}

export interface AutomationEvent {
  reviewId: string;
  reviewSeverity: "detection" | "alert";
  eventId: string;
  camera: string;
  label: string;
  score: number;
  zones?: string[];
  sub_label?: string | null;
  stationary?: boolean | null;
  has_clip?: boolean;
  recognized_plate?: string | null;
}

export interface StoredAutomationPolicy {
  schema: "lumen-automation-policy-v1";
  revision: number;
  hash: string;
  policyBase64: string;
  decisionKeyBase64: string;
  timeZone: string;
  updatedAt: number;
}

export interface AutomationDecisionFields {
  automationSchema: "lumen-automation-decision-v1";
  policyRevision: number;
  policyHash: string;
  ruleId: string;
  branchId: string;
  decisionId: string;
  presentation: AutomationPresentation;
  decisionMAC: string;
}

type JsonObject = Record<string, unknown>;
type Truth = "yes" | "no" | "unknown";

const ZERO_ID = "00000000-0000-0000-0000-000000000000";
const SUPPORTED_CONDITIONS = new Set([
  "camera", "label", "zone", "subLabel", "confidence", "timeOfDay",
  "dayOfWeek", "recognizedFace", "unknownFace", "recognizedPlate",
  "unknownPlate", "stationary", "hasClip", "perRuleCooldown",
]);
const SUPPORTED_ACTIONS = new Set([
  "notification", "criticalAlert", "spokenAnnouncement", "suppressNotification",
]);

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function decodeBase64(value: string): Uint8Array | null {
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

function bytesToHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function validatePolicyUpload(value: unknown): Promise<StoredAutomationPolicy | null> {
  if (!isObject(value) || value.schema !== "lumen-automation-policy-v1") return null;
  if (!Number.isSafeInteger(value.revision) || (value.revision as number) <= 0) return null;
  if (typeof value.hash !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value.hash)) return null;
  if (typeof value.policyBase64 !== "string" || value.policyBase64.length > 174_764) return null;
  if (typeof value.decisionKeyBase64 !== "string") return null;
  if (typeof value.timeZone !== "string" || value.timeZone.length === 0 || value.timeZone.length > 64) return null;
  try { new Intl.DateTimeFormat("en-US", { timeZone: value.timeZone }).format(new Date(0)); } catch { return null; }
  const policyBytes = decodeBase64(value.policyBase64);
  const keyBytes = decodeBase64(value.decisionKeyBase64);
  if (!policyBytes || policyBytes.byteLength === 0 || policyBytes.byteLength > 131_072) return null;
  if (!keyBytes || keyBytes.byteLength !== 32) return null;
  const actualHash = `sha256:${bytesToHex(await crypto.subtle.digest("SHA-256", policyBytes))}`;
  if (actualHash !== value.hash) return null;
  let rules: unknown;
  try { rules = JSON.parse(new TextDecoder().decode(policyBytes)); } catch { return null; }
  if (!Array.isArray(rules) || !rules.every(ruleIsSupported)) return null;
  return {
    schema: "lumen-automation-policy-v1",
    revision: value.revision as number,
    hash: value.hash,
    policyBase64: value.policyBase64,
    decisionKeyBase64: value.decisionKeyBase64,
    timeZone: value.timeZone,
    updatedAt: Math.floor(Date.now() / 1000),
  };
}

function expressionIsSupported(value: unknown): boolean {
  if (!isObject(value) || typeof value.kind !== "string") return false;
  if (value.kind === "all" || value.kind === "any") {
    return Array.isArray(value.parts) && value.parts.length > 0 && value.parts.every(expressionIsSupported);
  }
  if (value.kind === "not") return expressionIsSupported(value.expression);
  if (value.kind !== "condition" || !isObject(value.condition)) return false;
  const keys = Object.keys(value.condition);
  return keys.length === 1 && SUPPORTED_CONDITIONS.has(keys[0])
    && conditionPayloadIsValid(keys[0], value.condition[keys[0]]);
}

function nonEmptyString(value: unknown, max = 256): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

function conditionPayloadIsValid(name: string, raw: unknown): boolean {
  const value = isObject(raw) ? raw : {};
  // NumericComparison is a Swift RawRepresentable enum. These compact wire
  // values are the canonical JSON emitted by AutomationRuleV4.
  const comparison = ["gt", "gte", "lt", "lte", "eq"];
  switch (name) {
    case "camera": case "label": return nonEmptyString(value.name);
    case "zone": return nonEmptyString(value.camera) && nonEmptyString(value.zone);
    case "subLabel": return nonEmptyString(value.value);
    case "confidence": return comparison.includes(String(value.comparison))
      && typeof value.value === "number" && Number.isFinite(value.value) && value.value >= 0 && value.value <= 1;
    case "timeOfDay": return Number.isInteger(value.startMinutes) && Number.isInteger(value.endMinutes)
      && (value.startMinutes as number) >= 0 && (value.startMinutes as number) < 1440
      && (value.endMinutes as number) >= 0 && (value.endMinutes as number) < 1440;
    case "dayOfWeek": return Number.isInteger(value.daysMask) && (value.daysMask as number) > 0 && (value.daysMask as number) <= 127;
    case "recognizedFace": return Array.isArray(value.names) && value.names.length > 0 && value.names.length <= 64
      && value.names.every((entry) => nonEmptyString(entry, 128));
    case "recognizedPlate": return Array.isArray(value.plates) && value.plates.length > 0 && value.plates.length <= 64
      && value.plates.every((entry) => nonEmptyString(entry, 64));
    case "stationary": return typeof value.stationary === "boolean";
    case "perRuleCooldown": return Number.isInteger(value.seconds) && (value.seconds as number) >= 0 && (value.seconds as number) <= 604_800;
    case "unknownFace": case "unknownPlate": case "hasClip": return Object.keys(value).length === 0;
    default: return false;
  }
}

function actionIsSupported(raw: unknown): boolean {
  if (!isObject(raw)) return false;
  const keys = Object.keys(raw);
  if (keys.length !== 1 || !SUPPORTED_ACTIONS.has(keys[0])) return false;
  const name = keys[0], value = isObject(raw[name]) ? raw[name] as JsonObject : {};
  const categoryIsValid = value.category === undefined || value.category === null || nonEmptyString(value.category, 64);
  if (name === "notification") {
    return (value.priority === "normal" || value.priority === "timeSensitive") && categoryIsValid;
  }
  if (name === "criticalAlert") {
    return typeof value.volume === "number" && Number.isFinite(value.volume)
      && value.volume >= 0 && value.volume <= 1 && categoryIsValid;
  }
  if (name === "spokenAnnouncement") {
    return ["personAtDoor", "detectionAtCamera", "criticalDetection"].includes(String(value.template))
      && typeof value.critical === "boolean";
  }
  return name === "suppressNotification" && Object.keys(value).length === 0;
}

function ruleIsSupported(value: unknown): boolean {
  if (!isObject(value) || value.schemaVersion !== 4 || !nonEmptyString(value.id, 64)
      || !nonEmptyString(value.name, 256) || !Array.isArray(value.branches) || value.branches.length === 0
      || (value.cooldownSeconds !== undefined && (!Number.isInteger(value.cooldownSeconds)
        || (value.cooldownSeconds as number) < 0 || (value.cooldownSeconds as number) > 604_800))) return false;
  if (value.enabled !== true || value.sideEffectAuthority !== "bridgeRequired") return true;
  const branches = value.branches as unknown[];
  let sawElse = false;
  return branches.every((branch, index) => {
    if (!isObject(branch) || typeof branch.id !== "string" || !Array.isArray(branch.actions) || branch.actions.length === 0) return false;
    if (branch.kind === "if" && index !== 0) return false;
    if (branch.kind === "elseIf" && (index === 0 || sawElse)) return false;
    if (branch.kind === "else") {
      if (index === 0 || sawElse || index !== branches.length - 1 || branch.expression !== undefined) return false;
      sawElse = true;
    } else if ((branch.kind !== "if" && branch.kind !== "elseIf") || !expressionIsSupported(branch.expression)) return false;
    if (!branch.actions.every(actionIsSupported)) return false;
    const actionNames = branch.actions.map((action) => Object.keys(action as JsonObject)[0]);
    if (actionNames.includes("suppressNotification") && actionNames.length !== 1) return false;
    return actionNames.filter((name) => name === "notification" || name === "criticalAlert").length <= 1;
  });
}

function compare(actual: number, target: number, operation: unknown): Truth {
  if (!Number.isFinite(actual) || !Number.isFinite(target)) return "unknown";
  switch (operation) {
    case "gt": return actual > target ? "yes" : "no";
    case "gte": return actual >= target ? "yes" : "no";
    case "lt": return actual < target ? "yes" : "no";
    case "lte": return actual <= target ? "yes" : "no";
    case "eq": return actual === target ? "yes" : "no";
    default: return "unknown";
  }
}

function truth(value: boolean): Truth { return value ? "yes" : "no"; }

function normalizePlate(value: string): string {
  return value.normalize("NFKD").toUpperCase().replace(/[^A-Z0-9]/g, "");
}

function clockParts(now: Date, timeZone: string): { minute: number; weekdayBit: number } | null {
  try {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23",
    }).formatToParts(now);
    const value = Object.fromEntries(parts.map((part) => [part.type, part.value]));
    const weekdays: Record<string, number> = { Mon: 0, Tue: 1, Wed: 2, Thu: 3, Fri: 4, Sat: 5, Sun: 6 };
    const hour = Number(value.hour), minute = Number(value.minute), weekdayBit = weekdays[value.weekday];
    return Number.isInteger(hour) && Number.isInteger(minute) && weekdayBit !== undefined
      ? { minute: hour * 60 + minute, weekdayBit } : null;
  } catch { return null; }
}

function evaluateCondition(
  condition: JsonObject,
  event: AutomationEvent,
  now: Date,
  timeZone: string,
  ruleId: string,
  lastFired: Map<string, number>,
): Truth {
  const keys = Object.keys(condition);
  if (keys.length !== 1) return "unknown";
  const name = keys[0];
  const value = isObject(condition[name]) ? condition[name] as JsonObject : {};
  switch (name) {
    case "camera": return typeof value.name === "string" ? truth(event.camera === value.name) : "unknown";
    case "label": return typeof value.name === "string" ? truth(event.label === value.name) : "unknown";
    case "zone": return typeof value.camera === "string" && typeof value.zone === "string"
      ? truth(event.camera === value.camera && (event.zones ?? []).includes(value.zone)) : "unknown";
    case "subLabel": return typeof value.value === "string" ? truth(event.sub_label === value.value) : "unknown";
    case "confidence": return typeof value.value === "number" ? compare(event.score, value.value, value.comparison) : "unknown";
    case "timeOfDay": {
      if (!Number.isInteger(value.startMinutes) || !Number.isInteger(value.endMinutes)) return "unknown";
      const parts = clockParts(now, timeZone);
      if (!parts) return "unknown";
      const minute = parts.minute;
      const start = value.startMinutes as number, end = value.endMinutes as number;
      return truth(start <= end ? minute >= start && minute <= end : minute >= start || minute <= end);
    }
    case "dayOfWeek": {
      if (!Number.isInteger(value.daysMask)) return "unknown";
      const parts = clockParts(now, timeZone);
      return parts ? truth(((value.daysMask as number) & (1 << parts.weekdayBit)) !== 0) : "unknown";
    }
    case "recognizedFace": return Array.isArray(value.names) && typeof event.sub_label === "string"
      ? truth(value.names.includes(event.sub_label)) : "no";
    case "unknownFace": return truth(event.label === "person" && !event.sub_label);
    case "recognizedPlate": return Array.isArray(value.plates) && typeof event.recognized_plate === "string"
      ? truth(value.plates.some((plate) => typeof plate === "string" && normalizePlate(plate) === normalizePlate(event.recognized_plate!))) : "no";
    case "unknownPlate": return truth(["car", "motorcycle", "license_plate"].includes(event.label) && !event.recognized_plate);
    case "stationary": return typeof value.stationary === "boolean" && typeof event.stationary === "boolean"
      ? truth(event.stationary === value.stationary) : "unknown";
    case "hasClip": return typeof event.has_clip === "boolean" ? truth(event.has_clip) : "unknown";
    case "perRuleCooldown": {
      if (!Number.isInteger(value.seconds)) return "unknown";
      const last = lastFired.get(ruleId);
      return last === undefined ? "yes"
        : truth(now.getTime() / 1000 - last >= (value.seconds as number));
    }
    default: return "unknown";
  }
}

function evaluateExpression(
  value: unknown,
  event: AutomationEvent,
  now: Date,
  timeZone: string,
  ruleId: string,
  lastFired: Map<string, number>,
): Truth {
  if (!isObject(value)) return "unknown";
  if (value.kind === "condition" && isObject(value.condition)) {
    return evaluateCondition(value.condition, event, now, timeZone, ruleId, lastFired);
  }
  if (value.kind === "not") {
    const result = evaluateExpression(value.expression, event, now, timeZone, ruleId, lastFired);
    return result === "yes" ? "no" : result === "no" ? "yes" : "unknown";
  }
  if ((value.kind === "all" || value.kind === "any") && Array.isArray(value.parts) && value.parts.length > 0) {
    const results = value.parts.map((part) => evaluateExpression(
      part, event, now, timeZone, ruleId, lastFired
    ));
    if (value.kind === "all") return results.includes("no") ? "no" : results.includes("unknown") ? "unknown" : "yes";
    return results.includes("yes") ? "yes" : results.includes("unknown") ? "unknown" : "no";
  }
  return "unknown";
}

function canonicalVolume(value: number | undefined): string {
  return value === undefined ? "" : value.toFixed(6).replace(/0+$/, "").replace(/\.$/, "");
}

function parsePolicy(record: StoredAutomationPolicy): JsonObject[] | null {
  const bytes = decodeBase64(record.policyBase64);
  if (!bytes) return null;
  try {
    const value = JSON.parse(new TextDecoder().decode(bytes));
    return Array.isArray(value) && value.every(ruleIsSupported) ? value as JsonObject[] : null;
  } catch { return null; }
}

export async function evaluateAndSignPolicy(
  record: StoredAutomationPolicy,
  event: AutomationEvent,
  lastFired: Map<string, number>,
  now = new Date(),
): Promise<AutomationDecisionFields | null> {
  const rules = parsePolicy(record);
  const key = decodeBase64(record.decisionKeyBase64);
  if (!rules || !key || key.byteLength !== 32) throw new Error("invalid_policy_record");
  let ruleId = ZERO_ID, branchId = ZERO_ID;
  let presentation: AutomationPresentation = { disposition: "normal", priority: "normal" };

  for (const rule of rules) {
    if (rule.enabled !== true || rule.sideEffectAuthority !== "bridgeRequired") continue;
    const id = typeof rule.id === "string" ? rule.id : "";
    if (!id || !Array.isArray(rule.branches)) throw new Error("invalid_policy_record");
    const cooldown = typeof rule.cooldownSeconds === "number" ? rule.cooldownSeconds : 0;
    const last = lastFired.get(id);
    if (cooldown > 0 && last !== undefined && now.getTime() / 1000 - last < cooldown) continue;
    let selected: JsonObject | null = null;
    for (const rawBranch of rule.branches) {
      if (!isObject(rawBranch)) continue;
      if (rawBranch.kind === "else") { selected = rawBranch; break; }
      const result = evaluateExpression(
        rawBranch.expression, event, now, record.timeZone, id, lastFired
      );
      if (result === "unknown") throw new Error("predicate_input_unavailable");
      if (result === "yes") { selected = rawBranch; break; }
    }
    if (!selected || !Array.isArray(selected.actions)) continue;
    lastFired.set(id, now.getTime() / 1000);
    if (ruleId === ZERO_ID) {
      ruleId = id;
      branchId = typeof selected.id === "string" ? selected.id : ZERO_ID;
    }
    for (const rawAction of selected.actions) {
      if (!isObject(rawAction)) continue;
      if (Object.prototype.hasOwnProperty.call(rawAction, "suppressNotification")) {
        presentation = { disposition: "suppress", priority: "normal" };
        break;
      }
      if (isObject(rawAction.notification)) {
        if (rawAction.notification.priority === "timeSensitive") presentation.priority = "timeSensitive";
        if (typeof rawAction.notification.category === "string" && rawAction.notification.category) presentation.category = rawAction.notification.category.slice(0, 64);
      }
      if (isObject(rawAction.criticalAlert)) {
        const volume = typeof rawAction.criticalAlert.volume === "number" ? rawAction.criticalAlert.volume : 1;
        presentation = { ...presentation, disposition: "critical", priority: "timeSensitive", criticalVolume: Math.min(1, Math.max(0, volume)) };
        if (typeof rawAction.criticalAlert.category === "string" && rawAction.criticalAlert.category) presentation.category = rawAction.criticalAlert.category.slice(0, 64);
      }
      if (isObject(rawAction.spokenAnnouncement)) {
        if (typeof rawAction.spokenAnnouncement.template === "string") presentation.spokenTemplate = rawAction.spokenAnnouncement.template.slice(0, 64);
        if (rawAction.spokenAnnouncement.critical === true) {
          presentation.disposition = "critical";
          presentation.priority = "timeSensitive";
          presentation.criticalVolume ??= 1;
        }
      }
    }
    if (presentation.disposition === "suppress") break;
  }

  const decisionId = `${event.reviewId}/${event.reviewSeverity}/${record.revision}`;
  const input = [event.reviewId, event.reviewSeverity, event.eventId, String(record.revision), record.hash,
    ruleId, branchId, decisionId, presentation.disposition, presentation.priority,
    presentation.category ?? "", presentation.spokenTemplate ?? "", canonicalVolume(presentation.criticalVolume)].join("\n");
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const decisionMAC = bytesToHex(await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(input)));
  return {
    automationSchema: "lumen-automation-decision-v1", policyRevision: record.revision,
    policyHash: record.hash, ruleId, branchId, decisionId, presentation, decisionMAC,
  };
}
