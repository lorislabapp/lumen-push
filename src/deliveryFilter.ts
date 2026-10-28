/** Device-owned settings. No geolocation, credentials or notification history. */
export interface CameraDeliveryFilter {
  enabled: boolean;
  labels: string[];
  minScore: number;
  criticalMinScore: number;
  ignoreStationary: boolean;
  cooldownSeconds: number;
}

export interface DeliveryFilterPolicy {
  schema: "lumen-delivery-filter-v1";
  enabled: boolean;
  isPassthrough: boolean;
  reviewAlertsOnly: boolean;
  globalDefaults: CameraDeliveryFilter;
  cameras: Record<string, CameraDeliveryFilter>;
}

function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function validateDeliveryFilterPolicy(value: unknown): DeliveryFilterPolicy | null {
  if (!record(value) || value.schema !== "lumen-delivery-filter-v1"
      || typeof value.enabled !== "boolean" || typeof value.isPassthrough !== "boolean"
      || typeof value.reviewAlertsOnly !== "boolean" || !record(value.cameras)
      || Object.keys(value.cameras).length > 64) return null;
  function camera(value: unknown): CameraDeliveryFilter | null {
    if (!record(value) || typeof value.enabled !== "boolean" || !Array.isArray(value.labels)
        || value.labels.length > 64 || value.labels.some(x => typeof x !== "string" || x.length === 0 || x.length > 128)
        || typeof value.minScore !== "number" || !Number.isFinite(value.minScore) || value.minScore < 0 || value.minScore > 1
        || typeof value.criticalMinScore !== "number" || !Number.isFinite(value.criticalMinScore) || value.criticalMinScore < 0 || value.criticalMinScore > 1
        || typeof value.ignoreStationary !== "boolean" || !Number.isInteger(value.cooldownSeconds)
        || (value.cooldownSeconds as number) < 0 || (value.cooldownSeconds as number) > 86400) return null;
    // Persist only the reviewed allowlist, never arbitrary device-supplied fields.
    return { enabled: value.enabled, labels: value.labels as string[], minScore: value.minScore,
      criticalMinScore: value.criticalMinScore, ignoreStationary: value.ignoreStationary,
      cooldownSeconds: value.cooldownSeconds as number };
  }
  const globalDefaults = camera(value.globalDefaults);
  if (!globalDefaults) return null;
  const cameras: Record<string, CameraDeliveryFilter> = Object.create(null);
  for (const [name, raw] of Object.entries(value.cameras)) {
    if (!name || name.length > 256 || ["__proto__", "constructor", "prototype"].includes(name)) return null;
    const filter = camera(raw);
    if (!filter) return null;
    cameras[name] = filter;
  }
  return { schema: "lumen-delivery-filter-v1", enabled: value.enabled, isPassthrough: value.isPassthrough,
    reviewAlertsOnly: value.reviewAlertsOnly, globalDefaults, cameras };
}

export function deliveryFilterDecision(policy: DeliveryFilterPolicy | undefined,
  event: { camera: string; label: string; score: number; stationary?: boolean | null; reviewSeverity: string }): string | null {
  if (!policy) return null;
  if (!policy.enabled) return "disabled";
  if (policy.isPassthrough) return null;
  if (policy.reviewAlertsOnly && event.reviewSeverity !== "alert") return "review-alert-required";
  const filter = policy.cameras[event.camera] ?? policy.globalDefaults;
  if (!filter.enabled) return "camera-disabled";
  if (!filter.labels.includes(event.label)) return "label";
  if (!Number.isFinite(event.score) || event.score < filter.minScore || event.score > 1) return "confidence";
  // Unknown is not evidence of motion; no GenAI text is interpreted as a boolean.
  if (filter.ignoreStationary && event.stationary !== false) return "stationary-or-unknown";
  return null;
}
