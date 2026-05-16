/**
 * Rule-based event classification for Frigate detections.
 *
 * Phase 1: Rules-based (label + duration + time + zone → EventClass)
 * Phase 2: Cloudflare Worker AI (ML model inference)
 */

export interface EventClassification {
  class: string;  // EventClass from training
  severity: number;  // 0-5, where 5 is most critical
  confidence: number;  // 0.0-1.0
  context_flags: string[];  // Flags that influenced classification
  suggested_actions: string[];  // Recommended response
}

/**
 * Classify a Frigate event using rule-based heuristics.
 *
 * Maps detection characteristics → semantic event type + severity.
 * Designed to match the 18 classes from the trained DistilBERT model
 * so when Worker AI (Phase 2) is added, NSE template rendering remains
 * compatible.
 */
export function classifyEvent(event: {
  label: string;
  camera: string;
  zones: string[];
  top_score: number;
  start_time: number;  // Unix epoch seconds
  stationary?: boolean;
}): EventClassification {
  const label = event.label.toLowerCase();
  const score = event.top_score;
  const zones = event.zones.map(z => z.toLowerCase());

  // Calculate event duration (now - start_time)
  const durationSeconds = Math.floor(Date.now() / 1000) - event.start_time;

  // Time-of-day context
  const hour = new Date().getHours();
  const isNight = hour < 6 || hour >= 22;
  const isUnusualTime = hour < 5 || hour >= 23;

  const contextFlags: string[] = [];
  const suggestedActions: string[] = [];

  // Helper: Add flags based on duration
  if (event.stationary && durationSeconds > 30) {
    contextFlags.push("stationary_medium");
  }
  if (event.stationary && durationSeconds > 60) {
    contextFlags.push("stationary_long");
  }
  if (durationSeconds < 5) {
    contextFlags.push("fast_movement");
  }

  // Helper: Time context
  if (isUnusualTime) {
    contextFlags.push("unusual_time");
  }
  if (isNight) {
    contextFlags.push("dark_conditions");
  }

  // Helper: Confidence
  if (score < 0.6) {
    contextFlags.push("low_confidence");
  }
  if (score >= 0.9) {
    contextFlags.push("high_confidence");
  }

  // --- Classification Rules ---

  // Person detection
  if (label === "person") {
    // Loitering: stationary for >60s with high confidence
    if (event.stationary && durationSeconds > 60 && score >= 0.8) {
      if (isUnusualTime) {
        // Suspicious loitering at night/early morning
        suggestedActions.push("notify_immediately", "view_live", "two_way_audio");
        return {
          class: "suspiciousActivity",
          severity: 5,
          confidence: score,
          context_flags: contextFlags,
          suggested_actions: suggestedActions,
        };
      } else {
        // Normal loitering during day
        suggestedActions.push("notify_immediately", "view_live");
        return {
          class: "personLoitering",
          severity: 5,
          confidence: score,
          context_flags: contextFlags,
          suggested_actions: suggestedActions,
        };
      }
    }

    // Approaching: short duration, moving
    if (durationSeconds < 20 && !event.stationary) {
      suggestedActions.push("view_live");
      return {
        class: "personApproaching",
        severity: 4,
        confidence: score,
        context_flags: contextFlags,
        suggested_actions: suggestedActions,
      };
    }

    // Leaving: detection ending (this is a heuristic - end_time logic would be better)
    if (event.stationary && durationSeconds > 10 && durationSeconds < 30) {
      return {
        class: "personLeaving",
        severity: 2,
        confidence: score,
        context_flags: contextFlags,
        suggested_actions: [],
      };
    }

    // Default person: approaching
    suggestedActions.push("view_snapshot");
    return {
      class: "personApproaching",
      severity: 3,
      confidence: score,
      context_flags: contextFlags,
      suggested_actions: suggestedActions,
    };
  }

  // Package detection
  if (label === "package") {
    // Delivery: new stationary object
    if (event.stationary) {
      contextFlags.push("object_left");
      suggestedActions.push("view_snapshot");
      return {
        class: "packageDelivered",
        severity: 4,
        confidence: score,
        context_flags: contextFlags,
        suggested_actions: suggestedActions,
      };
    }

    // Pickup: moving package
    contextFlags.push("object_taken");
    suggestedActions.push("view_live", "view_clip");
    return {
      class: "packagePickup",
      severity: 5,
      confidence: score,
      context_flags: contextFlags,
      suggested_actions: suggestedActions,
    };
  }

  // Vehicle detection
  if (label === "car" || label === "vehicle" || label === "truck") {
    // Parking: stationary vehicle
    if (event.stationary && durationSeconds > 30) {
      return {
        class: "vehicleParking",
        severity: 3,
        confidence: score,
        context_flags: contextFlags,
        suggested_actions: [],
      };
    }

    // Passing: short duration
    if (durationSeconds < 15) {
      return {
        class: "vehiclePassing",
        severity: 1,
        confidence: score,
        context_flags: contextFlags,
        suggested_actions: [],
      };
    }

    // Arriving: moderate duration, not yet parked
    if (durationSeconds < 30) {
      return {
        class: "vehicleArriving",
        severity: 3,
        confidence: score,
        context_flags: contextFlags,
        suggested_actions: [],
      };
    }

    // Leaving: longer duration (heuristic)
    return {
      class: "vehicleLeaving",
      severity: 2,
      confidence: score,
      context_flags: contextFlags,
      suggested_actions: [],
    };
  }

  // Animal detection
  if (label === "cat" || label === "dog" || label === "bird" || label === "animal") {
    return {
      class: "animalPassing",
      severity: 1,
      confidence: score,
      context_flags: contextFlags,
      suggested_actions: [],
    };
  }

  // Low confidence → likely false positive
  if (score < 0.6) {
    return {
      class: "falsePositive",
      severity: 1,
      confidence: score,
      context_flags: contextFlags,
      suggested_actions: [],
    };
  }

  // Fast movement / motion blur
  if (durationSeconds < 3) {
    return {
      class: "motionBlur",
      severity: 1,
      confidence: score,
      context_flags: contextFlags,
      suggested_actions: [],
    };
  }

  // Multiple objects (this would need count from Frigate, which isn't in the current payload)
  // For now, skip this case

  // Default: routine activity
  return {
    class: "routineActivity",
    severity: 1,
    confidence: score,
    context_flags: contextFlags,
    suggested_actions: [],
  };
}
