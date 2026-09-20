# Strict Review evidence rollout

This candidate requires an explicitly correlated `frigate-review-v1` envelope with a real Review ID, severity and object confidence. Raw events and fabricated/missing evidence are rejected. Upgrade active relays first; the old 1.2.0 image and the September 16 Review projection do not supply the full contract.

Use the tested `review-confidence-20260920` relay image, preserving MQTT credentials, push destinations and delivery-state storage. Confirm qualifying and suppressed cases on a controlled channel/device before routing production traffic to this Worker. Global activation before migration will stop legacy relay pushes.

Per-device acceptance receipts prevent repeated sends to successful recipients when another device fails. Enrichment requires a prior initial acceptance and is passive. Same-isolate concurrent sends coalesce; KV eventual consistency and the APNs crash boundary do not promise exactly-once delivery. An APNs collapse identifier does not cancel a separately scheduled local notification.

Validation: 39 Vitest tests plus TypeScript noEmit, including real relay-generated fixtures, low-confidence/label/stationary policy, orphan enrichment and partial delivery retries. Production APNs/device validation remains separate. No Worker is deployed by this repository's test workflow.

The configured Cloudflare account denied even read-only deployment access on 2026-09-20. Restore access to the existing `lumen-push` Worker before reviewing its active version and deploying this candidate. Do not create a replacement Worker or change channel secrets to bypass that access problem.
