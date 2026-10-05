// Detector output contract — matches the FastAPI backend shapes.

// The sensor ids the backend sends (see sensors/registry.py).
export type DetectorName =
  | "log_sentinel"
  | "net_guard"
  | "http_payload_sensor"
  | "netflow_sensor"
  | "recon_sensor";

export type Verdict = "anomaly" | "normal";

/** Detector output — this is what LogSentinel actually returns today. */
export interface DetectorResult {
  id: string; // stable id, referenced by EvidenceRef
  detector: DetectorName;
  anomaly_score: number; // 0.0 - 1.0
  verdict: Verdict;
  threshold: number; // model-specific, read from backend, never hardcode 0.5
  raw: Record<string, unknown>;
}
