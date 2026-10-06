// Sensor health, profile and feed activity (GET /sensors).

import type { LiveEvent } from "./live";

export interface SensorActivity {
  scored: number | null; // null: the feed does not drive this sensor
  flagged: number | null;
  flagged_last_hour: number;
  last_flagged_at: number | null; // epoch seconds
  recent: LiveEvent[];
}

export interface SensorInfo {
  name: string;
  status: "ok" | "error" | "bad_output" | "failed_to_load" | "missing";
  error: string | null;
  latency_ms: number | null;
  threshold: number | null;
  probe_score: number | null;
  purpose: string;
  model: string;
  trained_on: string;
  sees: string;
  fed_by: string;
  score: string;
  limits: string[];
  mitre: string | null;
  correlator_weight: number;
  counts_as_strong: boolean;
  activity: SensorActivity;
}

export interface SensorsData {
  sampled_at: number;
  all_healthy: boolean;
  how_cases_are_raised: string;
  feed_running: boolean;
  sensors: SensorInfo[];
}
