// Upload analysis contract (POST /ingest).

import type { SeverityLevel } from "./vulnerability";

export type IngestKind = "access_log" | "event_ids" | "flow_csv";

export interface SensorStat {
  sensor: string;
  scored: number;
  flagged: number;
  max_score: number;
}

export interface SourceSummary {
  source: string;
  severity: Exclude<SeverityLevel, "critical">;
  composite_score: number;
  sensors: string[];
  items: number;
  flagged: number;
}

export interface Finding {
  sensor: string;
  score: number;
  source: string | null;
  path: string | null;
  status: number | null;
  count: number;
  detail: string | null;
  time: number | null; // epoch seconds
}

export interface IngestResult {
  filename: string;
  size_bytes: number;
  kind: IngestKind;
  kind_label: string;
  items_read: number;
  items_unreadable: number;
  truncated: boolean;
  truncated_reason: string | null;
  duration_ms: number;
  severity: Exclude<SeverityLevel, "critical">;
  composite_score: number;
  time_first: number | null;
  time_last: number | null;
  sensors: SensorStat[];
  sources: SourceSummary[];
  findings: Finding[];
  breakdown: Record<string, number>;
  notes: string[];
}
