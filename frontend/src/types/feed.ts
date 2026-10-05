// Detection feed contract: one row per incident (GET /incidents).

import type { SeverityLevel } from "./vulnerability";

export type IncidentStatus =
  | "open"
  | "confirmed"
  | "false_positive"
  | "needs_human"
  | "closed";

export interface DetectionRow {
  incident_id: number;
  case_key: string;
  ip: string; // the client IP of the incident
  severity: SeverityLevel;
  composite_score: number; // 0.0 - 1.0
  status: IncidentStatus; // "open" until the master agent has a verdict
  created_at: string; // ISO 8601
  sensors: string[]; // sensor ids that contributed
  confidence: number | null; // the master's confidence, once it has a verdict
  mitre_technique: string | null; // set by the master, null until then
  notified: boolean; // the admin alert was sent
}

export interface FeedList {
  items: DetectionRow[];
  total: number;
  skip: number;
  limit: number;
}

export interface FeedFilterState {
  severity: SeverityLevel | "all";
  source: string; // free text, "" means all
}
