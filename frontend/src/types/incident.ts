// Incident drill-down contract (GET /incidents/{case_key}).

import type { IncidentStatus } from "./feed";
import type { SeverityLevel } from "./vulnerability";

export interface Verdict {
  verdict: "confirmed" | "false_positive" | "needs_human";
  needs_human: boolean;
  confidence: number;
  mitre_technique: string | null;
  owasp_category: string | null;
  summary: string;
}

export interface Ioc {
  ioc_id: number;
  ioc_type: "ip" | "user_agent" | "hash" | "url";
  value: string;
  created_at: string;
}

export interface ActionTaken {
  action_id: number;
  tool_name: string;
  params: Record<string, unknown> | null;
  result: Record<string, unknown> | null;
  performed_by: string;
  created_at: string;
}

/** One sensor's best event for the window; extra keys are possible. */
export type EvidenceEntry = Record<string, unknown>;

export interface IncidentDetail {
  incident_id: number;
  case_key: string;
  ip: string;
  severity: SeverityLevel;
  composite_score: number;
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
  num_sensors: number;
  num_strong_sensors: number;
  contributing_sensors: string[];
  sensor_scores: Record<string, number>;
  event_counts: Record<string, number>;
  evidence: EvidenceEntry[];
  verdict: Verdict | null;
  report_md: string | null;
  notified: boolean;
  iocs: Ioc[];
  actions: ActionTaken[];
}
