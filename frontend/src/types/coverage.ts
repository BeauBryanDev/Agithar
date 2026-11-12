// ATT&CK detection coverage of the protected servers (GET /coverage).

export type CoverageLevel = 0 | 1 | 2 | 3;

export interface CoverageRow {
  technique: string;
  name: string;
  tactics: string[];
  parent: string | null;
  level: CoverageLevel;
  rules: number;
  usable_rules: number;
  usable_logs: string[];
  missing_logs: string[];
  sensors: string[];
  offline_sensors: string[];
  incidents: number;
  threat_groups: number;
  sample_rules: { rule_id: string; title: string }[];
}

export interface CoverageLevelCount {
  level: CoverageLevel;
  meaning: string;
  techniques: number;
}

export interface CoverageData {
  summary: {
    techniques_in_scope: number;
    levels: CoverageLevelCount[];
    seen_in_incidents: number;
  };
  collected_logs: string[];
  incident_window_days: number;
  incidents_available: boolean;
  attack_version: string;
  sigma_commit: string;
  attribution: string[];
  rows: CoverageRow[];
}
