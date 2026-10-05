// Dashboard contract (GET /dashboard) and sensor status (GET /detectors).

export interface TimelinePoint {
  timestamp: string; // ISO 8601, start of the bucket
  score: number; // highest composite score in the bucket, 0 if none
  incidents: number;
}

export interface SensorCount {
  sensor: string;
  count: number;
}

export interface TechniqueCount {
  technique: string; // "T1595.002"
  name: string | null; // from the ATT&CK index
  count: number;
}

export interface DashboardData {
  window_hours: number;
  total_incidents: number;
  truncated: boolean;
  severity_distribution: Record<string, number>;
  status_counts: Record<string, number>;
  avg_confidence: number | null; // mean confidence of the master's verdicts
  timeline: TimelinePoint[];
  by_sensor: SensorCount[];
  top_techniques: TechniqueCount[];
}

export interface DetectorInfo {
  name: string;
  status: "loaded" | "failed";
  model: string | null;
  threshold: number | null;
}

export interface DetectorsResponse {
  detectors: DetectorInfo[];
  complete: boolean;
}
