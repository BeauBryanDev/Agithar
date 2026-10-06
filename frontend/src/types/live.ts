// Live feed contract (GET /live).

export interface LiveEvent {
  timestamp: number; // epoch seconds
  ip: string;
  sensor: string;
  score: number;
  status: number;
  path: string; // no query string
  host: string;
}

export interface MinutePoint {
  minute: number; // epoch seconds, start of the minute
  requests: number;
  anomalies: number;
}

export interface TopIp {
  ip: string;
  count: number;
  max_score: number;
  sensors: string[];
}

export interface TopPath {
  path: string;
  count: number;
}

export interface LiveData {
  enabled: boolean;
  log_only: boolean;
  events: LiveEvent[];
  per_minute: MinutePoint[];
  top_ips: TopIp[];
  top_paths: TopPath[];
  anomalies_in_window: number;
  window_minutes: number;
}
