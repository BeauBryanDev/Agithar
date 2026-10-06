// Per-shop traffic contract (GET /traffic).

export interface PathRow {
  path: string;
  requests: number;
}
export interface ClientRow {
  ip: string;
  requests: number;
  errors: number;
}
export interface TypeRow {
  type: string;
  requests: number;
}
export interface SeriesPoint {
  time: number; // epoch seconds, start of the bucket
  requests: number;
  errors: number;
}

export interface ShopTraffic {
  name: string;
  host: string;
  requests: number;
  requests_per_minute: number;
  error_rate: number; // 0..1
  not_found_rate: number; // 0..1
  unique_clients: number;
  status_classes: Record<string, number>;
  peak_minute: { time: string | null; requests: number } | null;
  series: SeriesPoint[];
  top_paths: PathRow[];
  top_error_paths: PathRow[];
  top_clients: ClientRow[];
  client_types: TypeRow[];
}

export interface RecentError {
  time: string | null;
  shop: string;
  ip: string;
  method: string | null;
  path: string;
  status: number;
  client_type: string;
}

export interface TrafficData {
  available: boolean;
  note: string | null;
  window_minutes: number;
  window_complete: boolean;
  data_starts_at: string | null;
  older_lines_not_read: boolean;
  unreadable_lines: Record<string, number>;
  shops: ShopTraffic[];
  recent_errors: RecentError[];
}
