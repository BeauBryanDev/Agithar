// Live telemetry contract (GET /telemetry).

export interface ServerTelemetry {
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
  disk_free_gb: number;
  net_bytes_sent: number;
  net_bytes_recv: number;
  siblings: Record<string, string>;
  system: Record<string, string>;
}

export interface IngestionTelemetry {
  running: boolean;
  log_only: boolean;
  hosts: string[];
  counters: Record<string, number>;
  seconds_since_last_scored_line: number | null;
  open_windows: number;
}

export interface DispatcherTelemetry {
  running: number;
  max_concurrent: number;
  queue_limit: number;
  runs_last_hour: number;
  hourly_cap: number;
}

export interface PipelineTelemetry {
  ingestion: IngestionTelemetry | null;
  correlator_windows: number;
  dispatcher: DispatcherTelemetry | null;
  sensors: { loaded: number; failed: number; complete: boolean };
}

export interface Telemetry {
  sampled_at: number; // epoch seconds
  server: ServerTelemetry | null;
  pipeline: PipelineTelemetry;
}
