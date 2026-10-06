from pydantic import BaseModel, ConfigDict, Field

Counters = dict[str, int]
Statuses = dict[str, str]


class ServerTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cpu_percent: float
    memory_percent: float
    disk_percent: float
    disk_free_gb: float
    net_bytes_sent: int
    net_bytes_recv: int
    siblings: Statuses
    system: Statuses


class IngestionTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    running: bool
    log_only: bool
    hosts: list[str] = Field(max_length=20)
    counters: Counters
    seconds_since_last_scored_line: float | None
    open_windows: int


class DispatcherTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    running: int
    max_concurrent: int
    queue_limit: int
    runs_last_hour: int
    hourly_cap: int


class SensorTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    loaded: int
    failed: int
    complete: bool


class PipelineTelemetry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ingestion: IngestionTelemetry | None
    correlator_windows: int
    dispatcher: DispatcherTelemetry | None
    sensors: SensorTelemetry


class TelemetryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sampled_at: float
    server: ServerTelemetry | None
    pipeline: PipelineTelemetry
