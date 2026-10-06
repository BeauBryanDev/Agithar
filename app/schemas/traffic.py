from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PathRow(Strict):
    path: str
    requests: int


class ClientRow(Strict):
    ip: str
    requests: int
    errors: int


class TypeRow(Strict):
    type: str
    requests: int


class PeakMinute(Strict):
    time: Optional[str]
    requests: int


class SeriesPoint(Strict):
    time: int
    requests: int
    errors: int


class ShopTraffic(Strict):
    name: str
    host: str
    requests: int
    requests_per_minute: float
    error_rate: float
    not_found_rate: float
    unique_clients: int
    status_classes: dict[str, int]
    peak_minute: Optional[PeakMinute]
    series: list[SeriesPoint] = Field(max_length=120)
    top_paths: list[PathRow]
    top_error_paths: list[PathRow]
    top_clients: list[ClientRow]
    client_types: list[TypeRow]


class RecentError(Strict):
    time: Optional[str]
    shop: str
    ip: str
    method: Optional[str]
    path: str
    status: int
    client_type: str


class TrafficResponse(Strict):
    available: bool
    note: Optional[str] = None
    window_minutes: int
    window_complete: bool = False
    data_starts_at: Optional[str] = None
    older_lines_not_read: bool = False
    unreadable_lines: dict[str, int] = Field(default_factory=dict)
    shops: list[ShopTraffic] = Field(default_factory=list)
    recent_errors: list[RecentError] = Field(default_factory=list)
