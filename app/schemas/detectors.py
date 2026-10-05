from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class DetectorInfo(BaseModel):
    name: str = Field(max_length=64)
    status: Literal["loaded", "failed"]
    model: Optional[str] = Field(default=None, max_length=64)
    threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    model_config = ConfigDict(extra="forbid")


class DetectorsResponse(BaseModel):
    detectors: list[DetectorInfo]
    complete: bool

    model_config = ConfigDict(extra="forbid")
