"""GET /scanners 的回應（docs/API_CONTRACT.md §2）。"""

from pydantic import BaseModel, ConfigDict

from secscan.core.api import UtcDatetime
from secscan.scanners.domain.instances import EngineStatus
from secscan.scanners.service import ProcessStatus, ScannerOverview
from secscan.scans.domain.catalog import Engine, ScanProfile


class EngineOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    engine: Engine
    integrated: bool
    available: bool
    image: str | None
    profiles: list[ScanProfile]
    unavailable_reason: str | None

    @classmethod
    def of(cls, status: EngineStatus) -> "EngineOut":
        return cls(
            engine=status.engine,
            integrated=status.integrated,
            available=status.available,
            image=status.image,
            profiles=list(status.profiles),
            unavailable_reason=status.unavailable_reason,
        )


class ProcessOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    alive: bool
    last_heartbeat_at: UtcDatetime | None

    @classmethod
    def of(cls, status: ProcessStatus) -> "ProcessOut":
        return cls(alive=status.alive, last_heartbeat_at=status.last_heartbeat_at)


class ScannersOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    engines: list[EngineOut]
    runner: ProcessOut
    worker: ProcessOut

    @classmethod
    def of(cls, overview: ScannerOverview) -> "ScannersOut":
        return cls(
            engines=[EngineOut.of(status) for status in overview.engines],
            runner=ProcessOut.of(overview.runner),
            worker=ProcessOut.of(overview.worker),
        )
