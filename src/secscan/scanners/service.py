"""runner 與 worker 的心跳，以及 GET /scanners 的內容（docs/DECISIONS.md §14.7）。"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session, sessionmaker

from secscan.scanners.domain.instances import (
    ALIVE_WITHIN,
    STALE_AFTER,
    Capabilities,
    EngineStatus,
    InstanceRole,
    capabilities_json,
    engine_statuses,
)
from secscan.scanners.repository import InstanceState, RunnerInstanceRepository


class Fleet:
    """一個 runner 或 worker 程序的心跳；每個操作一個短 transaction。"""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        owner: str,
        role: InstanceRole,
        software_version: str,
    ) -> None:
        self._sessions = sessions
        self._owner = owner
        self._role = role
        self._software_version = software_version

    def beat(self, capabilities: Capabilities) -> None:
        with self._sessions.begin() as session:
            RunnerInstanceRepository(session).beat(
                owner=self._owner,
                role=self._role,
                software_version=self._software_version,
                capabilities=capabilities_json(capabilities),
            )

    def others_alive(self) -> bool:
        """同一個角色是否還有其他 30 秒內有心跳的程序。"""
        with self._sessions.begin() as session:
            return RunnerInstanceRepository(session).others_alive(
                self._role, excluding=self._owner, alive_within=ALIVE_WITHIN
            )

    def prune(self) -> int:
        """刪掉 7 天沒有心跳的列（程序每次啟動都是新的一列）。"""
        with self._sessions.begin() as session:
            return RunnerInstanceRepository(session).prune(older_than=STALE_AFTER)


@dataclass(frozen=True, slots=True)
class ProcessStatus:
    alive: bool
    last_heartbeat_at: datetime | None


@dataclass(frozen=True, slots=True)
class ScannerOverview:
    engines: tuple[EngineStatus, ...]
    runner: ProcessStatus
    worker: ProcessStatus


class ScannerCatalog:
    """內容不分 project、不含秘密或路徑：任何有效的平台 key 都可以讀（API_CONTRACT.md §2）。"""

    def __init__(self, session: Session) -> None:
        self._instances = RunnerInstanceRepository(session)

    def describe(self) -> ScannerOverview:
        runner = self._instances.latest(InstanceRole.RUNNER, alive_within=ALIVE_WITHIN)
        worker = self._instances.latest(InstanceRole.WORKER, alive_within=ALIVE_WITHIN)
        live = runner.capabilities if runner is not None and runner.alive else None
        return ScannerOverview(
            engines=engine_statuses(live), runner=_status(runner), worker=_status(worker)
        )


def _status(state: InstanceState | None) -> ProcessStatus:
    if state is None:
        return ProcessStatus(alive=False, last_heartbeat_at=None)
    return ProcessStatus(alive=state.alive, last_heartbeat_at=state.heartbeat_at)
