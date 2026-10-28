"""runner_instances 的存取（docs/DECISIONS.md §14.7）。時間一律以 DB 的時鐘判斷。"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from secscan.core.json_types import JsonObject
from secscan.scanners.domain.instances import Capabilities, InstanceRole, read_capabilities
from secscan.scanners.models import RunnerInstanceModel


@dataclass(frozen=True, slots=True)
class InstanceState:
    heartbeat_at: datetime
    alive: bool
    capabilities: Capabilities


class RunnerInstanceRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def beat(
        self,
        *,
        owner: str,
        role: InstanceRole,
        software_version: str,
        capabilities: JsonObject,
    ) -> None:
        """同一個 owner 只更新同一列：心跳的時間與最新的能力。"""
        statement = insert(RunnerInstanceModel).values(
            role=role.value,
            owner=owner,
            software_version=software_version,
            capabilities=capabilities,
            heartbeat_at=func.statement_timestamp(),
        )
        self._session.execute(
            statement.on_conflict_do_update(
                index_elements=[RunnerInstanceModel.owner],
                set_={
                    "heartbeat_at": func.statement_timestamp(),
                    "capabilities": statement.excluded.capabilities,
                    "software_version": statement.excluded.software_version,
                },
            )
        )

    def latest(self, role: InstanceRole, *, alive_within: timedelta) -> InstanceState | None:
        """這個角色最近一次的心跳（不論是否存活）；從沒有心跳時回 None。"""
        alive = RunnerInstanceModel.heartbeat_at > func.clock_timestamp() - alive_within
        row = self._session.execute(
            select(
                RunnerInstanceModel.heartbeat_at,
                RunnerInstanceModel.capabilities,
                alive.label("alive"),
            )
            .where(RunnerInstanceModel.role == role.value)
            .order_by(RunnerInstanceModel.heartbeat_at.desc())
            .limit(1)
        ).first()
        if row is None:
            return None
        return InstanceState(
            heartbeat_at=row.heartbeat_at,
            alive=bool(row.alive),
            capabilities=read_capabilities(row.capabilities),
        )

    def others_alive(self, role: InstanceRole, *, excluding: str, alive_within: timedelta) -> bool:
        return (
            self._session.execute(
                select(RunnerInstanceModel.id)
                .where(
                    RunnerInstanceModel.role == role.value,
                    RunnerInstanceModel.owner != excluding,
                    RunnerInstanceModel.heartbeat_at > func.clock_timestamp() - alive_within,
                )
                .limit(1)
            ).first()
            is not None
        )

    def prune(self, *, older_than: timedelta) -> int:
        removed = self._session.execute(
            delete(RunnerInstanceModel)
            .where(RunnerInstanceModel.heartbeat_at < func.clock_timestamp() - older_than)
            .returning(RunnerInstanceModel.id)
        ).all()
        return len(removed)
