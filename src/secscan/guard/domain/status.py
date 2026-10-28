"""guard 的 status（docs/DECISIONS.md §15.3）：guard 每 5 秒原子寫入，runner 據此判斷能不能認領。

boot_id 每次啟動隨機產生：執行中的 run 看到它改變，就知道 guard 重啟過（可能漏掉請求），
不再相信這個 run 的出站紀錄。
"""

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from secscan.guard.domain.policy import POLICY_SCHEMA
from secscan.guard.domain.strict import dump_canonical, load_object

STATUS_SCHEMA = 1
STATUS_FILE_NAME = "status.json"
STATUS_INTERVAL_SECONDS = 5
# 超過三次沒有更新就不可用（容許一次寫入延遲）。
STATUS_FRESH_SECONDS = 15
MAX_STATUS_BYTES = 4096
_FIELDS = frozenset(
    {"schema", "boot_id", "started_at", "updated_at", "listen", "policy_schema", "enforcing"}
)


class StatusError(ValueError):
    """status 不合格式。"""


class StatusIssue(StrEnum):
    MISSING = "MISSING"
    INVALID = "INVALID"
    STALE = "STALE"
    VERSION = "VERSION"
    LISTEN = "LISTEN"
    NOT_ENFORCING = "NOT_ENFORCING"


@dataclass(frozen=True, slots=True)
class GuardStatus:
    boot_id: UUID
    started_at: int
    updated_at: int
    listen: str
    policy_schema: int
    enforcing: bool


def encode_status(status: GuardStatus) -> bytes:
    return dump_canonical(
        {
            "schema": STATUS_SCHEMA,
            "boot_id": str(status.boot_id),
            "started_at": status.started_at,
            "updated_at": status.updated_at,
            "listen": status.listen,
            "policy_schema": status.policy_schema,
            "enforcing": status.enforcing,
        }
    )


def decode_status(raw: bytes) -> GuardStatus:
    document = load_object(
        raw, fields=_FIELDS, max_bytes=MAX_STATUS_BYTES, label="status", error=StatusError
    )
    if document.integer("schema") != STATUS_SCHEMA:
        raise StatusError(f"schema 必須是 {STATUS_SCHEMA}")
    return GuardStatus(
        boot_id=document.uuid("boot_id"),
        started_at=document.integer("started_at"),
        updated_at=document.integer("updated_at"),
        listen=document.string("listen"),
        policy_schema=document.integer("policy_schema"),
        enforcing=document.boolean("enforcing"),
    )


def status_issue(status: GuardStatus | None, *, now: float, listen: str) -> StatusIssue | None:
    """guard 可用時回傳 None：最近有更新、policy 的版本相符、聽在 runner 設定的位址、正在檢查。"""
    if status is None:
        return StatusIssue.MISSING
    if abs(now - status.updated_at) > STATUS_FRESH_SECONDS:
        return StatusIssue.STALE
    if status.policy_schema != POLICY_SCHEMA:
        return StatusIssue.VERSION
    if status.listen != listen:
        return StatusIssue.LISTEN
    if not status.enforcing:
        return StatusIssue.NOT_ENFORCING
    return None
