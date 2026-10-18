"""稽核事件的 domain model；只用標準函式庫。

稽核紀錄只能新增，不能修改或刪除（DB trigger 強制，目前防的是程式錯誤造成的誤改，
不是已取得 DDL 能力的攻擊者；見 docs/DECISIONS.md §7）。redacted_changes 必須先以
security.redaction 遮罩（audit service 會處理），不得放入秘密、Token 或完整的請求內容
（CLAUDE.md §9）；這裡再檢查一次，並限制大小。
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from secscan.core.json_types import JsonValue
from secscan.core.text import require_text
from secscan.security.redaction import redact_object

AUDIT_LABEL_MAX_LENGTH = 64
REQUEST_ID_MAX_LENGTH = 64
# 稽核只記必要的變更摘要；序列化（UTF-8）後超過這個大小就是呼叫端放了不該放的內容。
AUDIT_CHANGES_MAX_BYTES = 8 * 1024


@dataclass(frozen=True, slots=True)
class NewAuditEvent:
    """要寫入的事件。actor 為 None 代表本機 CLI 或系統動作；project 為 None 代表全域動作。"""

    action: str
    object_type: str
    actor_key_id: UUID | None = None
    project_id: UUID | None = None
    object_id: UUID | None = None
    request_id: str | None = None
    redacted_changes: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require_text(self.action, field="action", max_length=AUDIT_LABEL_MAX_LENGTH)
        require_text(self.object_type, field="object_type", max_length=AUDIT_LABEL_MAX_LENGTH)
        if self.request_id is not None:
            require_text(self.request_id, field="request_id", max_length=REQUEST_ID_MAX_LENGTH)
        _check_changes(self.redacted_changes)


def _check_changes(changes: Mapping[str, JsonValue]) -> None:
    """已遮罩（再遮罩一次結果不變）、是合法的 JSON，而且不超過大小上限。"""
    plain = dict(changes)
    if redact_object(plain) != plain:
        raise ValueError("redacted_changes 必須先以 security.redaction.redact_object 遮罩")
    try:
        encoded = json.dumps(plain, ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise ValueError("redacted_changes 必須是 JSON 物件") from exc
    if len(encoded) > AUDIT_CHANGES_MAX_BYTES:
        raise ValueError(f"redacted_changes 不可超過 {AUDIT_CHANGES_MAX_BYTES} bytes")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    id: UUID
    created_at: datetime
    action: str
    object_type: str
    actor_key_id: UUID | None
    project_id: UUID | None
    object_id: UUID | None
    request_id: str | None
    redacted_changes: Mapping[str, JsonValue]
