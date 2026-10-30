"""runner 重新判斷 gate（docs/DECISIONS.md §10.6、§17.5）：prepare 與心跳共用的純函式。

以建立 scan 時相同的規則判斷，回傳停止的錯誤碼（None 是可以繼續）。grant 不屬於這個 target、
origin 不在範圍內，都只有直接改了 DB 才會發生（SCOPE_MISMATCH）。
"""

from datetime import datetime

from secscan.api_keys.domain import ApiKey
from secscan.grants.domain.lifecycle import GrantUnusableError, ScopeGrant, check_usable
from secscan.scans.domain.lifecycle import GATE_ERROR_CODES, RunErrorCode
from secscan.targets.domain import LabNetwork, Origin, OutsideLabError, Target


def gate_error(
    *,
    target: Target | None,
    grant: ScopeGrant | None,
    origin: Origin,
    lab: LabNetwork,
    now: datetime,
) -> RunErrorCode | None:
    """origin 是 scan 的快照：target 的 origin 改了就不再相符。"""
    if target is None or grant is None or target.origin != origin:
        return RunErrorCode.SCOPE_MISMATCH
    try:
        check_usable(grant, target=target, lab=lab, now=now)
    except GrantUnusableError as exc:
        return GATE_ERROR_CODES[exc.reason]
    except OutsideLabError:
        return RunErrorCode.SCOPE_OUTSIDE_LAB
    return None


def creator_error(key: ApiKey | None) -> RunErrorCode | None:
    """建立 scan 的平台 key 已被撤銷：外洩的 key 排進佇列或正在執行的 scan 都停下。

    到期不算：到期是例行的，不代表 key 外洩（§13.5）。
    """
    if key is None or key.revoked_at is not None:
        return RunErrorCode.CREATOR_KEY_REVOKED
    return None
