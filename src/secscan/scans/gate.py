"""runner 重新判斷 gate 的讀取（docs/DECISIONS.md §10.6、§17.5）：判斷本身在 domain/gate.py。

- locked：prepare 用。target、grant 與建立者的 key 以 FOR SHARE 鎖住（在 scan 之後），撤銷與
  停用要等這個 transaction 結束；時間在取得鎖之後才取。
- current：心跳用。不加鎖、一定向 DB 重新讀取：心跳不等撤銷或停用的 FOR UPDATE，commit 之後的
  下一次心跳就看得到。綁定的 profile 不檢查（PATCH 不影響已啟動的 run，§14.12）。
"""

from collections.abc import Callable
from datetime import datetime

from sqlalchemy.orm import Session

from secscan.api_keys.repository import ApiKeyRepository
from secscan.grants.domain.lifecycle import ScopeGrant
from secscan.grants.repository import ScopeGrantRepository
from secscan.scans.domain.gate import creator_error, gate_error
from secscan.scans.domain.lifecycle import RunErrorCode
from secscan.scans.progress import LockedScan
from secscan.targets.domain import LabNetwork
from secscan.targets.repository import TargetRepository


class RunGate:
    def __init__(self, session: Session, *, lab: LabNetwork) -> None:
        self._targets = TargetRepository(session)
        self._grants = ScopeGrantRepository(session)
        self._keys = ApiKeyRepository(session)
        self._lab = lab

    def locked(
        self, scan: LockedScan, clock: Callable[[], datetime]
    ) -> tuple[RunErrorCode | None, ScopeGrant | None]:
        """通過時一併回傳鎖住的 grant：guard 的 policy 以它的範圍與期限產生（§15.7）。"""
        target = self._targets.lock(scan.target_id, shared=True)
        grant = self._grants.lock(scan.scope_grant_id, shared=True)
        error = gate_error(
            target=target, grant=grant, origin=scan.target_origin, lab=self._lab, now=clock()
        )
        return (error, None) if error is not None else (None, grant)

    def locked_creator(self, scan: LockedScan) -> RunErrorCode | None:
        return creator_error(self._keys.lock_shared(scan.created_by_key_id))

    def current(self, scan: LockedScan, clock: Callable[[], datetime]) -> RunErrorCode | None:
        target = self._targets.current(scan.target_id)
        grant = self._grants.current(scan.scope_grant_id)
        error = gate_error(
            target=target, grant=grant, origin=scan.target_origin, lab=self._lab, now=clock()
        )
        return error or creator_error(self._keys.current(scan.created_by_key_id))
