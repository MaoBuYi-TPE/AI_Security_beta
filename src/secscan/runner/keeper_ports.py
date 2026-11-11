"""keeper 依賴的介面（runner/keeper.py；docs/DECISIONS.md §30.3、§30.12、§30.13）。

- Store：DB 的部分（scans.evidence_records.EvidenceStore）。
- Vault：active/ 的檔案（runner.evidence.EvidenceVault）。
- Isolation：隔離目錄的搬移與對帳（runner.isolation.HoldIsolation）。
"""

from collections.abc import Collection
from contextlib import AbstractContextManager
from datetime import datetime
from typing import Protocol
from uuid import UUID

from secscan.runner.evidence import DirectoryState
from secscan.scans.domain.evidence import EvidenceHoldCode, SealedEvidence
from secscan.scans.evidence_records import EvidenceRun


class Store(Protocol):
    def overdue(
        self, *, now: datetime, max_minutes: int, limit: int
    ) -> tuple[EvidenceRun, ...]: ...

    def expire(self, run: EvidenceRun, *, now: datetime, max_minutes: int) -> bool: ...

    def sealable(self, *, limit: int, exclude: Collection[UUID]) -> tuple[EvidenceRun, ...]: ...

    def record(self, run: EvidenceRun, sealed: SealedEvidence | None) -> bool: ...

    def purgeable(
        self, *, now: datetime, retention_days: int, limit: int, exclude: Collection[UUID]
    ) -> tuple[EvidenceRun, ...]: ...

    def record_purged(self, run: EvidenceRun) -> bool: ...

    def known(self, run_ids: Collection[UUID]) -> frozenset[UUID]: ...

    def hold(
        self,
        directory: UUID,
        run: EvidenceRun | None,
        code: EvidenceHoldCode,
        attempts: int,
        source_ino: int,
    ) -> None: ...

    def held(self, directories: Collection[UUID]) -> frozenset[UUID]: ...

    def exclusive(self) -> AbstractContextManager[bool]: ...


class Vault(Protocol):
    def check(self) -> None: ...

    def entries(self) -> tuple[str, ...]: ...

    def inspect(self, name: str) -> DirectoryState | None: ...

    def inode(self, name: str) -> int: ...

    def sealed_at(self, name: str) -> int | None: ...

    def seal(self, name: str) -> SealedEvidence | None: ...

    def purge(self, name: str) -> None: ...


class Isolation(Protocol):
    def reconcile(self, deadline: float) -> object: ...
