"""keeper 的單元測試共用的替身：記憶體中的 store、vault 與 monotonic 時鐘。

實際的 DB 與檔案見 tests/integration/test_evidence_keeper.py、test_evidence_holds.py。
"""

from collections.abc import Collection, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy.exc import OperationalError

from secscan.runner.evidence import DirectoryState, EvidenceError, EvidenceLimitError
from secscan.runner.keeper import EvidenceKeeper, KeeperSettings
from secscan.scans.domain.evidence import EvidenceHoldCode, SealedEvidence
from secscan.scans.evidence_records import EvidenceRun

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
SETTINGS = KeeperSettings(retention_days=7, plaintext_max_minutes=60, batch=5)
LIMIT_MESSAGES = {
    EvidenceHoldCode.TREE_TOO_DEEP: "目錄的深度超過上限",
    EvidenceHoldCode.TREE_TOO_MANY_ENTRIES: "目錄的條目超過上限",
    EvidenceHoldCode.TREE_PATHS_TOO_LONG: "目錄的路徑總長度超過上限",
}


def evidence_run() -> EvidenceRun:
    return EvidenceRun(uuid4(), uuid4())


@dataclass(frozen=True)
class Held:
    run: EvidenceRun | None
    code: EvidenceHoldCode
    attempts: int


@dataclass
class FakeStore:
    overdue_runs: list[EvidenceRun] = field(default_factory=list)
    sealable_runs: list[EvidenceRun] = field(default_factory=list)
    purgeable_runs: list[EvidenceRun] = field(default_factory=list)
    known_ids: set[UUID] = field(default_factory=set)
    lock_free: bool = True
    broken: str | None = None
    expired: list[UUID] = field(default_factory=list)
    recorded: dict[UUID, SealedEvidence | None] = field(default_factory=dict)
    purged: list[UUID] = field(default_factory=list)
    holds: dict[UUID, Held] = field(default_factory=dict)
    # 隔離紀錄寫入（commit）之後，回應在送回之前遺失：keeper 收到錯誤。
    hold_reply_lost: bool = False
    calls: list[str] = field(default_factory=list)

    def _maybe_fail(self, name: str) -> None:
        self.calls.append(name)
        if self.broken == name:
            raise OperationalError("SELECT 1", {}, Exception("db down"))

    def overdue(self, *, now: datetime, max_minutes: int, limit: int) -> tuple[EvidenceRun, ...]:
        self._maybe_fail("overdue")
        assert (now, max_minutes) == (NOW, 60)
        return tuple(self.overdue_runs[:limit])

    def expire(self, run: EvidenceRun, *, now: datetime, max_minutes: int) -> bool:
        self._maybe_fail("expire")
        self.expired.append(run.run_id)
        return True

    def sealable(self, *, limit: int, exclude: Collection[UUID]) -> tuple[EvidenceRun, ...]:
        """和 SQL 相同：退避中的 run 由 keeper 排除，隔離的 run 由 DB 排除。"""
        self._maybe_fail("sealable")
        return tuple(
            run
            for run in self.sealable_runs
            if run.run_id not in exclude and run.run_id not in self.holds
        )[:limit]

    def record(self, run: EvidenceRun, sealed: SealedEvidence | None) -> bool:
        self._maybe_fail("record")
        self.recorded[run.run_id] = sealed
        self.sealable_runs = [item for item in self.sealable_runs if item != run]
        return True

    def purgeable(
        self, *, now: datetime, retention_days: int, limit: int, exclude: Collection[UUID]
    ) -> tuple[EvidenceRun, ...]:
        self._maybe_fail("purgeable")
        assert retention_days == 7
        return tuple(run for run in self.purgeable_runs if run.run_id not in exclude)[:limit]

    def record_purged(self, run: EvidenceRun) -> bool:
        self._maybe_fail("record_purged")
        self.purged.append(run.run_id)
        self.purgeable_runs = [item for item in self.purgeable_runs if item != run]
        return True

    def known(self, run_ids: Collection[UUID]) -> frozenset[UUID]:
        self._maybe_fail("known")
        return frozenset(set(run_ids) & self.known_ids)

    def hold(
        self, directory: UUID, run: EvidenceRun | None, code: EvidenceHoldCode, attempts: int
    ) -> None:
        self._maybe_fail("hold")
        assert run is None or run.run_id == directory
        assert directory not in self.holds
        self.holds[directory] = Held(run, code, attempts)
        if self.hold_reply_lost:
            raise OperationalError("COMMIT", {}, Exception("connection lost"))

    def held(self, directories: Collection[UUID]) -> frozenset[UUID]:
        self._maybe_fail("held")
        return frozenset(set(directories) & set(self.holds))

    @contextmanager
    def exclusive(self) -> Iterator[bool]:
        self.calls.append("lock")
        yield self.lock_free


@dataclass
class FakeVault:
    states: dict[str, DirectoryState | None] = field(default_factory=dict)
    sealed_times: dict[str, int | None] = field(default_factory=dict)
    failing: set[str] = field(default_factory=set)
    over_limit: dict[str, EvidenceHoldCode] = field(default_factory=dict)
    missing: set[str] = field(default_factory=set)
    sealed: list[str] = field(default_factory=list)
    purged: list[str] = field(default_factory=list)
    inspected: list[str] = field(default_factory=list)
    on_seal: list[object] = field(default_factory=list)
    unexpected: BaseException | None = None
    volume_error: EvidenceError | None = None

    def _maybe_over_limit(self, name: str) -> None:
        code = self.over_limit.get(name)
        if code is not None:
            raise EvidenceLimitError(code, LIMIT_MESSAGES[code])

    def check(self) -> None:
        if self.volume_error is not None:
            raise self.volume_error

    def entries(self) -> tuple[str, ...]:
        return tuple(sorted(self.states))

    def inspect(self, name: str) -> DirectoryState | None:
        self.inspected.append(name)
        self._maybe_over_limit(name)
        return self.states.get(name)

    def sealed_at(self, name: str) -> int | None:
        return self.sealed_times.get(name)

    def seal(self, name: str) -> SealedEvidence | None:
        for hook in self.on_seal:
            assert callable(hook)
            hook()
        if self.unexpected is not None:
            raise self.unexpected
        if name in self.failing:
            raise EvidenceError("加密檔驗證不通過")
        self._maybe_over_limit(name)
        if name in self.missing:
            return None
        self.sealed.append(name)
        return SealedEvidence(files=2, plaintext_bytes=10)

    def purge(self, name: str) -> None:
        if name in self.failing:
            raise EvidenceError("無法刪除目錄")
        self._maybe_over_limit(name)
        self.purged.append(name)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


def make_keeper(
    store: FakeStore,
    vault: FakeVault,
    *,
    clock: Clock | None = None,
    settings: KeeperSettings = SETTINGS,
) -> EvidenceKeeper:
    ticking = clock or Clock()
    return EvidenceKeeper(store, vault, settings, clock=lambda: NOW, monotonic=ticking.monotonic)
