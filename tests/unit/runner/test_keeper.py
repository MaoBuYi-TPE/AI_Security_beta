"""原始證據的 keeper（EVID-06；docs/DECISIONS.md §30.3）：每一輪的步驟、上限、失敗與健康狀態。

store 與 vault 都是記憶體中的替身；實際的 DB 與檔案見 tests/integration/test_evidence_keeper.py。
"""

import logging
import threading
from collections.abc import Collection, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import OperationalError

from secscan.runner.evidence import DirectoryState, EvidenceError
from secscan.runner.keeper import EvidenceKeeper, KeeperSettings, PassReport
from secscan.scans.domain.evidence import SealedEvidence
from secscan.scans.evidence_records import EvidenceRun

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
SETTINGS = KeeperSettings(retention_days=7, plaintext_max_minutes=60, batch=5)


def _run() -> EvidenceRun:
    return EvidenceRun(uuid4(), uuid4())


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

    def sealable(self, *, limit: int) -> tuple[EvidenceRun, ...]:
        self._maybe_fail("sealable")
        return tuple(self.sealable_runs[:limit])

    def record(self, run: EvidenceRun, sealed: SealedEvidence | None) -> bool:
        self._maybe_fail("record")
        self.recorded[run.run_id] = sealed
        return True

    def purgeable(
        self, *, now: datetime, retention_days: int, limit: int
    ) -> tuple[EvidenceRun, ...]:
        self._maybe_fail("purgeable")
        assert retention_days == 7
        return tuple(self.purgeable_runs[:limit])

    def record_purged(self, run: EvidenceRun) -> bool:
        self._maybe_fail("record_purged")
        self.purged.append(run.run_id)
        return True

    def known(self, run_ids: Collection[UUID]) -> frozenset[UUID]:
        self._maybe_fail("known")
        return frozenset(set(run_ids) & self.known_ids)

    @contextmanager
    def exclusive(self) -> Iterator[bool]:
        self.calls.append("lock")
        yield self.lock_free


@dataclass
class FakeVault:
    states: dict[str, DirectoryState | None] = field(default_factory=dict)
    sealed_times: dict[str, int | None] = field(default_factory=dict)
    failing: set[str] = field(default_factory=set)
    missing: set[str] = field(default_factory=set)
    sealed: list[str] = field(default_factory=list)
    purged: list[str] = field(default_factory=list)
    on_seal: list[object] = field(default_factory=list)

    def entries(self) -> tuple[str, ...]:
        return tuple(sorted(self.states))

    def inspect(self, name: str) -> DirectoryState | None:
        return self.states.get(name)

    def sealed_at(self, name: str) -> int | None:
        return self.sealed_times.get(name)

    def seal(self, name: str) -> SealedEvidence | None:
        for hook in self.on_seal:
            assert callable(hook)
            hook()
        if name in self.failing:
            raise EvidenceError("加密檔驗證不通過")
        if name in self.missing:
            return None
        self.sealed.append(name)
        return SealedEvidence(files=2, plaintext_bytes=10)

    def purge(self, name: str) -> None:
        if name in self.failing:
            raise EvidenceError("無法刪除目錄")
        self.purged.append(name)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


def _keeper(
    store: FakeStore,
    vault: FakeVault,
    *,
    clock: Clock | None = None,
    settings: KeeperSettings = SETTINGS,
) -> EvidenceKeeper:
    ticking = clock or Clock()
    return EvidenceKeeper(store, vault, settings, clock=lambda: NOW, monotonic=ticking.monotonic)


def test_a_clean_pass_expires_seals_purges_and_becomes_healthy() -> None:
    late, sealable, missing, old = _run(), _run(), _run(), _run()
    store = FakeStore(overdue_runs=[late], sealable_runs=[sealable, missing], purgeable_runs=[old])
    vault = FakeVault(missing={str(missing.run_id)})
    keeper = _keeper(store, vault)
    assert keeper.healthy is False

    report = keeper.run_pass()

    assert (report.expired, report.sealed, report.none, report.purged) == (1, 1, 1, 1)
    assert report.clean
    assert keeper.healthy is True
    assert store.expired == [late.run_id]
    assert store.recorded == {
        sealable.run_id: SealedEvidence(files=2, plaintext_bytes=10),
        missing.run_id: None,
    }
    assert vault.purged == [str(old.run_id)]
    assert store.purged == [old.run_id]


def test_a_failed_run_is_kept_and_the_pass_is_unhealthy(caplog: pytest.LogCaptureFixture) -> None:
    broken, fine = _run(), _run()
    store = FakeStore(sealable_runs=[broken, fine])
    vault = FakeVault(failing={str(broken.run_id)})
    keeper = _keeper(store, vault)
    caplog.set_level(logging.ERROR)

    report = keeper.run_pass()

    assert report.failures == 1
    assert keeper.healthy is False
    assert broken.run_id not in store.recorded
    assert fine.run_id in store.recorded
    assert str(broken.run_id) in caplog.text
    assert "加密檔驗證不通過" in caplog.text


def test_one_clean_pass_restores_health() -> None:
    broken = _run()
    store = FakeStore(sealable_runs=[broken])
    vault = FakeVault(failing={str(broken.run_id)})
    keeper = _keeper(store, vault)
    keeper.run_pass()
    assert keeper.healthy is False

    vault.failing.clear()
    keeper.run_pass()

    assert keeper.healthy is True


@pytest.mark.parametrize("step", ["overdue", "sealable", "purgeable", "known"])
def test_a_database_error_aborts_the_pass_without_crashing(
    step: str, caplog: pytest.LogCaptureFixture
) -> None:
    store = FakeStore(broken=step, sealable_runs=[_run()])
    vault = FakeVault(states={str(uuid4()): DirectoryState(True, NOW.timestamp(), 0)})
    keeper = _keeper(store, vault)
    caplog.set_level(logging.ERROR)

    report = keeper.run_pass()

    assert report.failures == 1
    assert keeper.healthy is False
    assert "OperationalError" in caplog.text
    assert "db down" not in caplog.text


@pytest.mark.parametrize("step", ["expire", "record", "record_purged"])
def test_a_database_error_for_one_run_counts_as_a_failure(step: str) -> None:
    store = FakeStore(
        broken=step,
        overdue_runs=[_run()],
        sealable_runs=[_run()],
        purgeable_runs=[_run()],
    )
    keeper = _keeper(store, FakeVault())

    report = keeper.run_pass()

    assert report.failures == 1
    assert keeper.healthy is False


def test_a_busy_lock_skips_the_file_work_and_is_not_healthy() -> None:
    store = FakeStore(sealable_runs=[_run()], lock_free=False)
    vault = FakeVault()
    keeper = _keeper(store, vault)

    report = keeper.run_pass()

    assert report.skipped
    assert vault.sealed == []
    assert keeper.healthy is False


def test_each_pass_stops_at_its_time_limit() -> None:
    clock = Clock()
    runs = [_run() for _ in range(5)]
    store = FakeStore(sealable_runs=runs)

    def tick() -> None:
        clock.now += 20

    vault = FakeVault(on_seal=[tick])
    keeper = _keeper(store, vault, clock=clock)

    keeper.run_pass()

    assert len(vault.sealed) == 2
    assert keeper.healthy is True


def test_each_pass_handles_at_most_a_batch() -> None:
    store = FakeStore(sealable_runs=[_run() for _ in range(9)])
    vault = FakeVault()

    _keeper(store, vault).run_pass()

    assert len(vault.sealed) == SETTINGS.batch


# --- 孤兒目錄 -------------------------------------------------------------------------------------

QUIET = SETTINGS.orphan_quiet_seconds
RETENTION = timedelta(days=SETTINGS.retention_days).total_seconds()


def _state(*, plaintext: bool, age: float, sealed: int = 0) -> DirectoryState:
    return DirectoryState(plaintext, NOW.timestamp() - age, sealed)


@pytest.mark.parametrize(
    ("state", "sealed_age", "action"),
    [
        (_state(plaintext=True, age=QUIET - 1), None, None),
        (_state(plaintext=True, age=QUIET + 1), None, "seal"),
        (_state(plaintext=False, age=QUIET + 1, sealed=2), RETENTION - 1, None),
        (_state(plaintext=False, age=QUIET + 1, sealed=2), RETENTION + 1, "purge"),
        (_state(plaintext=False, age=QUIET - 1), None, None),
        (_state(plaintext=False, age=QUIET + 1), None, "purge"),
        (None, None, None),
    ],
)
def test_orphans_are_sealed_after_an_hour_and_purged_after_retention(
    state: DirectoryState | None, sealed_age: float | None, action: str | None
) -> None:
    name = str(uuid4())
    sealed_at = None if sealed_age is None else int(NOW.timestamp() - sealed_age)
    vault = FakeVault(states={name: state}, sealed_times={name: sealed_at})
    keeper = _keeper(FakeStore(), vault)

    report = keeper.run_pass()

    assert report.clean
    assert vault.sealed == ([name] if action == "seal" else [])
    assert vault.purged == ([name] if action == "purge" else [])


def test_directories_of_known_runs_are_not_orphans() -> None:
    run = _run()
    name = str(run.run_id)
    vault = FakeVault(states={name: _state(plaintext=True, age=QUIET * 10)})

    _keeper(FakeStore(known_ids={run.run_id}), vault).run_pass()

    assert vault.sealed == []


def test_a_failing_orphan_is_a_failure() -> None:
    name = str(uuid4())
    vault = FakeVault(states={name: _state(plaintext=True, age=QUIET + 1)}, failing={name})
    keeper = _keeper(FakeStore(), vault)

    assert keeper.run_pass().failures == 1
    assert keeper.healthy is False


# --- 執行緒與停擺 ---------------------------------------------------------------------------------


def test_the_thread_runs_passes_until_stopped() -> None:
    store = FakeStore()
    passes = threading.Event()
    vault = FakeVault()
    settings = KeeperSettings(retention_days=7, plaintext_max_minutes=60, interval_seconds=0.01)
    keeper = EvidenceKeeper(store, vault, settings, clock=lambda: NOW)
    original = keeper.run_pass

    def counted() -> PassReport:
        report = original()
        passes.set()
        return report

    keeper.run_pass = counted  # type: ignore[method-assign]
    keeper.start()
    try:
        assert passes.wait(5)
        assert keeper.healthy is True
        with pytest.raises(RuntimeError, match="已經啟動"):
            keeper.start()
    finally:
        keeper.stop(timeout=5)
    assert keeper.healthy is False


def test_a_stalled_keeper_is_not_healthy() -> None:
    clock = Clock()
    keeper = _keeper(FakeStore(), FakeVault(), clock=clock)
    keeper.run_pass()
    assert keeper.healthy is True

    clock.now += 3 * (SETTINGS.interval_seconds + SETTINGS.max_pass_seconds) + 1

    assert keeper.healthy is False


def test_stop_without_start_is_harmless() -> None:
    _keeper(FakeStore(), FakeVault()).stop(timeout=0.1)
