"""原始證據的 keeper（EVID-06；docs/DECISIONS.md §30.3）：每一輪的步驟、上限、失敗與健康狀態。

store 與 vault 都是記憶體中的替身；實際的 DB 與檔案見 tests/integration/test_evidence_keeper.py。
"""

import itertools
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
from secscan.runner.keeper import (
    MAX_BACKOFF_SECONDS,
    EvidenceKeeper,
    KeeperSettings,
    PassReport,
)
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

    def sealable(self, *, limit: int, exclude: Collection[UUID]) -> tuple[EvidenceRun, ...]:
        self._maybe_fail("sealable")
        return tuple(run for run in self.sealable_runs if run.run_id not in exclude)[:limit]

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
    unexpected: BaseException | None = None
    volume_error: EvidenceError | None = None

    def check(self) -> None:
        if self.volume_error is not None:
            raise self.volume_error

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
        if self.unexpected is not None:
            raise self.unexpected
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
    clock = Clock()
    broken = _run()
    store = FakeStore(sealable_runs=[broken])
    vault = FakeVault(failing={str(broken.run_id)})
    keeper = _keeper(store, vault, clock=clock)
    keeper.run_pass()
    assert keeper.healthy is False

    vault.failing.clear()
    clock.now += 2 * SETTINGS.interval_seconds
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
    # 正常停止不是失敗：保留最後一輪的結果（審查 MEDIUM-1：否則每次 make down 都 exit 1）。
    assert keeper.healthy is True


def test_a_stalled_keeper_is_not_healthy() -> None:
    clock = Clock()
    keeper = _keeper(FakeStore(), FakeVault(), clock=clock)
    keeper.run_pass()
    assert keeper.healthy is True

    clock.now += 3 * (SETTINGS.interval_seconds + SETTINGS.max_pass_seconds) + 1

    assert keeper.healthy is False


def test_stop_without_start_is_harmless() -> None:
    _keeper(FakeStore(), FakeVault()).stop(timeout=0.1)


# --- 審查之後（docs/DECISIONS.md §30.11）--------------------------------------------------------


def test_an_unexpected_error_is_a_failure_not_a_dead_thread(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """任何例外都不能讓 keeper 的執行緒結束（審查 HIGH-1）：記下類別、這一輪不健康。"""
    vault = FakeVault(unexpected=RuntimeError("secret-looking detail"))
    keeper = _keeper(FakeStore(sealable_runs=[_run()]), vault)
    caplog.set_level(logging.ERROR)

    report = keeper.run_pass()

    assert report.failures == 1
    assert keeper.healthy is False
    assert "RuntimeError" in caplog.text
    assert "secret-looking detail" not in caplog.text


def test_a_broken_runs_volume_records_nothing() -> None:
    """runs volume 不存在或不能寫時，不能把任何 run 記成 none 或 purged（審查 HIGH-2）。"""
    store = FakeStore(sealable_runs=[_run()], purgeable_runs=[_run()])
    vault = FakeVault(volume_error=EvidenceError("無法開啟 runs volume（ENOENT）"))
    keeper = _keeper(store, vault)

    report = keeper.run_pass()

    assert report.failures == 1
    assert keeper.healthy is False
    assert (store.recorded, store.purged, vault.sealed, vault.purged) == ({}, [], [], [])


def test_a_failed_last_pass_stays_unhealthy_after_stopping() -> None:
    settings = KeeperSettings(retention_days=7, plaintext_max_minutes=60, interval_seconds=0.01)
    broken = _run()
    keeper = EvidenceKeeper(
        FakeStore(sealable_runs=[broken]),
        FakeVault(failing={str(broken.run_id)}),
        settings,
        clock=lambda: NOW,
    )
    keeper.start()
    keeper.stop(timeout=5)

    assert keeper.healthy is False


def test_a_thread_that_ended_without_being_stopped_is_not_healthy() -> None:
    keeper = _keeper(FakeStore(), FakeVault())
    keeper.run_pass()
    ended = threading.Thread(target=lambda: None)
    ended.start()
    ended.join()
    keeper._thread = ended

    assert keeper.healthy is False


def test_failing_runs_back_off_without_starving_the_others() -> None:
    """一直失敗的 run 排在最前面時，其他 run 仍然會被加密（安全審查 M1）；它還在退避時
    keeper 仍然不健康（不認領新的 run）。"""
    clock = Clock()
    first, second, fine = _run(), _run(), _run()
    store = FakeStore(sealable_runs=[first, second, fine])
    vault = FakeVault(failing={str(first.run_id), str(second.run_id)})
    settings = KeeperSettings(retention_days=7, plaintext_max_minutes=60, batch=2)
    keeper = _keeper(store, vault, clock=clock, settings=settings)

    assert keeper.run_pass().failures == 2
    clock.now += settings.interval_seconds
    report = keeper.run_pass()

    assert vault.sealed == [str(fine.run_id)]
    assert (report.failures, report.deferred) == (0, 2)
    assert not report.clean
    assert keeper.healthy is False

    vault.failing.clear()
    clock.now += 2 * settings.interval_seconds
    keeper.run_pass()

    assert set(store.recorded) == {first.run_id, second.run_id, fine.run_id}
    assert keeper.healthy is True


def test_a_failing_purge_backs_off_too() -> None:
    clock = Clock()
    broken = _run()
    store = FakeStore(purgeable_runs=[broken])
    vault = FakeVault(failing={str(broken.run_id)})
    keeper = _keeper(store, vault, clock=clock)

    keeper.run_pass()
    clock.now += SETTINGS.interval_seconds
    report = keeper.run_pass()

    assert (report.failures, report.deferred) == (0, 1)
    vault.failing.clear()
    clock.now += 4 * SETTINGS.interval_seconds
    keeper.run_pass()

    assert store.purged == [broken.run_id]
    assert keeper.healthy is True


def test_an_orphan_removed_by_the_operator_is_forgotten() -> None:
    clock = Clock()
    name = str(uuid4())
    vault = FakeVault(states={name: _state(plaintext=True, age=QUIET + 1)}, failing={name})
    keeper = _keeper(FakeStore(), vault, clock=clock)
    keeper.run_pass()
    clock.now += SETTINGS.interval_seconds
    assert keeper.run_pass().deferred == 1

    del vault.states[name]
    keeper.run_pass()

    assert keeper.healthy is True


def test_backoff_grows_and_is_capped() -> None:
    clock = Clock()
    broken = _run()
    store = FakeStore(sealable_runs=[broken])
    vault = FakeVault(failing={str(broken.run_id)})
    keeper = _keeper(store, vault, clock=clock)
    attempts: list[float] = []
    original = vault.seal

    def seal(name: str) -> SealedEvidence | None:
        attempts.append(clock.now)
        return original(name)

    vault.seal = seal  # type: ignore[method-assign]
    for _ in range(400):
        keeper.run_pass()
        clock.now += SETTINGS.interval_seconds

    gaps = [later - earlier for earlier, later in itertools.pairwise(attempts)]
    assert gaps[:3] == [20.0, 40.0, 80.0]
    assert max(gaps) == MAX_BACKOFF_SECONDS
