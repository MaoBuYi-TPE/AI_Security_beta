"""隔離目錄的對帳（EVID-11；docs/DECISIONS.md §30.13 的對帳表與中斷點）。

真的檔案系統（runs volume 的 layout）與記憶體中的 DB 替身；每個情境之後檢查不變條件：
- I1：已隔離 ⇒ 不在 active/；
- I2：解除中 ⇒ 在 active/ 時只有加密檔；
- I3：只有隔離中允許明文留在 active/。
DB 的轉換與 trigger 見 tests/integration/test_evidence_hold_isolation.py。
"""

import logging
import math
from collections.abc import Collection
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import OperationalError

from secscan.runner import isolation as isolation_module
from secscan.runner.evidence import EvidenceVault
from secscan.runner.hold_moves import HoldMoves
from secscan.runner.isolation import UNKNOWN_HELD, HoldIsolation
from secscan.runner.sealed_files import EvidenceError
from secscan.scans.domain.evidence import (
    ISOLATION_URGENT_AFTER,
    EvidenceHold,
    EvidenceHoldCode,
    HoldMoveCode,
    HoldStage,
)
from secscan.scans.evidence_holds import HeldDirectory, MoveFailures
from tests.runs_volume_support import runs_volume
from tests.secret_support import shared_evidence_cipher

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
CANARY = b"canary-isolation-7d2e"
SEALED_ITEM = "a" * 64


@dataclass
class FakeStore:
    holds: dict[UUID, HeldDirectory] = field(default_factory=dict)
    settled_runs: bool = True
    broken: str | None = None
    failures: list[tuple[UUID, HoldMoveCode]] = field(default_factory=list)
    notes: list[tuple[UUID, str]] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)

    def _maybe_fail(self, name: str) -> None:
        self.calls.append(name)
        if self.broken == name:
            raise OperationalError("UPDATE", {}, Exception("db down"))

    def unresolved_page(
        self, *, isolating: bool, after: HeldDirectory | None, limit: int
    ) -> tuple[HeldDirectory, ...]:
        self.calls.append(f"page:{isolating}")
        ordered = sorted(
            (held for held in self.holds.values() if (held.hold.isolated_at is None) == isolating),
            key=lambda held: (held.hold.held_at, held.directory),
        )
        if after is not None:
            key = (after.hold.held_at, after.directory)
            ordered = [held for held in ordered if (held.hold.held_at, held.directory) > key]
        return tuple(ordered[:limit])

    def overdue(
        self, *, now: datetime, urgent_after: timedelta, limit: int
    ) -> tuple[HeldDirectory, ...]:
        return tuple(
            held
            for held in self.holds.values()
            if held.hold.isolated_at is None and held.hold.held_at <= now - urgent_after
        )[:limit]

    def unresolved_among(self, directories: Collection[UUID]) -> frozenset[UUID]:
        return frozenset(set(directories) & set(self.holds))

    def settled(self, held: HeldDirectory) -> bool:
        return self.settled_runs

    def record_move_failure(self, directory: UUID, code: HoldMoveCode) -> bool:
        self._maybe_fail("record_move_failure")
        self.failures.append((directory, code))
        held = self.holds[directory]
        moves = MoveFailures(held.moves.count + 1, code, NOW)
        self.holds[directory] = replace(held, moves=moves)
        return True

    def mark_isolated(self, held: HeldDirectory) -> bool:
        self._maybe_fail("mark_isolated")
        current = self.holds[held.directory]
        self.holds[held.directory] = replace(current, hold=replace(current.hold, isolated_at=NOW))
        return True

    def note(self, held: HeldDirectory, action: str, changes: object) -> None:
        self._maybe_fail("note")
        self.notes.append((held.directory, action))


class Ticker:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    return runs_volume(tmp_path)


@pytest.fixture
def store() -> FakeStore:
    return FakeStore()


@pytest.fixture
def ticker() -> Ticker:
    return Ticker()


@pytest.fixture
def isolation(runs: Path, store: FakeStore, ticker: Ticker) -> HoldIsolation:
    vault = EvidenceVault(runs.parent, shared_evidence_cipher())
    return HoldIsolation(
        store, HoldMoves(runs.parent), vault, clock=lambda: NOW, monotonic=ticker.monotonic
    )


def _plaintext(area: Path, name: str) -> int:
    (area / name / "out").mkdir(parents=True)
    (area / name / "out" / "messages.txt").write_bytes(CANARY)
    return (area / name).lstat().st_ino


def _only_sealed(area: Path, name: str) -> int:
    (area / name / "sealed").mkdir(parents=True)
    (area / name / "sealed" / SEALED_ITEM).write_bytes(b"ciphertext")
    return (area / name).lstat().st_ino


def _hold(
    store: FakeStore,
    name: str,
    stage: HoldStage,
    source_ino: int | None,
    *,
    held_at: datetime = NOW,
) -> HeldDirectory:
    isolated = held_at if stage in (HoldStage.ISOLATED, HoldStage.RELEASING) else None
    releasing = held_at if stage is HoldStage.RELEASING else None
    hold = EvidenceHold(EvidenceHoldCode.TREE_TOO_DEEP, 3, held_at, None, isolated, releasing)
    held = HeldDirectory(UUID(name), None, None, hold, source_ino=source_ino)
    store.holds[held.directory] = held
    return held


def _stage(store: FakeStore, name: str) -> HoldStage:
    return store.holds[UUID(name)].hold.stage


def _check_invariants(store: FakeStore, runs: Path) -> None:
    for held in store.holds.values():
        active = runs / held.name
        stage = held.hold.stage
        if stage is HoldStage.ISOLATED:
            assert not active.exists(), "I1"
        if stage is HoldStage.RELEASING and active.exists():
            entries = {entry.name for entry in active.iterdir()}
            assert entries <= {"sealed"}, "I2"


def _reconcile(isolation: HoldIsolation, store: FakeStore, runs: Path) -> None:
    isolation.reconcile(math.inf)
    _check_invariants(store, runs)


# --- 隔離中 ------------------------------------------------------------------------------------


def test_an_isolating_directory_is_moved_to_held(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    name = str(uuid4())
    _hold(store, name, HoldStage.ISOLATING, _plaintext(runs, name))

    report = isolation.reconcile(math.inf)

    assert report.isolated == 1
    assert _stage(store, name) is HoldStage.ISOLATED
    assert not (runs / name).exists()
    assert (runs.parent / "held" / name / "out" / "messages.txt").read_bytes() == CANARY
    _check_invariants(store, runs)


def test_an_active_parse_lease_postpones_the_move(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    name = str(uuid4())
    _hold(store, name, HoldStage.ISOLATING, _plaintext(runs, name))
    store.settled_runs = False

    report = isolation.reconcile(math.inf)

    assert (report.isolated, report.failures) == (0, 0)
    assert (runs / name).is_dir()
    assert store.failures == []


@pytest.mark.parametrize(
    ("in_active", "in_held", "code"),
    [(True, True, HoldMoveCode.CONFLICT), (False, False, HoldMoveCode.DIRECTORY_MISSING)],
)
def test_conflicts_and_missing_directories_are_recorded_and_backed_off(
    runs: Path,
    store: FakeStore,
    isolation: HoldIsolation,
    ticker: Ticker,
    in_active: bool,
    in_held: bool,
    code: HoldMoveCode,
) -> None:
    name = str(uuid4())
    source_ino = _plaintext(runs, name) if in_active else 1
    if in_held:
        _plaintext(runs.parent / "held", name)
    _hold(store, name, HoldStage.ISOLATING, source_ino)

    report = isolation.reconcile(math.inf)
    isolation.reconcile(math.inf)

    assert report.failures == 1
    assert store.failures == [(UUID(name), code)]
    assert _stage(store, name) is HoldStage.ISOLATING
    ticker.now += 21
    isolation.reconcile(math.inf)
    assert len(store.failures) == 2


def test_a_wrong_directory_in_active_is_not_moved(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    name = str(uuid4())
    source_ino = _plaintext(runs, name)
    _hold(store, name, HoldStage.ISOLATING, source_ino + 1)

    isolation.reconcile(math.inf)

    assert store.failures == [(UUID(name), HoldMoveCode.CONFLICT)]
    assert (runs / name).is_dir()
    assert _stage(store, name) is HoldStage.ISOLATING


@pytest.mark.parametrize("kind", ["symlink", "other-inode"])
def test_a_same_named_entry_in_held_is_not_trusted(
    runs: Path, store: FakeStore, isolation: HoldIsolation, kind: str
) -> None:
    """第二次審查：對帳不能只因為 held/ 有同名的條目就補寫 isolated_at。"""
    name = str(uuid4())
    held = runs.parent / "held"
    if kind == "symlink":
        (runs.parent / "elsewhere").mkdir()
        (held / name).symlink_to(runs.parent / "elsewhere")
        source_ino = (runs.parent / "elsewhere").stat().st_ino
    else:
        source_ino = _plaintext(held, name) + 1
    _hold(store, name, HoldStage.ISOLATING, source_ino)

    isolation.reconcile(math.inf)

    assert _stage(store, name) is HoldStage.ISOLATING
    assert store.failures == [(UUID(name), HoldMoveCode.CONFLICT)]


def test_a_legacy_hold_without_an_inode_waits_for_the_migration(
    runs: Path, store: FakeStore, isolation: HoldIsolation, caplog: pytest.LogCaptureFixture
) -> None:
    name = str(uuid4())
    _plaintext(runs, name)
    _hold(store, name, HoldStage.ISOLATING, None)
    caplog.set_level(logging.ERROR)

    isolation.reconcile(math.inf)
    isolation.reconcile(math.inf)

    assert (runs / name).is_dir()
    assert store.failures == []
    assert caplog.text.count("make runs-layout-migrate") == 1


# --- 中斷點（§30.13：新增紀錄之後、rename 之後、fsync 之後）----------------------------------


def test_crash_after_the_hold_before_the_rename(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    """中斷點 1：紀錄已新增、目錄還在 active/（隔離中，I3 允許）→ 下一輪搬移。"""
    name = str(uuid4())
    _hold(store, name, HoldStage.ISOLATING, _plaintext(runs, name))
    _check_invariants(store, runs)

    _reconcile(isolation, store, runs)

    assert _stage(store, name) is HoldStage.ISOLATED


@pytest.mark.parametrize("point", ["after-rename", "after-fsync"])
def test_crash_after_the_rename_is_verified_synced_then_recorded(
    runs: Path,
    store: FakeStore,
    isolation: HoldIsolation,
    monkeypatch: pytest.MonkeyPatch,
    point: str,
) -> None:
    """中斷點 2、3：已搬到 held/、還沒寫 DB → 先確認身分、fsync 兩個區域，最後才補寫。"""
    name = str(uuid4())
    source_ino = _plaintext(runs, name)
    _hold(store, name, HoldStage.ISOLATING, source_ino)
    (runs / name).rename(runs.parent / "held" / name)
    order: list[str] = []
    for method in ("identify", "settle"):
        real = getattr(HoldMoves, method)

        def spy(self: HoldMoves, *args: object, _real: object = real, _name: str = method) -> None:
            order.append(_name)
            _real(self, *args)  # type: ignore[operator]

        monkeypatch.setattr(HoldMoves, method, spy)
    real_mark = store.mark_isolated

    def mark(held: HeldDirectory) -> bool:
        order.append("mark_isolated")
        return real_mark(held)

    monkeypatch.setattr(store, "mark_isolated", mark)

    _reconcile(isolation, store, runs)

    assert order == ["identify", "settle", "mark_isolated"]
    assert _stage(store, name) is HoldStage.ISOLATED


def test_a_database_failure_after_the_move_is_finished_next_pass(
    runs: Path, store: FakeStore, isolation: HoldIsolation, ticker: Ticker
) -> None:
    name = str(uuid4())
    _hold(store, name, HoldStage.ISOLATING, _plaintext(runs, name))
    store.broken = "mark_isolated"

    report = isolation.reconcile(math.inf)

    assert report.failures == 1
    assert (runs.parent / "held" / name).is_dir()
    store.broken = None
    ticker.now += 21
    _reconcile(isolation, store, runs)
    assert _stage(store, name) is HoldStage.ISOLATED


# --- 已隔離與解除中 ------------------------------------------------------------------------------


def test_an_isolated_directory_in_active_is_moved_back(
    runs: Path, store: FakeStore, isolation: HoldIsolation, caplog: pytest.LogCaptureFixture
) -> None:
    """違反 I1（不應發生）：搬回 held/、ERROR 與 audit。"""
    name = str(uuid4())
    _hold(store, name, HoldStage.ISOLATED, _plaintext(runs, name))
    caplog.set_level(logging.ERROR)

    report = isolation.reconcile(math.inf)

    assert report.reisolated == 1
    assert store.notes == [(UUID(name), "evidence.reisolated")]
    assert "違反 I1" in caplog.text
    _check_invariants(store, runs)


def test_a_normal_isolated_directory_is_left_alone(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    name = str(uuid4())
    _hold(store, name, HoldStage.ISOLATED, _plaintext(runs.parent / "held", name))

    report = isolation.reconcile(math.inf)

    assert (report.isolated, report.reisolated, report.failures) == (0, 0, 0)
    assert store.notes == []


@pytest.mark.parametrize("where", ["held", "active"])
def test_a_pending_release_is_left_for_retry_evidence(
    runs: Path,
    store: FakeStore,
    isolation: HoldIsolation,
    caplog: pytest.LogCaptureFixture,
    where: str,
) -> None:
    """解除中：只在 held/，或在 active/ 而只有加密檔 → 解除待完成，不動、不倒退。"""
    name = str(uuid4())
    area = runs.parent / "held" if where == "held" else runs
    _hold(store, name, HoldStage.RELEASING, _only_sealed(area, name))
    caplog.set_level(logging.WARNING)

    report = isolation.reconcile(math.inf)
    isolation.reconcile(math.inf)

    assert (report.reisolated, report.failures) == (0, 0)
    assert (area / name).is_dir()
    assert caplog.text.count("解除待完成") == 1
    _check_invariants(store, runs)


def test_plaintext_of_a_releasing_directory_in_active_is_moved_back(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    """違反 I2：解除中的目錄在 active/ 含明文 → 搬回 held/，狀態維持解除中。"""
    name = str(uuid4())
    source_ino = _only_sealed(runs, name)
    (runs / name / "leftover.txt").write_bytes(CANARY)
    _hold(store, name, HoldStage.RELEASING, source_ino)

    report = isolation.reconcile(math.inf)

    assert report.reisolated == 1
    assert (runs.parent / "held" / name / "leftover.txt").read_bytes() == CANARY
    assert _stage(store, name) is HoldStage.RELEASING
    _check_invariants(store, runs)


@pytest.mark.parametrize("stage", [HoldStage.ISOLATED, HoldStage.RELEASING])
@pytest.mark.parametrize("both", [True, False])
def test_conflicts_after_isolation_are_errors_without_state_changes(
    runs: Path, store: FakeStore, isolation: HoldIsolation, stage: HoldStage, both: bool
) -> None:
    name = str(uuid4())
    source_ino = _only_sealed(runs.parent / "held", name) if both else 1
    if both:
        _only_sealed(runs, name)
    _hold(store, name, stage, source_ino)

    report = isolation.reconcile(math.inf)

    assert report.failures == 1
    assert store.failures == []
    assert _stage(store, name) is stage


# --- 緊急門檻與其他 ------------------------------------------------------------------------------


def test_an_overdue_isolation_is_escalated_once(
    runs: Path, store: FakeStore, isolation: HoldIsolation, caplog: pytest.LogCaptureFixture
) -> None:
    """15 分鐘後升級為緊急狀態：CRITICAL log 與 audit，每個程序對每個目錄一次（主動告警是 T35）。"""
    name = str(uuid4())
    source_ino = _plaintext(runs, name)
    _plaintext(runs.parent / "held", name)
    _hold(store, name, HoldStage.ISOLATING, source_ino, held_at=NOW - ISOLATION_URGENT_AFTER)
    caplog.set_level(logging.CRITICAL)

    first = isolation.reconcile(math.inf)
    second = isolation.reconcile(math.inf)

    assert (first.urgent, second.urgent) == (1, 1)
    assert store.notes == [(UUID(name), "evidence.isolation_overdue")]
    assert caplog.text.count("需要緊急處理") == 1


def test_a_recent_isolation_is_not_urgent(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    name = str(uuid4())
    _hold(
        store,
        name,
        HoldStage.ISOLATING,
        1,
        held_at=NOW - ISOLATION_URGENT_AFTER + timedelta(seconds=1),
    )

    assert isolation.reconcile(math.inf).urgent == 0
    assert store.notes == []


def test_a_failed_overdue_audit_is_retried(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    name = str(uuid4())
    _hold(store, name, HoldStage.ISOLATING, 1, held_at=NOW - timedelta(hours=1))
    store.broken = "note"
    isolation.reconcile(math.inf)
    store.broken = None

    isolation.reconcile(math.inf)

    assert store.notes == [(UUID(name), "evidence.isolation_overdue")]


def test_a_failed_failure_record_does_not_stop_the_pass(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    missing, fine = str(uuid4()), str(uuid4())
    _hold(store, missing, HoldStage.ISOLATING, 1)
    _hold(store, fine, HoldStage.ISOLATING, _plaintext(runs, fine))
    store.broken = "record_move_failure"

    report = isolation.reconcile(math.inf)

    assert (report.failures, report.isolated) == (1, 1)
    assert _stage(store, fine) is HoldStage.ISOLATED


def test_unknown_held_directories_are_reported_once(
    runs: Path, store: FakeStore, isolation: HoldIsolation, caplog: pytest.LogCaptureFixture
) -> None:
    name = str(uuid4())
    _plaintext(runs.parent / "held", name)
    (runs.parent / "held" / "stray.txt").write_bytes(b"x")
    caplog.set_level(logging.ERROR)

    isolation.reconcile(math.inf)
    isolation.reconcile(math.inf)

    assert caplog.text.count(UNKNOWN_HELD) == 1
    assert caplog.text.count("不是隔離目錄的條目") == 1
    assert (runs.parent / "held" / name).is_dir()


def test_a_broken_held_area_fails_the_whole_pass(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    (runs.parent / "held").rmdir()

    with pytest.raises(EvidenceError, match="held/"):
        isolation.reconcile(math.inf)


def test_the_deadline_stops_the_pass(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    name = str(uuid4())
    _hold(store, name, HoldStage.ISOLATING, _plaintext(runs, name))

    assert isolation.reconcile(-1.0).isolated == 0
    assert (runs / name).is_dir()


def test_many_isolated_holds_do_not_hide_an_isolating_one(
    runs: Path, store: FakeStore, isolation: HoldIsolation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """程式碼與安全審查 M1：已隔離的紀錄等待人工處理、數量超過一頁時，新的隔離中紀錄仍然先處理。
    以 2 筆一頁代替 500 筆。"""
    monkeypatch.setattr(isolation_module, "_BATCH", 2)
    for _ in range(5):
        old = str(uuid4())
        _hold(store, old, HoldStage.ISOLATED, _plaintext(runs.parent / "held", old))
    names = [str(uuid4()) for _ in range(3)]
    for name in names:
        _hold(store, name, HoldStage.ISOLATING, _plaintext(runs, name))

    report = isolation.reconcile(math.inf)

    assert report.isolated == 3
    assert all(_stage(store, name) is HoldStage.ISOLATED for name in names)
    assert store.calls.index("page:True") < store.calls.index("page:False")
    _check_invariants(store, runs)


def test_a_failed_reisolation_audit_is_written_next_pass(
    runs: Path, store: FakeStore, isolation: HoldIsolation
) -> None:
    """審查 L2：已搬回 held/、audit 寫不進去時，下一輪補寫（目錄已在 held/，不會再觸發）。"""
    name = str(uuid4())
    _hold(store, name, HoldStage.ISOLATED, _plaintext(runs, name))
    store.broken = "note"

    report = isolation.reconcile(math.inf)

    assert (report.reisolated, store.notes) == (1, [])
    assert (runs.parent / "held" / name).is_dir()
    store.broken = None
    isolation.reconcile(math.inf)
    assert store.notes == [(UUID(name), "evidence.reisolated")]
