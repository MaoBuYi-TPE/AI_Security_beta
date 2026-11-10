"""需要人工處理的原始證據（EVID-08；docs/DECISIONS.md §30.12）：隔離紀錄的規則與 API 顯示的狀態。

不連 DB：evidence_state 只讀 model 的欄位，以未存檔的 model 測試優先順序。
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from secscan.scans.domain.evidence import (
    HOLD_AFTER_FAILURES,
    EvidenceHold,
    EvidenceHoldCode,
    EvidenceState,
    EvidenceStatus,
)
from secscan.scans.evidence_models import EvidenceHoldModel, RunEvidenceModel, evidence_state

HELD_AT = datetime(2026, 11, 10, 3, 0, tzinfo=UTC)


def _hold(*, resolved: bool = False) -> EvidenceHold:
    return EvidenceHold(
        code=EvidenceHoldCode.TREE_TOO_DEEP,
        attempts=HOLD_AFTER_FAILURES,
        held_at=HELD_AT,
        resolved_at=HELD_AT + timedelta(hours=1) if resolved else None,
    )


def test_the_threshold_is_three_consecutive_failures() -> None:
    assert HOLD_AFTER_FAILURES == 3


def test_codes_fit_the_column() -> None:
    assert {code.value for code in EvidenceHoldCode} == {
        "EVIDENCE_TREE_TOO_DEEP",
        "EVIDENCE_TREE_TOO_MANY_ENTRIES",
    }
    assert all(len(code.value) <= 32 for code in EvidenceHoldCode)


def test_a_hold_is_active_until_resolved() -> None:
    assert _hold().active
    assert not _hold(resolved=True).active


@pytest.mark.parametrize(
    "changes",
    [{"attempts": 0}, {"resolved_at": HELD_AT - timedelta(seconds=1)}],
)
def test_an_inconsistent_hold_is_rejected(changes: dict[str, object]) -> None:
    values: dict[str, object] = {
        "code": EvidenceHoldCode.TREE_TOO_MANY_ENTRIES,
        "attempts": 3,
        "held_at": HELD_AT,
    }
    with pytest.raises(ValueError, match="隔離紀錄"):
        EvidenceHold(**(values | changes))  # type: ignore[arg-type]


def test_manual_intervention_needs_an_active_hold() -> None:
    state = EvidenceState(EvidenceStatus.MANUAL_INTERVENTION_REQUIRED, hold=_hold())

    assert state.encrypted is False
    with pytest.raises(ValueError, match="需要人工處理"):
        EvidenceState(EvidenceStatus.MANUAL_INTERVENTION_REQUIRED)
    with pytest.raises(ValueError, match="需要人工處理"):
        EvidenceState(EvidenceStatus.MANUAL_INTERVENTION_REQUIRED, hold=_hold(resolved=True))


def _evidence_model(status: EvidenceStatus) -> RunEvidenceModel:
    run_id = uuid4()
    return RunEvidenceModel(
        scanner_run_id=run_id,
        scan_id=uuid4(),
        status=status.value,
        file_count=1,
        plaintext_bytes=1,
        sealed_at=HELD_AT + timedelta(hours=1),
        purged_at=None,
    )


def _hold_model(*, resolved: bool) -> EvidenceHoldModel:
    directory = uuid4()
    return EvidenceHoldModel(
        directory=directory,
        scanner_run_id=directory,
        scan_id=uuid4(),
        error_code=EvidenceHoldCode.TREE_TOO_DEEP.value,
        attempts=3,
        held_at=HELD_AT,
        resolved_at=HELD_AT + timedelta(hours=1) if resolved else None,
    )


def test_without_records_the_evidence_is_pending() -> None:
    state = evidence_state(None, None)

    assert (state.status, state.hold) == (EvidenceStatus.PENDING, None)


def test_an_active_hold_needs_manual_intervention_and_is_not_encrypted() -> None:
    state = evidence_state(None, _hold_model(resolved=False))

    assert state.status is EvidenceStatus.MANUAL_INTERVENTION_REQUIRED
    assert state.hold == _hold()
    assert state.encrypted is False
    assert state.sealed_at is None


def test_a_recorded_status_wins_and_the_resolved_hold_stays_visible() -> None:
    state = evidence_state(_evidence_model(EvidenceStatus.SEALED), _hold_model(resolved=True))

    assert state.status is EvidenceStatus.SEALED
    assert state.encrypted is True
    assert state.hold == _hold(resolved=True)
