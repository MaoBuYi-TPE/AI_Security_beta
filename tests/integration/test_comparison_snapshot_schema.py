"""T22 比較快照：同一 target、先後與封存後不可再追加。"""

from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.integration.sql_support import (
    CHECK_VIOLATION,
    FOREIGN_KEY_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    UNIQUE_VIOLATION,
    violation,
)
from tests.integration.test_scan_schema import LATER, Snapshot, _insert_scan

pytest_plugins = ("tests.integration.test_scan_schema",)
pytestmark = pytest.mark.integration

INSERT = (
    "INSERT INTO scan_comparisons (project_id, target_id, baseline_scan_id, current_scan_id, "
    "algorithm_version, comparability, reasons, manual_review_required) "
    "VALUES (:project, :target, :baseline, :current, :version, :comparability, "
    "CAST(:reasons AS jsonb), false) RETURNING id"
)


def _pair(session: Session, snap: Snapshot) -> dict[str, object]:
    baseline = _insert_scan(session, snap, status="failed", finished_at=LATER)
    current = _insert_scan(session, snap, status="failed", finished_at=LATER)
    return {
        "project": snap.project_a,
        "target": snap.target,
        "baseline": baseline,
        "current": current,
        "version": 1,
        "comparability": "different",
        "reasons": "[]",
    }


def _snapshot(session: Session, values: dict[str, object]) -> UUID:
    result = session.execute(text(INSERT), values).scalar_one()
    assert isinstance(result, UUID)
    return result


def test_snapshot_is_unique_and_cannot_be_changed_after_sealing(
    db_session: Session, snap: Snapshot
) -> None:
    values = _pair(db_session, snap)
    comparison = _snapshot(db_session, values)
    db_session.execute(
        text("UPDATE scan_comparisons SET sealed = true WHERE id = :id"), {"id": comparison}
    )
    assert violation(db_session, INSERT, values).sqlstate == UNIQUE_VIOLATION
    for statement in (
        "UPDATE scan_comparisons SET comparability = 'comparable' WHERE id = :id",
        "UPDATE scan_comparisons SET sealed = false WHERE id = :id",
        "DELETE FROM scan_comparisons WHERE id = :id",
    ):
        assert violation(db_session, statement, {"id": comparison}).sqlstate == (
            INTEGRITY_CONSTRAINT_VIOLATION
        )


def test_cross_target_scan_is_rejected(db_session: Session, snap: Snapshot) -> None:
    values = _pair(db_session, snap)
    other = _insert_scan(
        db_session,
        snap,
        target_id=snap.sibling,
        target_origin="http://vampi-b:5000",
        scope_grant_id=snap.sibling_grant,
        api_spec_id=snap.sibling_spec,
        auth_profile_id=snap.sibling_profile,
        status="failed",
        finished_at=LATER,
    )
    assert violation(db_session, INSERT, {**values, "current": other}).sqlstate == (
        FOREIGN_KEY_VIOLATION
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", 0),
        ("comparability", "invalid"),
        ("reasons", "{}"),
    ],
)
def test_invalid_snapshot_fields_are_rejected(
    db_session: Session, snap: Snapshot, field: str, value: object
) -> None:
    values = _pair(db_session, snap)
    assert violation(db_session, INSERT, {**values, field: value}).sqlstate == CHECK_VIOLATION


def test_same_scan_is_rejected(db_session: Session, snap: Snapshot) -> None:
    values = _pair(db_session, snap)
    assert violation(db_session, INSERT, {**values, "current": values["baseline"]}).sqlstate == (
        CHECK_VIOLATION
    )


def test_unsealed_snapshot_cannot_commit(db_session: Session, snap: Snapshot) -> None:
    _snapshot(db_session, _pair(db_session, snap))
    error = violation(db_session, "SET CONSTRAINTS ALL IMMEDIATE", {})
    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
