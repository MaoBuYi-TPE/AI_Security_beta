"""比較 finding 必須引用同一 target，且隨快照封存。"""

from uuid import UUID, uuid4

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
from tests.integration.test_findings_schema import Linked

pytest_plugins = ("tests.integration.test_findings_schema",)
pytestmark = pytest.mark.integration

ROW = (
    "INSERT INTO scan_comparison_findings "
    "(comparison_id, finding_id, target_id, classification, reasons, evidence, "
    "manual_review_required) "
    "VALUES (:comparison, :finding, :target, :classification, CAST(:reasons AS jsonb), "
    "CAST(:evidence AS jsonb), false)"
)


def _comparison(session: Session, linked: Linked) -> tuple[UUID, UUID]:
    scan = session.execute(text("SELECT * FROM scans WHERE id = :id"), {"id": linked.scan}).one()
    current = session.execute(
        text(
            "INSERT INTO scans (project_id, target_id, target_origin, scope_grant_id, "
            "auth_role, scan_profile, requests_per_second, max_requests, max_duration_seconds, "
            "status, idempotency_key, request_sha256, created_by_key_id, finished_at) "
            "SELECT project_id, target_id, target_origin, scope_grant_id, auth_role, scan_profile, "
            "requests_per_second, max_requests, max_duration_seconds, 'failed', :key, "
            "request_sha256, created_by_key_id, clock_timestamp() FROM scans WHERE id = :scan "
            "RETURNING id"
        ),
        {"scan": linked.scan, "key": uuid4().hex},
    ).scalar_one()
    comparison = session.execute(
        text(
            "INSERT INTO scan_comparisons (project_id, target_id, baseline_scan_id, "
            "current_scan_id, "
            "algorithm_version, comparability, reasons, manual_review_required) "
            "VALUES (:project, :target, :baseline, :current, 1, 'different', '[]', false) "
            "RETURNING id"
        ),
        {
            "project": scan.project_id,
            "target": scan.target_id,
            "baseline": linked.scan,
            "current": current,
        },
    ).scalar_one()
    return comparison, scan.target_id


def _values(comparison: UUID, finding: UUID, target: UUID) -> dict[str, object]:
    return {
        "comparison": comparison,
        "finding": finding,
        "target": target,
        "classification": "inconclusive",
        "reasons": '["coverage_missing"]',
        "evidence": "{}",
    }


def test_rows_are_immutable_and_no_rows_can_be_added_after_sealing(
    session: Session, linked: Linked
) -> None:
    comparison, target = _comparison(session, linked)
    values = _values(comparison, linked.finding, target)
    session.execute(text(ROW), values)
    assert violation(session, ROW, values).sqlstate == UNIQUE_VIOLATION
    for statement in (
        "UPDATE scan_comparison_findings SET classification = 'new' WHERE comparison_id = :id",
        "DELETE FROM scan_comparison_findings WHERE comparison_id = :id",
    ):
        assert violation(session, statement, {"id": comparison}).sqlstate == (
            INTEGRITY_CONSTRAINT_VIOLATION
        )
    session.execute(
        text("UPDATE scan_comparisons SET sealed = true WHERE id = :id"), {"id": comparison}
    )
    assert violation(session, ROW, {**values, "finding": uuid4()}).sqlstate == (
        INTEGRITY_CONSTRAINT_VIOLATION
    )
    session.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))


def test_row_cannot_reference_an_unknown_finding_or_wrong_target(
    session: Session, linked: Linked
) -> None:
    comparison, target = _comparison(session, linked)
    values = _values(comparison, linked.finding, target)
    assert violation(session, ROW, {**values, "finding": uuid4()}).sqlstate == FOREIGN_KEY_VIOLATION
    assert violation(session, ROW, {**values, "target": uuid4()}).sqlstate == FOREIGN_KEY_VIOLATION


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("classification", "resolved"),
        ("reasons", "{}"),
        ("evidence", "[]"),
    ],
)
def test_invalid_finding_snapshot_fields_are_rejected(
    session: Session, linked: Linked, field: str, value: str
) -> None:
    comparison, target = _comparison(session, linked)
    values = _values(comparison, linked.finding, target)
    assert violation(session, ROW, {**values, field: value}).sqlstate == CHECK_VIOLATION


def test_insert_guard_rejects_an_invisible_parent_before_foreign_key_check(
    session: Session,
    linked: Linked,
) -> None:
    _, target = _comparison(session, linked)
    error = violation(session, ROW, _values(uuid4(), linked.finding, target))
    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert "parent" in str(error)
