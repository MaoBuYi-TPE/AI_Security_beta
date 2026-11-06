"""T22：run 的比較版本與覆蓋標記必須成對且不可改寫。"""

from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from tests.integration.sql_support import CHECK_VIOLATION, INTEGRITY_CONSTRAINT_VIOLATION, violation
from tests.integration.test_scan_schema import Snapshot, _insert_run, _insert_scan

pytest_plugins = ("tests.integration.test_scan_schema",)
pytestmark = pytest.mark.integration

SHA = "ab" * 32


def _run(session: Session, snapshot: Snapshot) -> UUID:
    return _insert_run(session, _insert_scan(session, snapshot))


def test_legacy_run_has_unknown_comparison_provenance(db_session: Session, snap: Snapshot) -> None:
    run_id = _run(db_session, snap)
    row = db_session.execute(
        text(
            "SELECT rule_set, rule_set_sha256, link_mapping_version, link_taxonomy_sha256, "
            "locations_recorded FROM scanner_runs WHERE id = :id"
        ),
        {"id": run_id},
    ).one()
    assert tuple(row) == (None, None, None, None, False)


def test_mapping_provenance_is_written_together_and_only_once(
    db_session: Session, snap: Snapshot
) -> None:
    run_id = _run(db_session, snap)
    db_session.execute(
        text(
            "UPDATE scanner_runs SET link_mapping_version = 'v2', "
            "link_taxonomy_sha256 = :sha, locations_recorded = true WHERE id = :id"
        ),
        {"id": run_id, "sha": SHA},
    )
    for assignment in (
        "link_mapping_version = 'v3'",
        "link_taxonomy_sha256 = NULL",
        "locations_recorded = false",
    ):
        error = violation(
            db_session,
            f"UPDATE scanner_runs SET {assignment} WHERE id = :id",  # noqa: S608
            {"id": run_id},
        )
        assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION


@pytest.mark.parametrize(
    "assignment",
    [
        "link_mapping_version = 'v2'",
        "link_taxonomy_sha256 = '" + SHA + "'",
        "link_mapping_version = '', link_taxonomy_sha256 = '" + SHA + "'",
        "link_mapping_version = 'v2', link_taxonomy_sha256 = 'bad'",
        "locations_recorded = true",
        "rule_set = '[]'::jsonb",
        "rule_set_sha256 = '" + SHA + "'",
    ],
)
def test_incomplete_or_invalid_provenance_is_rejected(
    db_session: Session, snap: Snapshot, assignment: str
) -> None:
    run_id = _run(db_session, snap)
    error = violation(
        db_session,
        f"UPDATE scanner_runs SET {assignment} WHERE id = :id",  # noqa: S608
        {"id": run_id},
    )
    assert error.sqlstate == CHECK_VIOLATION


def test_comparison_fields_cannot_be_forged_when_a_run_is_created(
    db_session: Session, snap: Snapshot
) -> None:
    from tests.integration.test_scan_schema import INSERT_RUN, _run_params

    scan_id = _insert_scan(db_session, snap)
    statement = INSERT_RUN.replace(
        "(scan_id, engine,", "(link_mapping_version, link_taxonomy_sha256, scan_id, engine,"
    ).replace("VALUES (:scan_id,", "VALUES ('v2', :sha, :scan_id,")
    error = violation(db_session, statement, {**_run_params(scan_id), "sha": SHA})
    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION


def test_location_records_are_append_only_and_belong_to_their_run(
    db_session: Session, snap: Snapshot
) -> None:
    scan_id = _insert_scan(db_session, snap)
    run_id = _insert_run(db_session, scan_id)
    db_session.execute(
        text(
            "INSERT INTO run_locations (scanner_run_id, scan_id, method, path_sha256, answered, "
            "discovery_answered, authenticated, unanswered) "
            "VALUES (:run, :scan, 'GET', repeat('c', 64), true, true, false, false)"
        ),
        {"run": run_id, "scan": scan_id},
    )
    db_session.execute(
        text(
            "INSERT INTO run_rule_locations (scanner_run_id, method, path_sha256, rule, answered, "
            "parameters_unknown, parameters_truncated) "
            "VALUES (:run, 'GET', repeat('c', 64), '40018', true, true, false)"
        ),
        {"run": run_id},
    )
    for table in ("run_locations", "run_rule_locations"):
        error = violation(
            db_session,
            f"DELETE FROM {table} WHERE scanner_run_id = :run",  # noqa: S608
            {"run": run_id},
        )
        assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION


def test_rule_location_requires_its_location(db_session: Session, snap: Snapshot) -> None:
    from tests.integration.sql_support import FOREIGN_KEY_VIOLATION

    run_id = _run(db_session, snap)
    error = violation(
        db_session,
        "INSERT INTO run_rule_locations (scanner_run_id, method, path_sha256, rule, answered, "
        "parameters_unknown, parameters_truncated) "
        "VALUES (:run, 'GET', repeat('d', 64), '40018', true, true, false)",
        {"run": run_id},
    )
    assert error.sqlstate == FOREIGN_KEY_VIOLATION


def test_location_rows_cannot_be_added_after_coverage_is_recorded(
    db_session: Session, snap: Snapshot
) -> None:
    scan_id = _insert_scan(db_session, snap)
    run_id = _insert_run(db_session, scan_id)
    db_session.execute(
        text(
            "UPDATE scanner_runs SET link_mapping_version = 'v2', "
            "link_taxonomy_sha256 = :sha, locations_recorded = true WHERE id = :id"
        ),
        {"id": run_id, "sha": SHA},
    )
    error = violation(
        db_session,
        "INSERT INTO run_locations (scanner_run_id, scan_id, method, path_sha256, answered, "
        "discovery_answered, authenticated, unanswered) "
        "VALUES (:run, :scan, 'GET', repeat('e', 64), true, true, false, false)",
        {"run": run_id, "scan": scan_id},
    )
    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION


def test_location_insert_guard_fails_closed_for_an_invisible_parent(db_session: Session) -> None:
    from uuid import uuid4

    error = violation(
        db_session,
        "INSERT INTO run_locations (scanner_run_id, scan_id, method, path_sha256, answered, "
        "discovery_answered, authenticated, unanswered) "
        "VALUES (:run, :scan, 'GET', repeat('e', 64), true, false, false, false)",
        {"run": uuid4(), "scan": uuid4()},
    )
    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
