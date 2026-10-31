"""artifacts、observations 與 run 結果欄位的 DB 約束（docs/DECISIONS.md §19.6）。

直接用 SQL 驗證：觀察與 artifact 只能以複合 FK 掛在同一個 scan 的 run 上，寫入之後不能改、不能刪；
run 的結果欄位彼此一致，run 結束之後由既有的 trigger 凍結。每個測試用自己的資料庫。
"""

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Seeder
from tests.integration.sql_support import (
    CHECK_VIOLATION,
    FOREIGN_KEY_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    NOT_NULL_VIOLATION,
    UNIQUE_VIOLATION,
    violation,
)

pytestmark = pytest.mark.integration

SHA = "ab" * 32
INSERT_ARTIFACT = (
    "INSERT INTO artifacts (scanner_run_id, scan_id, kind, path, sha256, size, redactions, "
    "classification, storage_key) VALUES (:run, :scan, :kind, :path, :sha256, :size, "
    ":redactions, :classification, :storage_key) RETURNING id"
)
INSERT_OBSERVATION = (
    "INSERT INTO observations (scanner_run_id, scan_id, ordinal, source_event_id, source_index, "
    "source_rule, rule_variant, title, raw_severity, severity_label, raw_confidence, "
    "confidence_label, cwe_id, wasc_id, method, path, query, parameter, parameter_location, "
    "attack, evidence, other_info, auth_role, report_artifact_id, parser_version) VALUES (:run, "
    ":scan, :ordinal, :event, :index, :rule, :variant, :title, :severity, 'Medium', :confidence, "
    "'High', :cwe, :wasc, :method, :path, :query, :parameter, :location, :attack, :evidence, "
    ":other, :role, :artifact, :parser) RETURNING id"
)


@dataclass(frozen=True)
class Runs:
    """兩個 scan 各一個 run：第二個用來驗證不能跨 scan 引用。"""

    scan: UUID
    run: UUID
    other_scan: UUID
    other_run: UUID


@pytest.fixture
def runs(queue_seed: Seeder) -> Runs:
    world = queue_seed.world()
    first = queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    second = queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    [one] = queue_seed.query("SELECT id FROM scanner_runs WHERE scan_id = :id", id=first.id)
    [two] = queue_seed.query("SELECT id FROM scanner_runs WHERE scan_id = :id", id=second.id)
    return Runs(first.id, one.id, second.id, two.id)


@pytest.fixture
def session(queue_engine: Engine) -> Iterator[Session]:
    with Session(queue_engine) as opened:
        yield opened
        opened.rollback()


def _artifact(runs: Runs, **changes: object) -> dict[str, object]:
    path = changes.get("path", "zap-report.json")
    return {
        "run": runs.run,
        "scan": runs.scan,
        "kind": "output",
        "path": path,
        "sha256": SHA,
        "size": 10,
        "redactions": 0,
        "classification": "masked",
        "storage_key": f"{runs.run}/out/{path}",
        **changes,
    }


def _observation(runs: Runs, **changes: object) -> dict[str, object]:
    return {
        "run": runs.run,
        "scan": runs.scan,
        "ordinal": 1,
        "event": SHA,
        "index": 0,
        "rule": "10038",
        "variant": "10038-1",
        "title": "Content Security Policy (CSP) Header Not Set",
        "severity": "2",
        "confidence": "3",
        "cwe": 693,
        "wasc": 15,
        "method": "GET",
        "path": "/",
        "query": None,
        "parameter": None,
        "location": "unknown",
        "attack": None,
        "evidence": None,
        "other": None,
        "role": "anonymous",
        "artifact": None,
        "parser": "zap-traditional-json/1",
        **changes,
    }


def _inserted(session: Session, statement: str, params: dict[str, object]) -> UUID:
    value = session.execute(text(statement), params).scalar()
    assert isinstance(value, UUID)
    return value


def test_valid_rows_are_accepted(session: Session, runs: Runs) -> None:
    artifact = _inserted(session, INSERT_ARTIFACT, _artifact(runs))
    _inserted(session, INSERT_OBSERVATION, _observation(runs, artifact=artifact))
    _inserted(
        session,
        INSERT_ARTIFACT,
        _artifact(runs, kind="input", path="plan.yaml", classification="input"),
    )

    row = session.execute(text("SELECT encrypted, created_at FROM artifacts LIMIT 1")).one()
    assert row.encrypted is False
    assert row.created_at is not None


@pytest.mark.parametrize(
    ("changes", "state", "constraint"),
    [
        ({"kind": "other"}, CHECK_VIOLATION, "ck_artifacts_classification_matches_kind"),
        ({"classification": "other"}, CHECK_VIOLATION, "ck_artifacts_classification_matches_kind"),
        ({"kind": "input"}, CHECK_VIOLATION, "ck_artifacts_classification_matches_kind"),
        ({"sha256": "XY" * 32}, CHECK_VIOLATION, "ck_artifacts_sha256_valid"),
        ({"size": -1}, CHECK_VIOLATION, "ck_artifacts_counts_not_negative"),
        ({"redactions": -1}, CHECK_VIOLATION, "ck_artifacts_counts_not_negative"),
        ({"path": "  "}, CHECK_VIOLATION, "ck_artifacts_path_not_blank"),
        ({"storage_key": " "}, CHECK_VIOLATION, "ck_artifacts_storage_key_not_blank"),
    ],
)
def test_invalid_artifacts_are_rejected(
    session: Session, runs: Runs, changes: dict[str, object], state: str, constraint: str
) -> None:
    error = violation(session, INSERT_ARTIFACT, _artifact(runs, **changes))

    assert (error.sqlstate, error.diag.constraint_name) == (state, constraint)


def test_an_artifact_is_listed_once(session: Session, runs: Runs) -> None:
    _inserted(session, INSERT_ARTIFACT, _artifact(runs))

    error = violation(session, INSERT_ARTIFACT, _artifact(runs))

    assert error.sqlstate == UNIQUE_VIOLATION


def test_an_artifact_belongs_to_a_run_of_the_same_scan(session: Session, runs: Runs) -> None:
    error = violation(session, INSERT_ARTIFACT, _artifact(runs, run=runs.other_run))

    assert error.sqlstate == FOREIGN_KEY_VIOLATION


@pytest.mark.parametrize(
    ("changes", "constraint"),
    [
        ({"ordinal": 0}, "ck_observations_ordinal_valid"),
        ({"index": -1}, "ck_observations_source_index_valid"),
        ({"event": "z" * 64}, "ck_observations_source_event_id_valid"),
        ({"rule": " "}, "ck_observations_source_rule_not_blank"),
        ({"title": "  "}, "ck_observations_title_not_blank"),
        ({"severity": " "}, "ck_observations_raw_severity_not_blank"),
        ({"confidence": " "}, "ck_observations_raw_confidence_not_blank"),
        ({"cwe": 0}, "ck_observations_cwe_positive"),
        ({"wasc": -1}, "ck_observations_wasc_positive"),
        ({"method": "BOGUS"}, "ck_observations_method_valid"),
        ({"path": "relative"}, "ck_observations_path_valid"),
        ({"location": "body"}, "ck_observations_parameter_location_valid"),
        ({"role": "Not Valid"}, "ck_observations_auth_role_valid"),
        ({"parser": " "}, "ck_observations_parser_version_not_blank"),
    ],
)
def test_invalid_observations_are_rejected(
    session: Session, runs: Runs, changes: dict[str, object], constraint: str
) -> None:
    error = violation(session, INSERT_OBSERVATION, _observation(runs, **changes))

    assert (error.sqlstate, error.diag.constraint_name) == (CHECK_VIOLATION, constraint)


@pytest.mark.parametrize(
    "changes", [{"ordinal": 2}, {"event": "cd" * 32}], ids=["same event", "same ordinal"]
)
def test_an_observation_is_unique_within_its_run(
    session: Session, runs: Runs, changes: dict[str, object]
) -> None:
    _inserted(session, INSERT_OBSERVATION, _observation(runs))

    duplicate = {"ordinal": 1} if "event" in changes else {"event": SHA}
    error = violation(session, INSERT_OBSERVATION, _observation(runs, **changes, **duplicate))

    assert error.sqlstate == UNIQUE_VIOLATION


def test_an_observation_belongs_to_a_run_of_the_same_scan(session: Session, runs: Runs) -> None:
    error = violation(session, INSERT_OBSERVATION, _observation(runs, run=runs.other_run))

    assert error.sqlstate == FOREIGN_KEY_VIOLATION


def test_the_report_of_an_observation_belongs_to_the_same_run(session: Session, runs: Runs) -> None:
    other = _inserted(
        session, INSERT_ARTIFACT, _artifact(runs, run=runs.other_run, scan=runs.other_scan)
    )

    error = violation(session, INSERT_OBSERVATION, _observation(runs, artifact=other))

    assert error.sqlstate == FOREIGN_KEY_VIOLATION


def test_an_observation_needs_a_run(session: Session, runs: Runs) -> None:
    error = violation(session, INSERT_OBSERVATION, _observation(runs, run=None))

    assert error.sqlstate == NOT_NULL_VIOLATION


def test_the_scan_cannot_be_deleted_under_the_records(
    queue_seed: Seeder, session: Session, runs: Runs
) -> None:
    """只有複合 FK 到 scanner_runs（§19.6）：沒有直接 FK 到 scans，對帳的鎖順序不受影響。"""
    rows = session.execute(
        text(
            "SELECT count(*) FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid "
            "JOIN pg_class r ON r.oid = c.confrelid "
            "WHERE t.relname IN ('artifacts', 'observations') AND r.relname = 'scans'"
        )
    ).scalar()

    assert rows == 0


@pytest.mark.parametrize(
    ("statement", "table"),
    [
        ("UPDATE artifacts SET size = 0", "artifacts"),
        ("DELETE FROM artifacts", "artifacts"),
        ("TRUNCATE artifacts CASCADE", "artifacts"),
        ("UPDATE observations SET title = 'x'", "observations"),
        ("DELETE FROM observations", "observations"),
        ("TRUNCATE observations", "observations"),
    ],
)
def test_records_are_append_only(
    queue_engine: Engine, runs: Runs, statement: str, table: str
) -> None:
    with Session(queue_engine) as session:
        artifact = _inserted(session, INSERT_ARTIFACT, _artifact(runs))
        _inserted(session, INSERT_OBSERVATION, _observation(runs, artifact=artifact))
        session.commit()

    with Session(queue_engine) as session, pytest.raises(DBAPIError) as caught:
        session.execute(text(statement))

    orig: Any = caught.value.orig
    assert orig.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert "rows are immutable" in str(orig)


# --- run 的結果欄位 ------------------------------------------------------------------------

SET_RESULTS = (
    "UPDATE scanner_runs SET results_recorded = :recorded, parser_version = :parser, "
    "engine_version = :engine, exit_code = :exit_code, observation_count = :count, "
    "result_details = CAST(:details AS jsonb) WHERE id = :run"
)


def _results(runs: Runs, **changes: object) -> dict[str, object]:
    return {
        "recorded": True,
        "parser": "zap-traditional-json/1",
        "engine": "2.17.0",
        "exit_code": 0,
        "count": 0,
        "details": '{"status": "succeeded"}',
        "run": runs.run,
        **changes,
    }


def test_a_run_starts_without_results(session: Session, runs: Runs) -> None:
    row = session.execute(
        text("SELECT results_recorded, parser_version FROM scanner_runs WHERE id = :id"),
        {"id": runs.run},
    ).one()

    assert (row.results_recorded, row.parser_version) == (False, None)


def test_results_are_accepted(session: Session, runs: Runs) -> None:
    session.execute(text(SET_RESULTS), _results(runs))
    # 輸出不能用時版本與退出碼可以是未知的。
    session.execute(text(SET_RESULTS), _results(runs, engine=None, exit_code=None))


@pytest.mark.parametrize(
    ("changes", "constraint"),
    [
        ({"recorded": False}, "ck_scanner_runs_results_consistent"),
        ({"parser": None}, "ck_scanner_runs_results_consistent"),
        ({"count": None}, "ck_scanner_runs_results_consistent"),
        ({"details": None}, "ck_scanner_runs_results_consistent"),
        ({"count": -1}, "ck_scanner_runs_result_counts_valid"),
        ({"exit_code": 256}, "ck_scanner_runs_result_counts_valid"),
        ({"exit_code": -1}, "ck_scanner_runs_result_counts_valid"),
        ({"details": "[]"}, "ck_scanner_runs_result_details_valid"),
        ({"details": '{"x": "' + "a" * 4096 + '"}'}, "ck_scanner_runs_result_details_valid"),
    ],
)
def test_invalid_results_are_rejected(
    session: Session, runs: Runs, changes: dict[str, object], constraint: str
) -> None:
    error = violation(session, SET_RESULTS, _results(runs, **changes))

    assert (error.sqlstate, error.diag.constraint_name) == (CHECK_VIOLATION, constraint)


def test_nothing_about_the_results_can_be_set_without_recording_them(
    session: Session, runs: Runs
) -> None:
    error = violation(
        session,
        SET_RESULTS,
        _results(runs, recorded=False, parser=None, count=None, details=None),
    )

    assert error.diag.constraint_name == "ck_scanner_runs_results_consistent"


def test_results_are_frozen_when_the_run_ends(queue_seed: Seeder, queue_engine: Engine) -> None:
    world = queue_seed.world()
    queue_seed.scan(world.operator_a, queue_seed.scannable(world))
    queue = ScanQueue(
        sessionmaker(queue_engine, expire_on_commit=False),
        lab=LAB,
        clock=lambda: datetime.now(UTC),
    )
    lease = queue.claim(f"runner-{uuid4().hex[:6]}", frozenset({ScanEngine.FAKE}))
    assert lease is not None
    queue.advance(lease, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)

    with Session(queue_engine) as session, pytest.raises(DBAPIError) as caught:
        session.execute(
            text("UPDATE scanner_runs SET exit_code = 1 WHERE id = :id"), {"id": lease.run_id}
        )

    orig: Any = caught.value.orig
    assert orig.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
