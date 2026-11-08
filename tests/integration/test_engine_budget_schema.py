"""引擎子預算的 DB 約束與 trigger（BUDGET-06；docs/DECISIONS.md §29、migration v0020）。

直接以 SQL 驗證：即使程式有 bug，上限建立之後也不能修改；上限只屬於掃描引擎；分到的請求數與秒數
一起寫入、只寫一次，而且不超過上限（還不認得上限、只寫請求數的舊 runner 會被擋下）。
"""

from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from secscan.scans.domain.allocation import EngineBudgetRequest
from secscan.scans.domain.catalog import Engine
from secscan.scans.repository import ScanRepository
from tests.integration.scan_support import web_scan
from tests.integration.sql_support import (
    CHECK_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    violation,
)

pytestmark = pytest.mark.integration

SPLIT = (
    EngineBudgetRequest(Engine.ZAP, max_requests=760, max_duration_seconds=380),
    EngineBudgetRequest(Engine.NUCLEI, max_requests=440, max_duration_seconds=220),
)
ALLOTMENT_CHECK = "ck_scanner_runs_allotment_within_engine_budget"
INSERT_RUN = (
    "INSERT INTO scanner_runs (scan_id, engine, sequence, status, budget_max_requests, "
    "budget_max_duration_seconds) VALUES (:scan_id, :engine, :sequence, 'queued', :requests, "
    ":seconds)"
)


def _scan(session: Session, *, engines: tuple[Engine, ...], split: object = None) -> UUID:
    return web_scan(session, engines=engines, split=split)[1].id


def _run(session: Session, scan_id: UUID, engine: Engine) -> UUID:
    value = session.execute(
        text("SELECT id FROM scanner_runs WHERE scan_id = :scan AND engine = :engine"),
        {"scan": scan_id, "engine": engine.value},
    ).scalar_one()
    assert isinstance(value, UUID)
    return value


def _rejected(session: Session, statement: str, **params: object) -> tuple[str, str, str]:
    error = violation(session, statement, params)
    return error.sqlstate or "", error.diag.constraint_name or "", str(error)


@pytest.fixture
def capped(db_session: Session) -> UUID:
    """zap 與 nuclei 都有上限的 scan，回傳 zap 的 run。"""
    return _run(
        db_session, _scan(db_session, engines=(Engine.ZAP, Engine.NUCLEI), split=SPLIT), Engine.ZAP
    )


# --- 上限不能修改 --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE scanner_runs SET budget_max_requests = 1 WHERE id = :id",
        "UPDATE scanner_runs SET budget_max_duration_seconds = 1 WHERE id = :id",
        "UPDATE scanner_runs SET budget_max_requests = NULL, budget_max_duration_seconds = NULL "
        "WHERE id = :id",
    ],
)
def test_a_frozen_cap_cannot_change(db_session: Session, capped: UUID, statement: str) -> None:
    state, _, message = _rejected(db_session, statement, id=capped)

    assert state == INTEGRITY_CONSTRAINT_VIOLATION
    assert "engine budget is frozen" in message


def test_a_cap_cannot_be_added_after_the_scan_is_created(db_session: Session) -> None:
    scan_id = _scan(db_session, engines=(Engine.ZAP, Engine.NUCLEI))
    run_id = _run(db_session, scan_id, Engine.NUCLEI)

    state, _, message = _rejected(
        db_session,
        "UPDATE scanner_runs SET budget_max_requests = 10, budget_max_duration_seconds = 60 "
        "WHERE id = :id",
        id=run_id,
    )

    assert state == INTEGRITY_CONSTRAINT_VIOLATION
    assert "engine budget is frozen" in message


def test_the_same_value_written_again_is_not_a_change(db_session: Session, capped: UUID) -> None:
    db_session.execute(
        text("UPDATE scanner_runs SET budget_max_requests = 760 WHERE id = :id"), {"id": capped}
    )


# --- CHECK：上限 ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("engine", "requests", "seconds"),
    [
        (Engine.NUCLEI, 10, None),
        (Engine.NUCLEI, None, 60),
        (Engine.NUCLEI, 0, 60),
        (Engine.NUCLEI, 10, 0),
        (Engine.NUCLEI, -1, 60),
        (Engine.FAKE, 10, 60),
        (Engine.PREFLIGHT, 10, 60),
    ],
)
def test_a_cap_is_two_positive_integers_on_a_scanning_engine(
    db_session: Session, engine: Engine, requests: int | None, seconds: int | None
) -> None:
    scan_id = _scan(db_session, engines=(Engine.ZAP,))

    state, constraint, _ = _rejected(
        db_session,
        INSERT_RUN,
        scan_id=scan_id,
        engine=engine.value,
        sequence=2,
        requests=requests,
        seconds=seconds,
    )

    assert (state, constraint) == (CHECK_VIOLATION, "ck_scanner_runs_engine_budget_valid")


@pytest.mark.parametrize("engine", [Engine.NUCLEI, Engine.SCHEMATHESIS])
def test_a_valid_cap_can_be_inserted_while_creating_the_scan(
    db_session: Session, engine: Engine
) -> None:
    """允許清單：只有掃描引擎可以有上限（CHECK 是 engine IN (...)，不是排除清單）。"""
    scan_id = _scan(db_session, engines=(Engine.ZAP,))

    db_session.execute(
        text(INSERT_RUN),
        {"scan_id": scan_id, "engine": engine.value, "sequence": 2, "requests": 10, "seconds": 60},
    )


def test_a_new_run_cannot_carry_an_allotment(db_session: Session) -> None:
    """配額只在 runner 開始執行時寫入一次：新增 run 時預填會被擋下。"""
    scan_id = _scan(db_session, engines=(Engine.ZAP,))

    state, _, message = _rejected(
        db_session,
        "INSERT INTO scanner_runs (scan_id, engine, sequence, status, requests_allotted) "
        "VALUES (:scan_id, 'nuclei', 2, 'queued', 5)",
        scan_id=scan_id,
    )

    assert state == INTEGRITY_CONSTRAINT_VIOLATION
    assert "cannot carry an allotment" in message


# --- CHECK 與 trigger：分到的配額 ----------------------------------------------------------


def test_an_allotment_without_seconds_is_refused_on_a_capped_run(
    db_session: Session, capped: UUID
) -> None:
    """還不認得上限的舊 runner 只寫請求數：transaction 失敗，容器不會建立（fail closed）。"""
    state, constraint, _ = _rejected(
        db_session, "UPDATE scanner_runs SET requests_allotted = 5 WHERE id = :id", id=capped
    )

    assert (state, constraint) == (CHECK_VIOLATION, ALLOTMENT_CHECK)


@pytest.mark.parametrize(("requests", "seconds"), [(761, 380), (760, 381)])
def test_an_allotment_beyond_the_cap_is_refused(
    db_session: Session, capped: UUID, requests: int, seconds: int
) -> None:
    state, constraint, _ = _rejected(
        db_session,
        "UPDATE scanner_runs SET requests_allotted = :r, seconds_allotted = :s WHERE id = :id",
        id=capped,
        r=requests,
        s=seconds,
    )

    assert (state, constraint) == (CHECK_VIOLATION, ALLOTMENT_CHECK)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE scanner_runs SET seconds_allotted = 10 WHERE id = :id",
        "UPDATE scanner_runs SET requests_allotted = 5, seconds_allotted = -1 WHERE id = :id",
    ],
)
def test_seconds_come_with_requests_and_are_not_negative(
    db_session: Session, statement: str
) -> None:
    run_id = _run(db_session, _scan(db_session, engines=(Engine.ZAP,)), Engine.ZAP)

    state, constraint, _ = _rejected(db_session, statement, id=run_id)

    assert (state, constraint) == (CHECK_VIOLATION, "ck_scanner_runs_seconds_allotted_valid")


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE scanner_runs SET requests_allotted = 700 WHERE id = :id",
        "UPDATE scanner_runs SET seconds_allotted = 300 WHERE id = :id",
        "UPDATE scanner_runs SET seconds_allotted = NULL WHERE id = :id",
    ],
)
def test_an_allotment_is_recorded_only_once(
    db_session: Session, capped: UUID, statement: str
) -> None:
    db_session.execute(
        text(
            "UPDATE scanner_runs SET requests_allotted = 760, seconds_allotted = 380 WHERE id = :id"
        ),
        {"id": capped},
    )

    state, _, message = _rejected(db_session, statement, id=capped)

    assert state == INTEGRITY_CONSTRAINT_VIOLATION
    assert "allotment can only be recorded once" in message


def test_an_uncapped_run_still_records_requests_alone_once(db_session: Session) -> None:
    """T31 之前的資料列沒有秒數：沒有上限的 run 只寫請求數仍然可以，但也只能寫一次。"""
    run_id = _run(db_session, _scan(db_session, engines=(Engine.ZAP,)), Engine.ZAP)
    db_session.execute(
        text("UPDATE scanner_runs SET requests_allotted = 5 WHERE id = :id"), {"id": run_id}
    )

    state, _, message = _rejected(
        db_session, "UPDATE scanner_runs SET requests_allotted = 6 WHERE id = :id", id=run_id
    )

    assert state == INTEGRITY_CONSTRAINT_VIOLATION
    assert "allotment can only be recorded once" in message


def test_a_legacy_run_reads_back(db_session: Session) -> None:
    """T31 之前的 run：有請求數、沒有秒數、沒有上限；經 repository 讀回不違反 domain 的規則。"""
    scan_id = _scan(db_session, engines=(Engine.ZAP,))
    run_id = _run(db_session, scan_id, Engine.ZAP)
    db_session.execute(
        text("UPDATE scanner_runs SET requests_allotted = 5 WHERE id = :id"), {"id": run_id}
    )

    stored = ScanRepository(db_session).get(scan_id)

    assert stored is not None
    [run] = stored.runs
    assert (run.budget, run.requests_allotted, run.seconds_allotted) == (None, 5, None)
