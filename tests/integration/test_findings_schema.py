"""findings 與 finding_observations 的 DB 約束與 trigger（T19；docs/DECISIONS.md §25.8）。

直接用 SQL 驗證：身分與對應不可修改、聚合只會往上、不能刪除；連結 append-only、每個觀察最多一次；
CHECK 擋下不合規則的對應與參數。資料先經 FindingLinker 建立。每個測試用自己的資料庫。
"""

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from alembic import command
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from secscan.findings.models import FindingModel
from secscan.findings.service import FindingLinker
from secscan.migrations import alembic_config
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Seeder
from tests.integration.finding_support import ZAP_CORS, ZAP_SQLI, parsed_run, web_scan, web_target
from tests.integration.sql_support import (
    CHECK_VIOLATION,
    FOREIGN_KEY_VIOLATION,
    INTEGRITY_CONSTRAINT_VIOLATION,
    UNIQUE_VIOLATION,
    violation,
)

pytestmark = pytest.mark.integration

_COLUMNS = [column.name for column in FindingModel.__table__.columns]


@dataclass(frozen=True)
class Linked:
    finding: UUID
    observation: UUID
    run: UUID
    scan: UUID


@pytest.fixture
def linked(queue_engine: Engine, queue_seed: Seeder) -> Linked:
    sessions = sessionmaker(queue_engine, expire_on_commit=False)
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    world = queue_seed.world()
    target, grant_id = web_target(queue_seed, world)
    web_scan(queue_seed, world, target, grant_id, (ScanEngine.ZAP,))
    lease = parsed_run(queue, ScanEngine.ZAP, (ZAP_SQLI, ZAP_CORS))
    FindingLinker(sessions).link(lease)
    [row] = queue_seed.query(
        "SELECT f.id, l.observation_id FROM findings f JOIN finding_observations l "
        "ON l.finding_id = f.id WHERE f.rule_group = 'zap-sql-injection'"
    )
    return Linked(row.id, row.observation_id, lease.run_id, lease.scan_id)


@pytest.fixture
def session(queue_engine: Engine) -> Iterator[Session]:
    with Session(queue_engine) as opened:
        yield opened
        opened.rollback()


def _update(session: Session, finding: UUID, assignment: str) -> str:
    # assignment 是測試自己的常數（parametrize），不是外部輸入。
    statement = f"UPDATE findings SET {assignment} WHERE id = :id"  # noqa: S608
    error = violation(session, statement, {"id": finding})
    return str(error.sqlstate)


@pytest.mark.parametrize(
    "assignment",
    [
        "title = 'renamed'",
        "rule_group = 'zap:40018'",
        "route = '/other'",
        "fingerprint = repeat('c', 64)",
        "category = 'unclassified'",
        "auth_verified = false",
        "owasp_top10_2025 = NULL, owasp_top10_2025_source = 'none'",
        "cwe_id = 79",
        "triage_state = 'confirmed'",
        "lifecycle_state = 'resolved'",
        "created_at = created_at - interval '1 day'",
    ],
)
def test_identity_mapping_and_triage_cannot_change(
    session: Session, linked: Linked, assignment: str
) -> None:
    """triage 與 lifecycle 的修改在 T21（另以 migration 開放、留下 audit）。"""
    assert _update(session, linked.finding, assignment) == INTEGRITY_CONSTRAINT_VIOLATION


@pytest.mark.parametrize(
    "assignment",
    [
        "normalized_severity = 'medium'",  # high → medium
        "last_seen_at = created_at - interval '1 second'",
    ],
)
def test_aggregates_never_move_downwards(session: Session, linked: Linked, assignment: str) -> None:
    assert _update(session, linked.finding, assignment) in {
        INTEGRITY_CONSTRAINT_VIOLATION,
        CHECK_VIOLATION,
    }


def test_flags_once_raised_stay_raised(session: Session, linked: Linked) -> None:
    session.execute(
        text("UPDATE findings SET severity_conflict = true, needs_review = true WHERE id = :id"),
        {"id": linked.finding},
    )

    for assignment in ("severity_conflict = false", "needs_review = false"):
        assert _update(session, linked.finding, assignment) == INTEGRITY_CONSTRAINT_VIOLATION


def test_the_aggregates_and_last_seen_can_move_upwards(session: Session, linked: Linked) -> None:
    session.execute(
        text(
            "UPDATE findings SET normalized_severity = 'critical', severity_conflict = true, "
            "last_seen_at = clock_timestamp() WHERE id = :id"
        ),
        {"id": linked.finding},
    )

    severity = session.execute(
        text("SELECT normalized_severity FROM findings WHERE id = :id"), {"id": linked.finding}
    ).scalar()
    assert severity == "critical"


@pytest.mark.parametrize(
    ("statement", "params"),
    [
        ("DELETE FROM findings WHERE id = :id", "finding"),
        ("TRUNCATE findings CASCADE", None),
        ("UPDATE finding_observations SET needs_review = true WHERE observation_id = :id", "obs"),
        ("DELETE FROM finding_observations WHERE observation_id = :id", "obs"),
        ("TRUNCATE finding_observations", None),
    ],
)
def test_findings_and_links_cannot_be_removed(
    session: Session, linked: Linked, statement: str, params: str | None
) -> None:
    values = {"finding": {"id": linked.finding}, "obs": {"id": linked.observation}}
    error = violation(session, statement, values.get(params or "", {}))

    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION


def test_an_observation_is_linked_at_most_once(session: Session, linked: Linked) -> None:
    error = violation(
        session,
        "INSERT INTO finding_observations (observation_id, finding_id, normalized_severity, "
        "normalized_confidence, needs_review, taxonomy_sha256) SELECT observation_id, finding_id, "
        "normalized_severity, normalized_confidence, needs_review, taxonomy_sha256 "
        "FROM finding_observations WHERE observation_id = :id",
        {"id": linked.observation},
    )

    assert error.sqlstate == UNIQUE_VIOLATION


def _copy(session: Session, linked: Linked, **overrides: object) -> str:
    """複製既有的 finding（新的 id 與 fingerprint）再改幾個欄位：只驗證那些欄位的 CHECK。"""
    values = {"id": uuid4(), "fingerprint": uuid4().hex * 2, **overrides}
    selected = ", ".join(f":{name}" if name in values else name for name in _COLUMNS)
    # 欄位名稱來自 model，值都是 bind 參數。
    statement = (
        f"INSERT INTO findings ({', '.join(_COLUMNS)}) SELECT {selected} "  # noqa: S608
        "FROM findings WHERE id = :source"
    )
    error = violation(session, statement, {**values, "source": linked.finding})
    return str(error.sqlstate)


@pytest.mark.parametrize(
    "overrides",
    [
        {"owasp_top10_2025": "A11:2025"},
        {"owasp_top10_2025": "A02:2021"},
        {"owasp_top10_2025_source": "curated"},
        {"owasp_top10_2025": None},  # 有來源卻沒有分類
        {"owasp_api_2023": "API11:2023"},
        {"owasp_api_2023": "API8:2023", "owasp_api_2023_source": "official"},
        {"cwe_source": None},
        {"cwe_id": None},
        {"cwe_id": 0},
        {"parameter_name": None},
        {"parameter_location": "body"},
        {"kind": "finding"},
        {"category": "exploit"},
        # kind 與 category 不一致（unclassified 是 fallback，任何 kind 都可以）。
        {"category": "technology"},
        {"kind": "informational", "category": "vulnerability"},
        {"normalized_severity": "severe"},
        {"route": "search"},
        {"route_source": "guess"},
        {"fingerprint": "XYZ"},
        {"auth_role": "Admin"},
    ],
)
def test_checks_reject_invalid_rows(
    session: Session, linked: Linked, overrides: dict[str, object]
) -> None:
    assert _copy(session, linked, **overrides) == CHECK_VIOLATION


@pytest.mark.parametrize(
    "overrides", [{"triage_state": "confirmed"}, {"lifecycle_state": "resolved"}]
)
def test_new_findings_start_unreviewed_and_open(
    session: Session, linked: Linked, overrides: dict[str, object]
) -> None:
    """triage 只能由 T21 的流程改（留下 audit）：新增時也不能直接寫入非初始的狀態。

    BEFORE INSERT 的 trigger 在 CHECK 之前執行，所以不合法的 triage 值（例如 fixed）也在這裡擋下。
    """
    assert _copy(session, linked, **overrides) == INTEGRITY_CONSTRAINT_VIOLATION


def test_v0014_marks_existing_findings_unclassified_and_needing_review(
    queue_engine: Engine, linked: Linked
) -> None:
    """升級時既有的列沒有經過 v2 的分類：unclassified，並標 needs_review（安全審查）。"""
    with queue_engine.begin() as connection:
        config = alembic_config(connection=connection)
        command.downgrade(config, "0013")
        command.upgrade(config, "head")
    with Session(queue_engine) as session:
        row = session.execute(
            text("SELECT category, needs_review FROM findings WHERE id = :id"),
            {"id": linked.finding},
        ).one()

    assert (row.category, row.needs_review) == ("unclassified", True)


def test_a_target_has_one_finding_per_fingerprint(session: Session, linked: Linked) -> None:
    fingerprint = session.execute(
        text("SELECT fingerprint FROM findings WHERE id = :id"), {"id": linked.finding}
    ).scalar()

    assert _copy(session, linked, fingerprint=fingerprint) == UNIQUE_VIOLATION


def test_seen_runs_must_belong_to_the_seen_scan(session: Session, linked: Linked) -> None:
    """first／last seen 以複合 FK 掛在 scanner_runs：run 與 scan 必須一致。"""
    assert _copy(session, linked, last_seen_scan_id=uuid4()) == FOREIGN_KEY_VIOLATION
    assert _copy(session, linked, first_seen_run_id=uuid4()) == FOREIGN_KEY_VIOLATION
