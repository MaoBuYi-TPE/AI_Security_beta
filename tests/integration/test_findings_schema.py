"""findings 與 finding_observations 的 DB 約束與 trigger（T19；docs/DECISIONS.md §25.8）。

直接用 SQL 驗證：身分與對應不可修改、聚合只會往上、不能刪除；連結 append-only、每個觀察最多一次；
CHECK 擋下不合規則的對應與參數。資料先經 FindingLinker 建立。每個測試用自己的資料庫。
"""

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

import psycopg
import pytest
from alembic import command
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError, OperationalError
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
    NOT_NULL_VIOLATION,
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
        "normalized_confidence, needs_review, taxonomy_sha256, link_sequence) SELECT "
        "observation_id, finding_id, normalized_severity, normalized_confidence, needs_review, "
        "taxonomy_sha256, link_sequence FROM finding_observations WHERE observation_id = :id",
        {"id": linked.observation},
    )

    assert error.sqlstate == UNIQUE_VIOLATION


def _copy(session: Session, linked: Linked, **overrides: object) -> str:
    """複製既有的 finding（新的 id 與 fingerprint）再改幾個欄位：只驗證那些欄位的 CHECK。

    複製的列沒有連結，連結數不沿用來源的值（v0015 在 commit 時核對；這裡都會 rollback）。
    """
    values = {"id": uuid4(), "fingerprint": uuid4().hex * 2, "observations_linked": 0, **overrides}
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


# --- v0015：連結序號與跨表的 target 一致性（T20；docs/DECISIONS.md §26）---

_INSERT_OBSERVATION = (
    "INSERT INTO observations (scanner_run_id, scan_id, ordinal, source_event_id, source_index, "
    "source_rule, rule_variant, title, raw_severity, severity_label, raw_confidence, "
    "confidence_label, method, path, parameter_location, auth_role, parser_version) VALUES "
    "(:run, :scan, :ordinal, :event, 0, '40018', '40018', 'title', '3', 'High', '2', 'Medium', "
    "'GET', '/search', 'unknown', 'anonymous', 'test/1') RETURNING id"
)
# 0014 的形狀（沒有序號）：升級測試在降級之後寫入。
_INSERT_LINK_V14 = (
    "INSERT INTO finding_observations (observation_id, finding_id, normalized_severity, "
    "normalized_confidence, needs_review, taxonomy_sha256) VALUES "
    "(:observation, :finding, 'high', 'medium', false, repeat('a', 64))"
)
_INSERT_LINK = (
    "INSERT INTO finding_observations (observation_id, finding_id, normalized_severity, "
    "normalized_confidence, needs_review, taxonomy_sha256, link_sequence) VALUES "
    "(:observation, :finding, 'high', 'medium', false, repeat('a', 64), :sequence)"
)
_RESERVE = (
    "UPDATE findings SET observations_linked = observations_linked + :count WHERE id = :finding "
    "RETURNING observations_linked"
)


def _reserve(session: Session, finding: UUID, count: int = 1) -> int:
    """保留 count 個序號（持有 finding 的列鎖到 commit），回傳保留之後的連結數。"""
    return int(session.execute(text(_RESERVE), {"finding": finding, "count": count}).scalar_one())


def _link(session: Session, finding: UUID, observation: UUID, sequence: int) -> None:
    session.execute(
        text(_INSERT_LINK), {"finding": finding, "observation": observation, "sequence": sequence}
    )


def _observation(session: Session, run: UUID, scan: UUID) -> UUID:
    """同一個 run 的另一個觀察（直接以 SQL 寫入，不經 linker）。"""
    ordinal = session.execute(
        text("SELECT coalesce(max(ordinal), 0) + 1 FROM observations WHERE scanner_run_id = :run"),
        {"run": run},
    ).scalar_one()
    value = session.execute(
        text(_INSERT_OBSERVATION),
        {"run": run, "scan": scan, "ordinal": ordinal, "event": uuid4().hex * 2},
    ).scalar_one()
    assert isinstance(value, UUID)
    return value


def _sequences(session: Session, finding: UUID) -> tuple[int, list[int]]:
    linked = session.execute(
        text("SELECT observations_linked FROM findings WHERE id = :id"), {"id": finding}
    ).scalar_one()
    sequences = session.execute(
        text(
            "SELECT link_sequence FROM finding_observations WHERE finding_id = :id "
            "ORDER BY link_sequence"
        ),
        {"id": finding},
    ).scalars()
    return int(linked), [int(value) for value in sequences]


@dataclass(frozen=True)
class Foreign:
    """另一個 target 的 scan、run 與觀察。"""

    scan: UUID
    run: UUID
    observation: UUID


@pytest.fixture
def foreign(queue_engine: Engine, queue_seed: Seeder) -> Foreign:
    world = queue_seed.world()
    target, grant_id = web_target(queue_seed, world)
    scan = web_scan(queue_seed, world, target, grant_id, (ScanEngine.ZAP,))
    [run] = queue_seed.query("SELECT id FROM scanner_runs WHERE scan_id = :id", id=scan)
    with Session(queue_engine) as session, session.begin():
        observation = _observation(session, run.id, scan)
    return Foreign(scan, run.id, observation)


def test_links_carry_the_sequences_reserved_on_the_finding(
    session: Session, linked: Linked
) -> None:
    assert _sequences(session, linked.finding) == (1, [1])
    observations = [_observation(session, linked.run, linked.scan) for _ in range(2)]

    assert _reserve(session, linked.finding, 2) == 3
    for sequence, observation in enumerate(observations, start=2):
        _link(session, linked.finding, observation, sequence)
    session.commit()

    assert _sequences(session, linked.finding) == (3, [1, 2, 3])


def test_a_sequence_must_be_reserved_and_unused(session: Session, linked: Linked) -> None:
    observation = _observation(session, linked.run, linked.scan)
    params = {"finding": linked.finding, "observation": observation}

    unreserved = violation(session, _INSERT_LINK, {**params, "sequence": 2})
    _reserve(session, linked.finding)
    reused = violation(session, _INSERT_LINK, {**params, "sequence": 1})
    missing = violation(session, _INSERT_LINK, {**params, "sequence": None})

    assert unreserved.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION
    assert reused.sqlstate == UNIQUE_VIOLATION
    assert missing.sqlstate == NOT_NULL_VIOLATION


def test_an_observation_of_another_target_cannot_be_linked(
    session: Session, linked: Linked, foreign: Foreign
) -> None:
    """縱深防禦：linker 只連結同一個 target，DB 另外擋下（T19 的限制、安全審查）。"""
    _reserve(session, linked.finding)
    error = violation(
        session,
        _INSERT_LINK,
        {"observation": foreign.observation, "finding": linked.finding, "sequence": 2},
    )

    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION


def test_a_link_to_a_missing_finding_is_a_foreign_key_violation(
    session: Session, linked: Linked
) -> None:
    observation = _observation(session, linked.run, linked.scan)
    error = violation(
        session, _INSERT_LINK, {"observation": observation, "finding": uuid4(), "sequence": 1}
    )

    assert error.sqlstate == FOREIGN_KEY_VIOLATION


@pytest.mark.parametrize(
    "assignment", ["observations_linked = observations_linked - 1", "observations_linked = 0"]
)
def test_the_linked_count_never_moves_downwards(
    session: Session, linked: Linked, assignment: str
) -> None:
    assert _update(session, linked.finding, assignment) in {
        INTEGRITY_CONSTRAINT_VIOLATION,
        CHECK_VIOLATION,
    }


def test_reserved_sequences_must_all_be_linked_by_commit(
    queue_engine: Engine, linked: Linked
) -> None:
    """commit 時核對（deferred）：保留了卻沒有連結（含直接加 1 的計數）會讓 commit 失敗。"""
    with Session(queue_engine) as session:
        observation = _observation(session, linked.run, linked.scan)
        _reserve(session, linked.finding, 2)
        _link(session, linked.finding, observation, 2)
        with pytest.raises(IntegrityError, match="does not match"):
            session.commit()
    with Session(queue_engine) as session:
        _reserve(session, linked.finding)
        with pytest.raises(IntegrityError, match="does not match"):
            session.commit()
    with Session(queue_engine) as session:
        assert _sequences(session, linked.finding) == (1, [1])


def test_a_new_finding_must_have_its_reserved_links(queue_engine: Engine, linked: Linked) -> None:
    with Session(queue_engine) as session:
        values = {"id": uuid4(), "fingerprint": uuid4().hex * 2, "observations_linked": 5}
        selected = ", ".join(f":{name}" if name in values else name for name in _COLUMNS)
        session.execute(
            text(
                f"INSERT INTO findings ({', '.join(_COLUMNS)}) SELECT {selected} "  # noqa: S608
                "FROM findings WHERE id = :source"
            ),
            {**values, "source": linked.finding},
        )
        with pytest.raises(IntegrityError, match="does not match"):
            session.commit()


def test_seen_scans_must_belong_to_the_findings_target(
    session: Session, linked: Linked, foreign: Foreign
) -> None:
    other = {"first_seen_run_id": foreign.run, "first_seen_scan_id": foreign.scan}

    assert _copy(session, linked, **other) == INTEGRITY_CONSTRAINT_VIOLATION
    error = violation(
        session,
        "UPDATE findings SET last_seen_run_id = :run, last_seen_scan_id = :scan WHERE id = :id",
        {"run": foreign.run, "scan": foreign.scan, "id": linked.finding},
    )
    assert error.sqlstate == INTEGRITY_CONSTRAINT_VIOLATION


def test_a_second_writer_waits_and_readers_see_a_consistent_prefix(
    queue_engine: Engine, linked: Linked
) -> None:
    """同一個 finding 的配號以列鎖排隊：讀到的連結數 H 之內都已提交；別人保留、還沒提交的序號
    不能用；之後提交的序號一定大於 H。rollback 退回保留的序號，不留空號。
    """
    with Session(queue_engine) as setup, setup.begin():
        first, second, third = (_observation(setup, linked.run, linked.scan) for _ in range(3))
    finding = linked.finding
    with Session(queue_engine) as writer, Session(queue_engine) as other:
        assert _reserve(writer, finding) == 2
        _link(writer, finding, first, 2)
        with Session(queue_engine) as reader:
            assert _sequences(reader, finding) == (1, [1])
        with pytest.raises(IntegrityError):
            _link(other, finding, second, 2)
        other.rollback()
        other.execute(text("SET LOCAL lock_timeout = '200ms'"))
        with pytest.raises(OperationalError) as waited:
            _reserve(other, finding)
        assert isinstance(waited.value.orig, psycopg.errors.LockNotAvailable)
        other.rollback()
        writer.commit()
        assert _reserve(other, finding) == 3
        _link(other, finding, second, 3)
        other.rollback()
        assert _reserve(other, finding) == 3
        _link(other, finding, third, 3)
        other.commit()
    with Session(queue_engine) as reader:
        assert _sequences(reader, finding) == (3, [1, 2, 3])
        order = reader.execute(
            text(
                "SELECT observation_id FROM finding_observations WHERE finding_id = :finding "
                "ORDER BY link_sequence"
            ),
            {"finding": finding},
        ).scalars()
        assert list(order) == [linked.observation, first, third]


def test_the_upgrade_numbers_existing_links_in_link_order(
    queue_engine: Engine, linked: Linked
) -> None:
    with queue_engine.begin() as connection:
        command.downgrade(alembic_config(connection=connection), "0014")
    with Session(queue_engine) as session, session.begin():
        later = _observation(session, linked.run, linked.scan)
        session.execute(
            text(
                "INSERT INTO finding_observations (observation_id, finding_id, "
                "normalized_severity, normalized_confidence, needs_review, taxonomy_sha256, "
                "created_at) VALUES (:observation, :finding, 'high', 'medium', false, "
                "repeat('a', 64), now() + interval '1 second')"
            ),
            {"observation": later, "finding": linked.finding},
        )
    with queue_engine.begin() as connection:
        command.upgrade(alembic_config(connection=connection), "head")
    with Session(queue_engine) as session:
        assert _sequences(session, linked.finding) == (2, [1, 2])
        last = session.execute(
            text("SELECT observation_id FROM finding_observations WHERE link_sequence = 2")
        ).scalar_one()
    assert last == later


def test_the_upgrade_refuses_links_across_targets(
    queue_engine: Engine, linked: Linked, foreign: Foreign
) -> None:
    """升級前核對既有資料：不一致就失敗（fail closed），不靜默排除。"""
    with queue_engine.begin() as connection:
        command.downgrade(alembic_config(connection=connection), "0014")
    with Session(queue_engine) as session, session.begin():
        session.execute(
            text(_INSERT_LINK_V14),
            {"observation": foreign.observation, "finding": linked.finding},
        )

    with pytest.raises(IntegrityError, match="mix targets"), queue_engine.begin() as connection:
        command.upgrade(alembic_config(connection=connection), "head")

    with queue_engine.connect() as connection:
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
    assert version == "0014"
