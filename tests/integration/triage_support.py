"""T21 的整合測試共用：以真實的佇列與 linker 建立 scan 與 finding，再以構造的評估結果封存比較。

比較快照一律經 ComparisonRepository.save 寫入（走正常的 trigger、同一個 transaction 封存），只有
逐 finding 的分類與證據是構造的：用來涵蓋 algorithm v1 在 live 中不會產生的 not_observed，以及
人工複測需要的「平台證據都成立」的 inconclusive 列。
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.comparisons.domain.classification import (
    Classification,
    ComparisonFacts,
    CoverageEvidence,
    Reason,
    RuleEvidence,
    SourceRef,
)
from secscan.comparisons.domain.comparability import Comparability, ScanComparison
from secscan.comparisons.domain.facts import Evaluation, FindingComparison
from secscan.comparisons.inputs import ComparisonInputs
from secscan.comparisons.repository import ComparisonRepository
from secscan.findings.service import FindingLinker
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease
from secscan.scans.domain.observation import ObservationInput, RunOutcome
from secscan.scans.queue import ScanQueue
from secscan.targets.domain import Target
from tests.integration.api_support import LAB, Seeder, World
from tests.integration.finding_support import ZAP_CORS, ZAP_SQLI, parsed_run, web_scan, web_target

SOURCE = SourceRef("zap", "40018", "40018")
RULE = RuleEvidence(
    source=SOURCE,
    engine_succeeded=True,
    time_limit_reached=False,
    definition_comparable=True,
    has_location_response=True,
    rule_completed=False,
    parameter_comparable=False,
)
COVERAGE = CoverageEvidence(
    in_scope=True,
    role_comparable=True,
    identity_verified=True,
    spec_comparable=True,
    telemetry_complete=True,
    required_sources=(SOURCE,),
    sources=(RULE,),
)
ELIGIBLE_FACTS = ComparisonFacts(
    baseline_observed=True,
    current_observed=False,
    fingerprint_comparable=True,
    mapping_comparable=True,
    finding_identity_verified=True,
    other_scan_coverage=COVERAGE,
    reidentified=False,
)
ELIGIBLE_REASONS = (Reason.RULE_INCOMPLETE.value, Reason.PARAMETER_UNVERIFIED.value)
PERSISTENT_FACTS = replace(ELIGIBLE_FACTS, current_observed=True, other_scan_coverage=None)


@dataclass(frozen=True, slots=True)
class Scenario:
    target: Target
    grant_id: UUID
    baseline: UUID
    current: UUID
    sqli: UUID
    cors: UUID

    @property
    def host(self) -> str:
        return f"{self.target.origin.host}:{self.target.origin.port}"


def queue(engine: Engine) -> ScanQueue:
    sessions = sessionmaker(engine, expire_on_commit=False)
    return ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))


def run_scan(
    engine: Engine,
    seed: Seeder,
    world: World,
    target: Target,
    grant_id: UUID,
    observations: Sequence[ObservationInput],
    *,
    status: RunStatus = RunStatus.SUCCEEDED,
    link: bool = True,
) -> tuple[UUID, Lease]:
    """一個 ZAP scan：寫入觀察、連結 finding、結束 run（scan 隨之終止）。"""
    scan = web_scan(seed, world, target, grant_id, (ScanEngine.ZAP,))
    error = _ERRORS.get(status)
    lease = parsed_run(
        queue(engine), ScanEngine.ZAP, observations, outcome=RunOutcome(status, error)
    )
    if link:
        FindingLinker(sessionmaker(engine, expire_on_commit=False)).link(lease)
        queue(engine).advance(lease, status, error_code=error)
    return scan, lease


_ERRORS = {
    RunStatus.FAILED: RunErrorCode.ENGINE_FAILED,
    RunStatus.TIMED_OUT: RunErrorCode.TIME_LIMIT_EXCEEDED,
}


def scenario(engine: Engine, seed: Seeder, world: World) -> Scenario:
    """baseline 觀察到 SQLi 與 CORS；current 只觀察到 CORS（SQLi 未觀察到）。"""
    target, grant = web_target(seed, world)
    baseline, _ = run_scan(engine, seed, world, target, grant, (ZAP_SQLI, ZAP_CORS))
    current, _ = run_scan(engine, seed, world, target, grant, (ZAP_CORS,))
    [sqli] = seed.query(
        "SELECT id FROM findings WHERE target_id = :target AND route = '/search'", target=target.id
    )
    [cors] = seed.query(
        "SELECT id FROM findings WHERE target_id = :target AND route = '/'", target=target.id
    )
    return Scenario(target, grant, baseline, current, sqli.id, cors.id)


def seal(
    engine: Engine,
    baseline: UUID,
    current: UUID,
    rows: Mapping[UUID, "Row"],
    *,
    comparability: Comparability = Comparability.COMPARABLE,
) -> UUID:
    """以真實的 scan 證據與構造的逐 finding 結果封存比較（ComparisonRepository.save）。"""
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions.begin() as session:
        inputs = ComparisonInputs(session)
        before, after = inputs.scan(baseline), inputs.scan(current)
        assert before is not None
        assert after is not None
        evaluation = Evaluation(
            ScanComparison(comparability, (), False),
            tuple(
                FindingComparison(finding_id, classification, reasons, manual, facts)
                for finding_id, (classification, reasons, manual, facts) in rows.items()
            ),
        )
        snapshot, created = ComparisonRepository(session).save(before, after, evaluation)
        assert created
        return snapshot.id


Row = tuple[Classification, tuple[str, ...], bool, ComparisonFacts]


def eligible(engine: Engine, item: Scenario) -> UUID:
    """SQLi 是符合人工複測條件的 inconclusive；CORS 是 persistent。"""
    rows: dict[UUID, Row] = {
        item.sqli: (Classification.INCONCLUSIVE, ELIGIBLE_REASONS, False, ELIGIBLE_FACTS),
        item.cors: (Classification.PERSISTENT, (), False, PERSISTENT_FACTS),
    }
    return seal(engine, item.baseline, item.current, rows)


def db_now(seed: Seeder) -> datetime:
    [row] = seed.query("SELECT clock_timestamp() AS now")
    now: datetime = row.now
    return now


def attestation(item: Scenario, performed_at: datetime, **changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "method": "manual_retest",
        "performed_at": performed_at.isoformat(),
        "performed_by": "lab operator",
        "procedure": "以單引號送出 q；修補後應回 200 與空結果，不是 500。",
        "result": "not_reproduced",
        "auth_role": "anonymous",
        "request_excerpt": f"GET /search?q=apple' HTTP/1.1\nHost: {item.host}\nAccept: */*\n",
        "response_excerpt": "HTTP/1.1 200\n\n[]",
    }
    return {**body, **changes}


def resolve_body(
    comparison_id: UUID, body: dict[str, Any], *, version: int = 1, **changes: Any
) -> dict[str, Any]:
    return {
        "expected_version": version,
        "lifecycle_state": "resolved",
        "reason": "人工複測確認修補後的行為",
        "basis": "manual_retest",
        "comparison_id": str(comparison_id),
        "attestation": body,
        **changes,
    }


CONFIRM = {"expected_version": 0, "triage_state": "confirmed", "reason": "人工確認告警屬實"}
