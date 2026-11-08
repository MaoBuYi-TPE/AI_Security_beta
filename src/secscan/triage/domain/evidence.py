"""resolved 的證據資格（雙軌，使用者 2026-11-07；docs/DECISIONS.md §28.1）。純函式。

平台只檢查人選擇的依據（basis）的條件是否成立，不替人推斷，也不驗證修補：
- rescan_not_observed：比較中該列是 not_observed（三層覆蓋都成立）。algorithm v1 不會產生
  not_observed，所以這一軌在現行版本不會成立（以 not_observed_required 拒絕）。
- manual_retest：該列是 inconclusive，平台能證明的都成立，未完成的只有 rule_incomplete／
  parameter_unverified；另附人工複測聲明（attestation.py 做一致性檢查）。

兩軌共同：algorithm 版本受支援、整體 comparability 是 comparable（兩個 scan 沒有版本或設定差異）、
該列存在且不需要人工確認、比較的 current 之後沒有再觀察到這個 finding。比較標頭的
manual_review_required 會彙總其他 finding，不拿來判斷這個 finding。所有不符的原因一次列出。
"""

from dataclasses import dataclass
from enum import StrEnum

from secscan.comparisons.domain.classification import (
    Classification,
    ComparisonFacts,
    CoverageEvidence,
    Reason,
)
from secscan.comparisons.domain.comparability import Comparability
from secscan.findings.domain.triage import ResolutionBasis

SUPPORTED_ALGORITHMS = frozenset({1})
MANUAL_RETEST_REASONS = frozenset({Reason.RULE_INCOMPLETE.value, Reason.PARAMETER_UNVERIFIED.value})


class EvidenceProblem(StrEnum):
    ALGORITHM_UNSUPPORTED = "algorithm_unsupported"
    SCANS_NOT_COMPARABLE = "scans_not_comparable"
    FINDING_NOT_IN_COMPARISON = "finding_not_in_comparison"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"
    OBSERVED_AFTER_COMPARISON = "observed_after_comparison"
    NOT_OBSERVED_REQUIRED = "not_observed_required"
    INCONCLUSIVE_REQUIRED = "inconclusive_required"
    BASELINE_NOT_OBSERVED = "baseline_not_observed"
    CURRENT_OBSERVED = "current_observed"
    VERSION_INCOMPARABLE = "version_incomparable"
    FINDING_IDENTITY_UNVERIFIED = "finding_identity_unverified"
    COVERAGE_MISSING = "coverage_missing"
    SCOPE_UNVERIFIED = "scope_unverified"
    ROLE_NOT_COMPARABLE = "role_not_comparable"
    IDENTITY_UNVERIFIED = "identity_unverified"
    SPEC_NOT_COMPARABLE = "spec_not_comparable"
    TELEMETRY_INCOMPLETE = "telemetry_incomplete"
    SOURCES_MISSING = "sources_missing"
    ENGINE_INCOMPLETE = "engine_incomplete"
    TIME_LIMIT_REACHED = "time_limit_reached"
    DEFINITION_NOT_COMPARABLE = "definition_not_comparable"
    LOCATION_UNANSWERED = "location_unanswered"
    REASONS_NOT_ELIGIBLE = "reasons_not_eligible"


@dataclass(frozen=True, slots=True)
class ComparisonRow:
    """比較快照中這個 finding 的那一列（封存後不可修改）。"""

    classification: Classification
    reasons: tuple[str, ...]
    manual_review_required: bool
    facts: ComparisonFacts


@dataclass(frozen=True, slots=True)
class CitedComparison:
    algorithm_version: int
    comparability: Comparability
    row: ComparisonRow | None


def evidence_problems(
    basis: ResolutionBasis, cited: CitedComparison, *, observed_after: bool
) -> tuple[EvidenceProblem, ...]:
    """不符的原因（依固定順序、不重複）；空的代表這個依據的平台條件都成立。"""
    problems: list[EvidenceProblem] = []
    if cited.algorithm_version not in SUPPORTED_ALGORITHMS:
        problems.append(EvidenceProblem.ALGORITHM_UNSUPPORTED)
    if cited.comparability is not Comparability.COMPARABLE:
        problems.append(EvidenceProblem.SCANS_NOT_COMPARABLE)
    if observed_after:
        problems.append(EvidenceProblem.OBSERVED_AFTER_COMPARISON)
    row = cited.row
    if row is None:
        problems.append(EvidenceProblem.FINDING_NOT_IN_COMPARISON)
        return tuple(problems)
    if row.manual_review_required:
        problems.append(EvidenceProblem.MANUAL_REVIEW_REQUIRED)
    if basis is ResolutionBasis.RESCAN_NOT_OBSERVED:
        if row.classification is not Classification.NOT_OBSERVED:
            problems.append(EvidenceProblem.NOT_OBSERVED_REQUIRED)
        return tuple(problems)
    if row.classification is not Classification.INCONCLUSIVE:
        problems.append(EvidenceProblem.INCONCLUSIVE_REQUIRED)
    problems.extend(_fact_problems(row.facts))
    if not set(row.reasons) <= MANUAL_RETEST_REASONS or not row.reasons:
        problems.append(EvidenceProblem.REASONS_NOT_ELIGIBLE)
    return tuple(dict.fromkeys(problems))


def _fact_problems(facts: ComparisonFacts) -> list[EvidenceProblem]:
    checks = (
        (facts.baseline_observed is True, EvidenceProblem.BASELINE_NOT_OBSERVED),
        (facts.current_observed is False, EvidenceProblem.CURRENT_OBSERVED),
        (
            facts.fingerprint_comparable is True and facts.mapping_comparable is True,
            EvidenceProblem.VERSION_INCOMPARABLE,
        ),
        (
            facts.finding_identity_verified is True and not facts.reidentified,
            EvidenceProblem.FINDING_IDENTITY_UNVERIFIED,
        ),
    )
    problems = [problem for valid, problem in checks if not valid]
    if facts.other_scan_coverage is None:
        problems.append(EvidenceProblem.COVERAGE_MISSING)
    else:
        problems.extend(_coverage_problems(facts.other_scan_coverage))
    return problems


def _coverage_problems(coverage: CoverageEvidence) -> list[EvidenceProblem]:
    sources = coverage.sources
    required = set(coverage.required_sources)
    checks = (
        (coverage.in_scope is True, EvidenceProblem.SCOPE_UNVERIFIED),
        (coverage.role_comparable is True, EvidenceProblem.ROLE_NOT_COMPARABLE),
        (coverage.identity_verified is True, EvidenceProblem.IDENTITY_UNVERIFIED),
        (coverage.spec_comparable is True, EvidenceProblem.SPEC_NOT_COMPARABLE),
        (coverage.telemetry_complete is True, EvidenceProblem.TELEMETRY_INCOMPLETE),
        (
            bool(sources) and bool(required) and required == {item.source for item in sources},
            EvidenceProblem.SOURCES_MISSING,
        ),
        (all(item.engine_succeeded is True for item in sources), EvidenceProblem.ENGINE_INCOMPLETE),
        (
            all(item.time_limit_reached is False for item in sources),
            EvidenceProblem.TIME_LIMIT_REACHED,
        ),
        (
            all(item.definition_comparable is True for item in sources),
            EvidenceProblem.DEFINITION_NOT_COMPARABLE,
        ),
        (
            all(item.has_location_response is True for item in sources),
            EvidenceProblem.LOCATION_UNANSWERED,
        ),
    )
    return [problem for valid, problem in checks if not valid]
