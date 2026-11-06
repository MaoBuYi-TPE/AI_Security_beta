"""保守的逐 finding 複掃分類（T22）。

輸入只接受上游已驗證的證據結論：轉送請求、matcher 事件或 passive job 結束本身不等於
``rule_completed``。每個 baseline 來源都必須通過；不存在可證明的來源時一律 inconclusive。
not_observed 只描述這次比較，與人工認定 resolved 無關。
"""

from dataclasses import dataclass
from enum import StrEnum


class Classification(StrEnum):
    PERSISTENT = "persistent"
    NEW = "new"
    NOT_OBSERVED = "not_observed"
    INCONCLUSIVE = "inconclusive"
    NOT_COMPARABLE = "not_comparable"


class Reason(StrEnum):
    COVERAGE_VERIFIED = "coverage_verified"
    FINGERPRINT_VERSION = "fingerprint_version_mismatch"
    MAPPING_VERSION = "mapping_version_mismatch"
    REIDENTIFIED = "reidentified"
    COVERAGE_MISSING = "coverage_missing"
    OUT_OF_SCOPE = "out_of_scope"
    SCOPE_UNKNOWN = "scope_unknown"
    ROLE_MISMATCH = "auth_role_mismatch"
    ROLE_UNKNOWN = "auth_role_unknown"
    IDENTITY_UNVERIFIED = "identity_unverified"
    FINDING_IDENTITY_UNVERIFIED = "finding_identity_unverified"
    SPEC_MISMATCH = "spec_mismatch"
    TELEMETRY_INCOMPLETE = "telemetry_incomplete"
    SOURCES_MISSING = "sources_missing"
    SOURCE_MISMATCH = "source_mismatch"
    ENGINE_INCOMPLETE = "engine_incomplete"
    TIME_LIMIT_REACHED = "time_limit_reached"
    DEFINITION_MISMATCH = "engine_definition_mismatch"
    LOCATION_UNANSWERED = "location_unanswered"
    RULE_INCOMPLETE = "rule_incomplete"
    PARAMETER_UNVERIFIED = "parameter_unverified"


@dataclass(frozen=True, slots=True)
class SourceRef:
    """原始觀察的來源識別，不以規則名稱、CWE 或相似文字猜測。"""

    engine: str
    rule_id: str
    variant: str | None


@dataclass(frozen=True, slots=True)
class RuleEvidence:
    """某個 finding 來源在另一個 scan 的覆蓋結論，不含原始請求或參數值。"""

    source: SourceRef
    engine_succeeded: bool
    time_limit_reached: bool | None
    definition_comparable: bool
    has_location_response: bool
    rule_completed: bool
    parameter_comparable: bool


@dataclass(frozen=True, slots=True)
class CoverageEvidence:
    in_scope: bool | None
    role_comparable: bool | None
    identity_verified: bool
    spec_comparable: bool
    telemetry_complete: bool
    required_sources: tuple[SourceRef, ...]
    sources: tuple[RuleEvidence, ...]


@dataclass(frozen=True, slots=True)
class ComparisonFacts:
    baseline_observed: bool
    current_observed: bool
    fingerprint_comparable: bool
    mapping_comparable: bool
    finding_identity_verified: bool
    other_scan_coverage: CoverageEvidence | None
    reidentified: bool


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    classification: Classification
    reasons: tuple[Reason, ...] = ()
    manual_review_required: bool = False


def classify(facts: ComparisonFacts) -> ClassificationResult:
    """輸入是同一 finding 及其反向 scan 的證據；沒有可信覆蓋時不推定 new 或 not_observed。"""
    if type(facts.baseline_observed) is not bool or type(facts.current_observed) is not bool:
        raise ValueError("觀察狀態必須明確")
    if type(facts.reidentified) is not bool:
        raise ValueError("重新識別狀態必須明確")
    if not facts.baseline_observed and not facts.current_observed:
        raise ValueError("finding 必須至少出現在一次 scan")
    version_reasons = _version_reasons(facts)
    if version_reasons:
        return ClassificationResult(Classification.INCONCLUSIVE, version_reasons, True)
    if facts.baseline_observed and facts.current_observed:
        return ClassificationResult(Classification.PERSISTENT)
    if facts.reidentified:
        return ClassificationResult(Classification.INCONCLUSIVE, (Reason.REIDENTIFIED,), True)
    if facts.finding_identity_verified is not True:
        return ClassificationResult(
            Classification.INCONCLUSIVE, (Reason.FINDING_IDENTITY_UNVERIFIED,)
        )
    if facts.other_scan_coverage is None:
        return ClassificationResult(Classification.INCONCLUSIVE, (Reason.COVERAGE_MISSING,))
    evidence = facts.other_scan_coverage
    reasons = _coverage_reasons(evidence)
    if Reason.OUT_OF_SCOPE in reasons or Reason.ROLE_MISMATCH in reasons:
        return ClassificationResult(Classification.NOT_COMPARABLE, reasons)
    if reasons:
        return ClassificationResult(Classification.INCONCLUSIVE, reasons)
    outcome = Classification.NOT_OBSERVED if facts.baseline_observed else Classification.NEW
    return ClassificationResult(outcome, (Reason.COVERAGE_VERIFIED,))


def _version_reasons(facts: ComparisonFacts) -> tuple[Reason, ...]:
    return tuple(
        reason
        for valid, reason in (
            (facts.fingerprint_comparable is True, Reason.FINGERPRINT_VERSION),
            (facts.mapping_comparable is True, Reason.MAPPING_VERSION),
        )
        if not valid
    )


def _coverage_reasons(evidence: CoverageEvidence) -> tuple[Reason, ...]:
    checks = (
        (evidence.in_scope is not False, Reason.OUT_OF_SCOPE),
        (evidence.in_scope is True or evidence.in_scope is False, Reason.SCOPE_UNKNOWN),
        (evidence.role_comparable is not False, Reason.ROLE_MISMATCH),
        (
            evidence.role_comparable is True or evidence.role_comparable is False,
            Reason.ROLE_UNKNOWN,
        ),
        (evidence.identity_verified is True, Reason.IDENTITY_UNVERIFIED),
        (evidence.spec_comparable is True, Reason.SPEC_MISMATCH),
        (evidence.telemetry_complete is True, Reason.TELEMETRY_INCOMPLETE),
        (bool(evidence.required_sources) and bool(evidence.sources), Reason.SOURCES_MISSING),
        (_sources_match(evidence), Reason.SOURCE_MISMATCH),
        (
            all(source.engine_succeeded is True for source in evidence.sources),
            Reason.ENGINE_INCOMPLETE,
        ),
        (
            all(source.time_limit_reached is False for source in evidence.sources),
            Reason.TIME_LIMIT_REACHED,
        ),
        (
            all(source.definition_comparable is True for source in evidence.sources),
            Reason.DEFINITION_MISMATCH,
        ),
        (
            all(source.has_location_response is True for source in evidence.sources),
            Reason.LOCATION_UNANSWERED,
        ),
        (all(source.rule_completed is True for source in evidence.sources), Reason.RULE_INCOMPLETE),
        (
            all(source.parameter_comparable is True for source in evidence.sources),
            Reason.PARAMETER_UNVERIFIED,
        ),
    )
    return tuple(reason for valid, reason in checks if not valid)


def _sources_match(evidence: CoverageEvidence) -> bool:
    required = evidence.required_sources
    actual = tuple(source.source for source in evidence.sources)
    return (
        all(source.engine.strip() and source.rule_id.strip() for source in required)
        and len(required) == len(set(required))
        and len(actual) == len(set(actual))
        and set(required) == set(actual)
    )
