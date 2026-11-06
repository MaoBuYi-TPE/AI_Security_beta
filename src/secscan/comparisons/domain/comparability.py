"""scan 層級的複掃條件；逐 finding 的證據仍須另行判斷。"""

from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from secscan.scans.domain.lifecycle import TERMINAL_SCAN_STATUSES, ScanStatus


class ComparisonErrorCode(StrEnum):
    SAME_SCAN = "same_scan"
    TARGET_MISMATCH = "target_mismatch"
    ORDER = "invalid_order"
    NOT_TERMINAL = "scan_not_terminal"


class ComparisonError(ValueError):
    def __init__(self, code: ComparisonErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


class Comparability(StrEnum):
    COMPARABLE = "comparable"
    DIFFERENT = "different"
    NOT_COMPARABLE = "not_comparable"


class ScanReason(StrEnum):
    FIXTURE = "fixture_mismatch"
    PROFILE = "profile_mismatch"
    SCOPE = "scope_mismatch_or_unknown"
    SPEC = "spec_mismatch"
    AUTH_ROLE = "auth_role_mismatch_or_unknown"
    DEFINITIONS = "engine_definitions_mismatch_or_unknown"
    FINGERPRINT = "fingerprint_version_mismatch_or_unknown"
    MAPPING = "mapping_version_mismatch_or_unknown"


@dataclass(frozen=True, slots=True)
class ScanFacts:
    scan_id: UUID
    project_id: UUID
    target_id: UUID
    queue_position: int
    status: ScanStatus
    fixture: bool
    profile: str
    scope_sha256: str | None
    has_spec: bool
    spec_sha256: str | None
    auth_role: str
    definitions: tuple[tuple[str, str | None], ...]
    fingerprint_version: str | None
    mapping_version: str | None
    taxonomy_sha256: str | None


@dataclass(frozen=True, slots=True)
class ScanComparison:
    comparability: Comparability
    reasons: tuple[ScanReason, ...]
    manual_review_required: bool


def compare_scans(baseline: ScanFacts, current: ScanFacts) -> ScanComparison:
    """只比較已結束且具先後關係的同一 target；未知的必要資料不算相等。"""
    _validate_pair(baseline, current)
    hard = tuple(
        reason
        for same, reason in (
            (
                type(baseline.fixture) is bool
                and type(current.fixture) is bool
                and baseline.fixture == current.fixture,
                ScanReason.FIXTURE,
            ),
            (_same_known(baseline.profile, current.profile), ScanReason.PROFILE),
        )
        if not same
    )
    differences = _differences(baseline, current)
    manual = ScanReason.FINGERPRINT in differences or ScanReason.MAPPING in differences
    if hard:
        return ScanComparison(Comparability.NOT_COMPARABLE, hard + differences, manual)
    if differences:
        return ScanComparison(Comparability.DIFFERENT, differences, manual)
    return ScanComparison(Comparability.COMPARABLE, (), False)


def _validate_pair(baseline: ScanFacts, current: ScanFacts) -> None:
    if baseline.scan_id == current.scan_id:
        raise ComparisonError(ComparisonErrorCode.SAME_SCAN)
    if (baseline.project_id, baseline.target_id) != (current.project_id, current.target_id):
        raise ComparisonError(ComparisonErrorCode.TARGET_MISMATCH)
    if (
        type(baseline.queue_position) is not int
        or type(current.queue_position) is not int
        or baseline.queue_position < 1
        or baseline.queue_position >= current.queue_position
    ):
        raise ComparisonError(ComparisonErrorCode.ORDER)
    if (
        baseline.status not in TERMINAL_SCAN_STATUSES
        or current.status not in TERMINAL_SCAN_STATUSES
    ):
        raise ComparisonError(ComparisonErrorCode.NOT_TERMINAL)


def _same_known(first: str | None, second: str | None) -> bool:
    return bool(first) and bool(second) and first == second


def _same_definitions(
    first: tuple[tuple[str, str | None], ...], second: tuple[tuple[str, str | None], ...]
) -> bool:
    first_map, second_map = dict(first), dict(second)
    return (
        bool(first_map)
        and len(first_map) == len(first)
        and len(second_map) == len(second)
        and first_map.keys() == second_map.keys()
        and all(_same_known(first_map[key], second_map[key]) for key in first_map)
    )


def _differences(baseline: ScanFacts, current: ScanFacts) -> tuple[ScanReason, ...]:
    checks = (
        (_same_known(baseline.scope_sha256, current.scope_sha256), ScanReason.SCOPE),
        (_same_spec(baseline, current), ScanReason.SPEC),
        (_same_known(baseline.auth_role, current.auth_role), ScanReason.AUTH_ROLE),
        (_same_definitions(baseline.definitions, current.definitions), ScanReason.DEFINITIONS),
        (
            _same_known(baseline.fingerprint_version, current.fingerprint_version),
            ScanReason.FINGERPRINT,
        ),
        (
            _same_known(baseline.mapping_version, current.mapping_version)
            and _same_known(baseline.taxonomy_sha256, current.taxonomy_sha256),
            ScanReason.MAPPING,
        ),
    )
    return tuple(reason for same, reason in checks if not same)


def _same_spec(baseline: ScanFacts, current: ScanFacts) -> bool:
    if type(baseline.has_spec) is not bool or type(current.has_spec) is not bool:
        return False
    if baseline.has_spec != current.has_spec:
        return False
    if baseline.has_spec:
        return _same_known(baseline.spec_sha256, current.spec_sha256)
    return baseline.spec_sha256 is None and current.spec_sha256 is None
