"""T22：scan 層級比較條件與錯誤，缺少版本不能被視為相等。"""

from dataclasses import replace
from uuid import UUID

import pytest

from secscan.comparisons.domain.comparability import (
    Comparability,
    ComparisonError,
    ComparisonErrorCode,
    ScanFacts,
    compare_scans,
)
from secscan.scans.domain.lifecycle import ScanStatus

BASE = ScanFacts(
    scan_id=UUID("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"),
    project_id=UUID("0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"),
    target_id=UUID("3c4d5e6f-7081-4293-a4b5-c6d7e8f90a1b"),
    queue_position=41,
    status=ScanStatus.COMPLETED,
    fixture=False,
    profile="web_active_lab",
    scope_sha256="scope-v1",
    has_spec=False,
    spec_sha256=None,
    auth_role="anonymous",
    definitions=(("zap", "definition-v1"),),
    fingerprint_version="v2",
    mapping_version="mapping-v1",
    taxonomy_sha256="b" * 64,
)
CURRENT = replace(
    BASE,
    scan_id=UUID("7f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"),
    queue_position=42,
)


def test_identical_terminal_scans_are_comparable() -> None:
    result = compare_scans(BASE, CURRENT)
    assert result.comparability is Comparability.COMPARABLE
    assert not result.reasons
    assert not result.manual_review_required


@pytest.mark.parametrize(
    ("current", "code"),
    [
        (replace(CURRENT, scan_id=BASE.scan_id), ComparisonErrorCode.SAME_SCAN),
        (replace(CURRENT, target_id=UUID(int=4)), ComparisonErrorCode.TARGET_MISMATCH),
        (replace(CURRENT, project_id=UUID(int=5)), ComparisonErrorCode.TARGET_MISMATCH),
        (
            replace(CURRENT, queue_position=40),
            ComparisonErrorCode.ORDER,
        ),
        (replace(CURRENT, status=ScanStatus.RUNNING), ComparisonErrorCode.NOT_TERMINAL),
    ],
)
def test_invalid_scan_pairs_are_rejected(current: ScanFacts, code: ComparisonErrorCode) -> None:
    with pytest.raises(ComparisonError) as exc:
        compare_scans(BASE, current)
    assert exc.value.code is code


@pytest.mark.parametrize(
    "current", [replace(CURRENT, fixture=True), replace(CURRENT, profile="api_active_lab")]
)
def test_fixture_or_profile_mismatch_is_not_comparable(current: ScanFacts) -> None:
    result = compare_scans(BASE, current)
    assert result.comparability is Comparability.NOT_COMPARABLE
    assert result.reasons


@pytest.mark.parametrize(
    "current",
    [
        replace(CURRENT, scope_sha256="different"),
        replace(CURRENT, scope_sha256=None),
        replace(CURRENT, spec_sha256="different"),
        replace(CURRENT, auth_role="operator"),
        replace(CURRENT, definitions=(("zap", "changed"),)),
        replace(CURRENT, definitions=(("zap", None),)),
    ],
)
def test_different_or_unknown_conditions_are_reported(current: ScanFacts) -> None:
    result = compare_scans(BASE, current)
    assert result.comparability is Comparability.DIFFERENT
    assert result.reasons


@pytest.mark.parametrize(
    "current",
    [
        replace(CURRENT, fingerprint_version="v1"),
        replace(CURRENT, mapping_version="other"),
        replace(CURRENT, fingerprint_version=None),
        replace(CURRENT, mapping_version=None),
    ],
)
def test_unknown_or_changed_mapping_requires_manual_review(current: ScanFacts) -> None:
    result = compare_scans(BASE, current)
    assert result.comparability is Comparability.DIFFERENT
    assert result.manual_review_required
    assert result.reasons


def test_two_unknown_definitions_are_not_considered_equal() -> None:
    baseline = replace(BASE, definitions=(("zap", None),))
    current = replace(CURRENT, definitions=(("zap", None),))
    assert compare_scans(baseline, current).comparability is Comparability.DIFFERENT


def test_two_missing_spec_hashes_are_not_equal_when_specs_exist() -> None:
    baseline = replace(BASE, has_spec=True, spec_sha256=None)
    current = replace(CURRENT, has_spec=True, spec_sha256=None)
    assert compare_scans(baseline, current).comparability is Comparability.DIFFERENT


def test_ambiguous_fixture_state_does_not_become_comparable() -> None:
    baseline = replace(BASE, fixture=None)  # type: ignore[arg-type]
    current = replace(CURRENT, fixture=None)  # type: ignore[arg-type]
    assert compare_scans(baseline, current).comparability is Comparability.NOT_COMPARABLE


def test_equal_or_unknown_queue_position_does_not_prove_order() -> None:
    for position in (0, BASE.queue_position):
        with pytest.raises(ComparisonError) as exc:
            compare_scans(BASE, replace(CURRENT, queue_position=position))
        assert exc.value.code is ComparisonErrorCode.ORDER


@pytest.mark.parametrize(
    ("baseline", "current"),
    [
        (BASE, replace(CURRENT, has_spec=True, spec_sha256="spec-v1")),
        (replace(BASE, has_spec=True, spec_sha256="spec-v1"), CURRENT),
        (replace(BASE, has_spec=None), CURRENT),  # type: ignore[arg-type]
        (BASE, replace(CURRENT, has_spec=0)),  # type: ignore[arg-type]
    ],
)
def test_added_removed_or_ambiguous_spec_is_not_comparable(
    baseline: ScanFacts, current: ScanFacts
) -> None:
    result = compare_scans(baseline, current)
    assert result.comparability is Comparability.DIFFERENT
    assert result.reasons == ("spec_mismatch",)
