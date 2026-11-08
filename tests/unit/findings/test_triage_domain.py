"""T21 的人工轉換、自動重開（R1 至 R4）與 resolve 之後需要人工確認的規則。"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.findings.domain.model import LifecycleState, TriageState
from secscan.findings.domain.triage import (
    PROVENANCE_OF_BASIS,
    REQUEST_PROBLEMS,
    EvidenceProvenance,
    ReopenFacts,
    RequestedChange,
    ResolutionBasis,
    ReviewReason,
    TransitionError,
    TransitionProblem,
    TriageStatus,
    plan_manual,
    resolves,
    review_reasons,
    should_reopen,
)

T, L = TriageState, LifecycleState
MAPPING = ("2", "a" * 64)


def status(triage: TriageState = T.UNREVIEWED, lifecycle: LifecycleState = L.OPEN) -> TriageStatus:
    return TriageStatus(triage, lifecycle, 3)


def problem_of(current: TriageStatus, change: RequestedChange) -> TransitionProblem:
    with pytest.raises(TransitionError) as caught:
        plan_manual(current, change)
    return caught.value.problem


@pytest.mark.parametrize("target", [T.CONFIRMED, T.FALSE_POSITIVE, T.ACCEPTED_RISK])
@pytest.mark.parametrize("lifecycle", [L.OPEN, L.REOPENED])
def test_triage_changes_keep_the_lifecycle_and_bump_the_version(
    target: TriageState, lifecycle: LifecycleState
) -> None:
    planned = plan_manual(status(lifecycle=lifecycle), RequestedChange(triage=target))
    assert planned == TriageStatus(target, lifecycle, 4)


@pytest.mark.parametrize("lifecycle", [L.OPEN, L.REOPENED])
def test_only_confirmed_findings_can_be_resolved(lifecycle: LifecycleState) -> None:
    current = status(T.CONFIRMED, lifecycle)
    planned = plan_manual(current, RequestedChange(lifecycle=L.RESOLVED))
    assert planned == TriageStatus(T.CONFIRMED, L.RESOLVED, 4)
    assert resolves(current, planned)
    for triage in (T.UNREVIEWED, T.FALSE_POSITIVE, T.ACCEPTED_RISK):
        assert (
            problem_of(status(triage, lifecycle), RequestedChange(lifecycle=L.RESOLVED))
            is TransitionProblem.NOT_CONFIRMED
        )


def test_accepted_risk_and_false_positive_are_not_repairs() -> None:
    for triage in (T.ACCEPTED_RISK, T.FALSE_POSITIVE):
        planned = plan_manual(status(), RequestedChange(triage=triage))
        assert planned.lifecycle is L.OPEN


def test_manual_reopen_only_from_resolved_and_never_back_to_open() -> None:
    resolved = status(T.CONFIRMED, L.RESOLVED)
    planned = plan_manual(resolved, RequestedChange(lifecycle=L.REOPENED))
    assert planned == TriageStatus(T.CONFIRMED, L.REOPENED, 4)
    assert not resolves(resolved, planned)
    assert problem_of(status(), RequestedChange(lifecycle=L.REOPENED)) is (
        TransitionProblem.NOT_RESOLVED
    )
    for lifecycle in (L.RESOLVED, L.REOPENED):
        assert problem_of(status(T.CONFIRMED, lifecycle), RequestedChange(lifecycle=L.OPEN)) is (
            TransitionProblem.REOPEN_TO_OPEN
        )


def test_triage_cannot_change_while_resolved() -> None:
    resolved = status(T.CONFIRMED, L.RESOLVED)
    assert problem_of(resolved, RequestedChange(triage=T.FALSE_POSITIVE)) is (
        TransitionProblem.TRIAGE_WHILE_RESOLVED
    )


def test_one_change_per_request_and_no_op_requests_are_rejected() -> None:
    both = RequestedChange(triage=T.CONFIRMED, lifecycle=L.RESOLVED)
    assert problem_of(status(), both) is TransitionProblem.MULTIPLE_CHANGES
    assert problem_of(status(), RequestedChange()) is TransitionProblem.NO_CHANGE
    assert problem_of(status(), RequestedChange(triage=T.UNREVIEWED)) is TransitionProblem.NO_CHANGE
    resolved = status(T.CONFIRMED, L.RESOLVED)
    assert problem_of(resolved, RequestedChange(lifecycle=L.RESOLVED)) is (
        TransitionProblem.NO_CHANGE
    )
    # 同值的欄位不算變更：只改另一個欄位仍可以。
    same = RequestedChange(triage=T.CONFIRMED, lifecycle=L.REOPENED)
    assert plan_manual(resolved, same).lifecycle is L.REOPENED
    assert {TransitionProblem.NO_CHANGE, TransitionProblem.MULTIPLE_CHANGES} == REQUEST_PROBLEMS


def test_each_basis_states_who_produced_the_evidence() -> None:
    assert PROVENANCE_OF_BASIS == {
        ResolutionBasis.RESCAN_NOT_OBSERVED: EvidenceProvenance.PLATFORM_COMPARISON,
        ResolutionBasis.MANUAL_RETEST: EvidenceProvenance.OPERATOR_SUPPLIED,
    }


_CHANGES = st.builds(
    RequestedChange,
    triage=st.none() | st.sampled_from(list(T)),
    lifecycle=st.none() | st.sampled_from([L.OPEN, L.REOPENED]),
)


@given(st.lists(_CHANGES, max_size=30))
def test_without_a_resolve_request_no_sequence_reaches_resolved(
    changes: list[RequestedChange],
) -> None:
    """不送出 resolved 的請求，任何人工操作序列都不會到達 resolved（證據門檻之外的保證）。"""
    current = TriageStatus(T.UNREVIEWED, L.OPEN, 0)
    for change in changes:
        try:
            planned = plan_manual(current, change)
        except TransitionError:
            continue
        assert planned.version == current.version + 1
        assert planned.lifecycle is not L.RESOLVED
        current = planned


@given(st.sampled_from(list(T)), st.sampled_from(list(L)), st.integers(0, 10))
def test_resolved_always_requires_confirmed(
    triage: TriageState, lifecycle: LifecycleState, version: int
) -> None:
    current = TriageStatus(triage, lifecycle, version)
    try:
        planned = plan_manual(current, RequestedChange(lifecycle=L.RESOLVED))
    except TransitionError:
        return
    assert planned.triage is T.CONFIRMED


def facts(**changes: object) -> ReopenFacts:
    values: dict[str, object] = {
        "lifecycle": L.RESOLVED,
        "resolved_scan_position": 10,
        "run_scan_position": 11,
        "run_mapping": MAPPING,
        "finding_mapping": MAPPING,
        "new_links": 1,
        **changes,
    }
    return ReopenFacts(**values)  # type: ignore[arg-type]


def test_reopen_requires_all_four_conditions() -> None:
    assert should_reopen(facts())
    for lifecycle in (L.OPEN, L.REOPENED):
        assert not should_reopen(facts(lifecycle=lifecycle))  # R1
    assert not should_reopen(facts(new_links=0))  # R2
    assert not should_reopen(facts(run_scan_position=10))  # R3：舊資料延遲寫入
    assert not should_reopen(facts(run_scan_position=9))
    assert not should_reopen(facts(resolved_scan_position=None))
    assert not should_reopen(facts(run_mapping=("3", "a" * 64)))  # R4
    assert not should_reopen(facts(run_mapping=("2", "b" * 64)))
    assert not should_reopen(facts(run_mapping=None))


def test_review_reasons_only_for_resolved_findings() -> None:
    assert (
        review_reasons(
            L.RESOLVED, observations_linked=5, resolved_link_count=5, later_mapping_differs=False
        )
        == ()
    )
    assert review_reasons(
        L.RESOLVED, observations_linked=6, resolved_link_count=5, later_mapping_differs=True
    ) == (ReviewReason.OBSERVED_AFTER_RESOLUTION, ReviewReason.MAPPING_CHANGED)
    assert review_reasons(
        L.RESOLVED, observations_linked=5, resolved_link_count=5, later_mapping_differs=True
    ) == (ReviewReason.MAPPING_CHANGED,)
    for lifecycle in (L.OPEN, L.REOPENED):
        assert (
            review_reasons(
                lifecycle, observations_linked=9, resolved_link_count=1, later_mapping_differs=True
            )
            == ()
        )
    assert (
        review_reasons(
            L.RESOLVED, observations_linked=9, resolved_link_count=None, later_mapping_differs=True
        )
        == ()
    )
