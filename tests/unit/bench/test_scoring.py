"""資源、完成度、覆蓋與去重（BENCH-07、08；SECURITY_AND_TESTING.md §6、§7.2、§7.3）。"""

import pytest

from benchmarks.ground_truth import PairLabels
from benchmarks.metrics import NotAvailable, Ratio
from benchmarks.models import RunRecord, Signature
from benchmarks.scoring import InconsistentScanError, coverage, resources, score_dedup
from tests.unit.bench.records import CSP, SQLI, XCTO, capped, finding, labeled, run, scan


def test_resources_are_the_guard_counts_summed_over_started_runs() -> None:
    record = scan(
        runs=(
            capped(run("zap", requests_sent=700, requests_denied=4, traffic_seconds=375), 760, 380),
            run("nuclei", requests_sent=200, requests_denied=0, traffic_seconds=221),
        )
    )

    usage = resources(record)

    assert (usage.requests_sent, usage.requests_denied, usage.traffic_seconds) == (900, 4, 596)
    assert usage.wall_seconds == 630.0
    assert usage.runs[0].cap == (760, 380)
    assert usage.runs[1].cap is None


def test_runs_that_never_started_a_container_are_not_counted() -> None:
    record = scan(
        runs=(
            run("zap"),
            run(
                "nuclei",
                status="failed",
                error_code="BUDGET_EXHAUSTED",
                requests_allotted=None,
                seconds_allotted=None,
                requests_sent=None,
                requests_denied=None,
                traffic_seconds=None,
            ),
        )
    )

    assert resources(record).requests_sent == 100


def test_an_unknown_count_makes_the_total_unknown() -> None:
    record = scan(runs=(run("zap", requests_sent=None), run("nuclei")))

    usage = resources(record)

    assert usage.requests_sent is None
    assert usage.traffic_seconds == 240


def test_a_scan_that_has_not_finished_has_no_wall_time() -> None:
    assert resources(scan(finished_at=None)).wall_seconds is None


@pytest.mark.parametrize(
    ("record", "requests_bound", "time_bound"),
    [
        (run("zap"), False, False),
        (run("zap", guard_exhausted=True, requests_sent=10), True, False),
        (run("zap", requests_sent=600), True, False),
        (run("zap", time_limit_reached=True), False, True),
        (run("nuclei", error_code="TIME_LIMIT_EXCEEDED", status="timed_out"), False, True),
        (run("zap", error_code="ENGINE_TIMEOUT", status="timed_out"), False, True),
        (run("nuclei", requests_sent=None, guard_exhausted=None), None, False),
    ],
)
def test_which_limit_bound_a_run(
    record: RunRecord, requests_bound: bool | None, time_bound: bool
) -> None:
    [usage] = resources(scan(runs=(record,))).runs

    assert (usage.requests_bound, usage.time_bound) == (requests_bound, time_bound)


def test_coverage_needs_a_measurement() -> None:
    assert coverage(scan()) == NotAvailable("coverage_not_measured")
    assert coverage(
        scan(coverage_measured=True, eligible_operations=10, observed_operations=4)
    ) == Ratio(4, 10)
    assert coverage(
        scan(coverage_measured=True, eligible_operations=0, observed_operations=0)
    ) == NotAvailable("no_eligible_operations")
    assert coverage(
        scan(coverage_measured=True, eligible_operations=None, observed_operations=None)
    ) == (NotAvailable("coverage_not_measured"))


# --- 去重（§7.2）-----------------------------------------------------------------------------


def _labels(
    *,
    complete: bool,
    merged: dict[Signature, bool],
    missed: tuple[tuple[Signature, Signature], ...] = (),
) -> PairLabels:
    def signature(sig: Signature) -> dict[str, object]:
        return {
            "rule_group": sig.rule_group,
            "method": sig.method,
            "route": sig.route,
            "parameter_location": sig.parameter_location,
            "parameter_name": sig.parameter_name,
        }

    return PairLabels.model_validate(
        {
            "version": 1,
            "complete": complete,
            "merged": [
                {"target": "fixture", "finding": signature(sig), "correct": correct}
                for sig, correct in merged.items()
            ],
            "missed": [
                {"target": "fixture", "first": signature(a), "second": signature(b)}
                for a, b in missed
            ],
        }
    )


def test_compression_is_only_the_list_getting_shorter() -> None:
    record = scan(finding(XCTO, "zap", "nuclei", observations=3), finding(SQLI, observations=3))

    dedup = score_dedup(labeled(record), None)

    assert (dedup.findings, dedup.observations) == (2, 6)
    assert dedup.compression == Ratio(4, 6)
    assert dedup.merged_findings == 1
    assert dedup.merge_precision == NotAvailable("unlabeled_merges")
    assert dedup.merge_recall == NotAvailable("pair_labels_incomplete")


def test_merges_are_judged_by_the_labels() -> None:
    record = scan(finding(XCTO, "zap", "nuclei"), finding(CSP, "zap", "nuclei"), finding(SQLI))

    dedup = score_dedup(labeled(record), _labels(complete=True, merged={XCTO: True, CSP: False}))

    assert dedup.merge_precision == Ratio(1, 2)
    assert dedup.false_merges == (CSP,)
    assert dedup.merge_recall == Ratio(1, 1)


def test_missed_merges_lower_the_recall_when_the_labels_are_complete() -> None:
    other = Signature("sql-injection", "GET", "/search", "query", "term")
    record = scan(finding(XCTO, "zap", "nuclei"), finding(SQLI), finding(other))
    labels = _labels(complete=True, merged={XCTO: True}, missed=((SQLI, other), (SQLI, CSP)))

    dedup = score_dedup(labeled(record), labels)

    assert dedup.missed_merges == 1
    assert dedup.merge_recall == Ratio(1, 2)


def test_recall_is_not_available_without_complete_labels() -> None:
    record = scan(finding(XCTO, "zap", "nuclei"))

    dedup = score_dedup(labeled(record), _labels(complete=False, merged={XCTO: True}))

    assert dedup.merge_precision == Ratio(1, 1)
    assert dedup.merge_recall == NotAvailable("pair_labels_incomplete")


def test_labels_for_another_target_do_not_apply() -> None:
    record = scan(finding(XCTO, "zap", "nuclei"))

    dedup = score_dedup(
        labeled(record, target_kind="vampi"), _labels(complete=True, merged={XCTO: True})
    )

    assert dedup.merge_precision == NotAvailable("unlabeled_merges")


def test_no_merges_and_no_observations_are_not_available() -> None:
    dedup = score_dedup(labeled(scan(observation_count=0)), _labels(complete=True, merged={}))

    assert dedup.merge_precision == NotAvailable("no_merges")
    assert dedup.merge_recall == NotAvailable("nothing_to_merge")
    assert dedup.compression == NotAvailable("no_observations")


def test_more_findings_than_observations_is_inconsistent() -> None:
    record = scan(finding(SQLI), finding(CSP), observation_count=1)

    with pytest.raises(InconsistentScanError, match="不一致"):
        score_dedup(labeled(record), None)
