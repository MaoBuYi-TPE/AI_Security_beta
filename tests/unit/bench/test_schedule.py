"""執行順序（BENCH-02）：由種子決定；比較區塊整塊移動、baseline 在前。"""

import json
from collections import Counter
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from benchmarks.schedule import ScheduledScan, build_schedule
from benchmarks.spec import ExperimentSpec, Variant, parse_spec


def _spec(seed: int, *, repetitions: int = 3, blocks: int = 2) -> ExperimentSpec:
    document: dict[str, Any] = {
        "name": "unit-schedule",
        "purpose": "smoke",
        "seed": seed,
        "profile": "web_active_lab",
        "budget": {"requests_per_second": 2, "max_requests": 1200, "max_duration_seconds": 600},
        "groups": [
            {"id": "A", "engines": ["zap"]},
            {"id": "B", "engines": ["nuclei"]},
            {"id": "C", "engines": ["zap", "nuclei"]},
        ],
        "targets": [{"id": "fixture", "kind": "fixture"}, {"id": "vampi", "kind": "vampi"}],
        "cells": [
            {"group": group, "target": target, "variant": "insecure", "repetitions": repetitions}
            for group in ("A", "B", "C")
            for target in ("fixture", "vampi")
        ],
        "comparisons": [
            {
                "id": f"c{index}",
                "group": "C",
                "target": "fixture",
                "baseline": "insecure",
                "current": "secure",
            }
            for index in range(blocks)
        ],
    }
    return parse_spec(json.dumps(document).encode())


def _scans(schedule: tuple[ScheduledScan, ...]) -> Counter[tuple[str, str, str, int | None]]:
    return Counter((s.group, s.target, s.variant.value, s.repetition) for s in schedule)


def test_the_same_seed_gives_the_same_order() -> None:
    assert build_schedule(_spec(31)) == build_schedule(_spec(31))


def test_another_seed_gives_another_order_of_the_same_scans() -> None:
    first, second = build_schedule(_spec(1)), build_schedule(_spec(2))

    assert [s.unit for s in first] != [s.unit for s in second]
    assert _scans(first) == _scans(second)


def test_every_repetition_and_block_is_scheduled_once() -> None:
    schedule = build_schedule(_spec(5, repetitions=3, blocks=2))

    assert len(schedule) == 3 * 2 * 3 + 2 * 2
    assert [s.position for s in schedule] == list(range(1, len(schedule) + 1))
    cells = [s for s in schedule if s.comparison is None]
    assert len({s.unit for s in cells}) == len(cells)
    assert all(s.role is None and s.repetition is not None for s in cells)


@settings(max_examples=50)
@given(st.integers(min_value=0, max_value=2**32 - 1))
def test_comparison_blocks_stay_together_with_the_baseline_first(seed: int) -> None:
    schedule = build_schedule(_spec(seed, repetitions=1, blocks=3))

    for index, scan in enumerate(schedule):
        if scan.role == "baseline":
            current = schedule[index + 1]
            assert (current.comparison, current.role) == (scan.comparison, "current")
            assert (scan.variant, current.variant) == (Variant.INSECURE, Variant.SECURE)
            assert current.unit == scan.unit
            assert scan.repetition is None
    assert Counter(s.role for s in schedule)["baseline"] == 3


@settings(max_examples=50)
@given(st.integers(min_value=0, max_value=2**32 - 1))
def test_the_order_is_a_permutation_for_any_seed(seed: int) -> None:
    schedule = build_schedule(_spec(seed, repetitions=2, blocks=1))

    assert _scans(schedule) == _scans(build_schedule(_spec(0, repetitions=2, blocks=1)))
