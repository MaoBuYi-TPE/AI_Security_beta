"""實驗規格的嚴格檢查（BENCH-01；docs/DECISIONS.md §29）。"""

import json
from pathlib import Path
from typing import Any

import pytest

from benchmarks import spec as bench_spec
from benchmarks.spec import (
    ExperimentSpec,
    Purpose,
    SpecError,
    TargetKind,
    check_name,
    load_spec,
    parse_spec,
)
from benchmarks.strict_yaml import MAX_YAML_BYTES, StrictYamlError, load_strict_yaml
from secscan.scans.domain import allocation
from secscan.scans.service import MAX_SCANS_PER_TARGET_PER_DAY

SMOKE = Path(__file__).resolve().parents[3] / "benchmarks" / "experiments" / "t31-smoke.yaml"


def _document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "name": "unit-spec",
        "purpose": "smoke",
        "seed": 7,
        "profile": "web_active_lab",
        "budget": {"requests_per_second": 2, "max_requests": 1200, "max_duration_seconds": 600},
        "groups": [
            {"id": "A", "engines": ["zap"]},
            {"id": "B", "engines": ["nuclei"]},
            {
                "id": "C",
                "engines": ["zap", "nuclei"],
                "engine_budgets": [
                    {"engine": "zap", "max_requests": 760, "max_duration_seconds": 380},
                    {"engine": "nuclei", "max_requests": 440, "max_duration_seconds": 220},
                ],
            },
        ],
        "targets": [{"id": "fixture", "kind": "fixture"}],
        "cells": [{"group": "A", "target": "fixture", "variant": "insecure", "repetitions": 1}],
        "comparisons": [
            {
                "id": "c1",
                "group": "C",
                "target": "fixture",
                "baseline": "insecure",
                "current": "secure",
            }
        ],
    }
    document.update(overrides)
    return document


def _parse(document: dict[str, Any]) -> ExperimentSpec:
    # JSON 也是合法的 YAML；safe_dump 會為重複引用的物件產生別名（嚴格的讀取會拒絕）。
    return parse_spec(json.dumps(document).encode())


def _rejected(document: dict[str, Any], problem: str) -> None:
    with pytest.raises(SpecError, match=problem):
        _parse(document)


def test_the_smoke_spec_is_valid() -> None:
    spec, digest = load_spec(SMOKE)

    assert spec.purpose is Purpose.SMOKE
    assert [group.id for group in spec.groups] == ["A", "B", "C"]
    assert len(digest) == 64
    assert spec.target("fixture").kind is TargetKind.FIXTURE
    assert spec.group("C").engine_budgets is not None


def test_minimum_windows_and_quota_match_the_platform() -> None:
    """benchmarks 不 import secscan：各寫一份，在這裡核對（BUDGET-09 的 harness 版）。"""
    assert bench_spec.ZAP_MIN_SECONDS == allocation.ZAP_MIN_SECONDS
    assert bench_spec.ZAP_MIN_REQUEST_SECONDS == allocation.ZAP_MIN_REQUEST_SECONDS
    assert bench_spec.NUCLEI_MIN_SECONDS == allocation.NUCLEI_MIN_SECONDS
    assert bench_spec.MAX_SCANS_PER_TARGET == MAX_SCANS_PER_TARGET_PER_DAY


@pytest.mark.parametrize(
    ("overrides", "problem"),
    [
        ({"extra": 1}, "extra"),
        ({"profile": "api_active_lab"}, "profile"),
        ({"purpose": "demo"}, "purpose"),
        ({"seed": -1}, "seed"),
        ({"seed": True}, "seed"),
        ({"name": "../escape"}, "name"),
        ({"targets": [{"id": "x", "kind": "http://10.0.0.1"}]}, "kind"),
        ({"targets": [{"id": "x", "kind": "fixture", "url": "http://a"}]}, "url"),
        (
            {"budget": {"requests_per_second": 0, "max_requests": 1, "max_duration_seconds": 1}},
            "requests_per_second",
        ),
        ({"cells": [], "comparisons": []}, "至少要有一個 scan"),
    ],
)
def test_the_schema_is_strict(overrides: dict[str, Any], problem: str) -> None:
    _rejected(_document(**overrides), problem)


def test_the_message_does_not_echo_input_values() -> None:
    with pytest.raises(SpecError) as caught:
        _parse(_document(targets=[{"id": "x", "kind": "http://10.66.77.88"}]))

    assert "10.66.77.88" not in str(caught.value)


def _groups(*groups: dict[str, Any]) -> list[dict[str, Any]]:
    return list(groups)


SHARES = [
    {"engine": "zap", "max_requests": 760, "max_duration_seconds": 380},
    {"engine": "nuclei", "max_requests": 440, "max_duration_seconds": 220},
]


@pytest.mark.parametrize(
    ("group", "problem"),
    [
        ({"id": "C", "engines": ["zap", "zap"]}, "重複"),
        ({"id": "C", "engines": ["fake"]}, "engines"),
        ({"id": "C", "engines": ["zap"], "engine_budgets": SHARES[:1]}, "兩個以上"),
        ({"id": "C", "engines": ["zap", "nuclei"], "engine_budgets": SHARES[:1]}, "各列一次"),
        (
            {"id": "C", "engines": ["zap", "nuclei"], "engine_budgets": [SHARES[0], SHARES[0]]},
            "各列一次",
        ),
        (
            {
                "id": "C",
                "engines": ["zap", "nuclei"],
                "engine_budgets": [{**SHARES[0], "max_requests": 761}, SHARES[1]],
            },
            "合計",
        ),
        (
            {
                "id": "C",
                "engines": ["zap", "nuclei"],
                "engine_budgets": [{**SHARES[0], "max_duration_seconds": 119}, SHARES[1]],
            },
            "zap",
        ),
        (
            {
                "id": "C",
                "engines": ["zap", "nuclei"],
                "engine_budgets": [{**SHARES[0], "max_requests": 239}, SHARES[1]],
            },
            "zap",
        ),
        (
            {
                "id": "C",
                "engines": ["zap", "nuclei"],
                "engine_budgets": [SHARES[0], {**SHARES[1], "max_duration_seconds": 59}],
            },
            "nuclei",
        ),
    ],
)
def test_engine_budgets_follow_the_platform_rules(group: dict[str, Any], problem: str) -> None:
    document = _document(groups=_groups({"id": "A", "engines": ["zap"]}, group))
    document["comparisons"] = [{**document["comparisons"][0], "group": "C"}]

    _rejected(document, problem)


def test_an_experiment_freezes_the_shares_and_they_add_up_to_the_total() -> None:
    unfrozen = _document(
        purpose="experiment",
        groups=[{"id": "A", "engines": ["zap"]}, {"id": "C", "engines": ["zap", "nuclei"]}],
        cells=[{"group": "A", "target": "fixture", "variant": "insecure", "repetitions": 3}],
    )
    _rejected(unfrozen, "必須凍結")

    partial = _document(
        purpose="experiment",
        groups=[
            {"id": "A", "engines": ["zap"]},
            {
                "id": "C",
                "engines": ["zap", "nuclei"],
                "engine_budgets": [SHARES[0], {**SHARES[1], "max_requests": 400}],
            },
        ],
        cells=[{"group": "A", "target": "fixture", "variant": "insecure", "repetitions": 3}],
    )
    _rejected(partial, "等於總預算")


def test_an_experiment_repeats_each_cell_at_least_three_times() -> None:
    _rejected(_document(purpose="experiment"), "至少重複 3 次")


@pytest.mark.parametrize(
    ("overrides", "problem"),
    [
        (
            {
                "cells": [
                    {"group": "Z", "target": "fixture", "variant": "insecure", "repetitions": 1}
                ]
            },
            "組別",
        ),
        (
            {"cells": [{"group": "A", "target": "nope", "variant": "insecure", "repetitions": 1}]},
            "靶場",
        ),
        (
            {
                "targets": [{"id": "juice", "kind": "juice_shop"}],
                "cells": [{"group": "A", "target": "juice", "variant": "secure", "repetitions": 1}],
                "comparisons": [],
            },
            "沒有 secure 版",
        ),
        (
            {
                "cells": [
                    {"group": "A", "target": "fixture", "variant": "insecure", "repetitions": 11}
                ]
            },
            "repetitions",
        ),
        (
            {
                "cells": [
                    {"group": "A", "target": "fixture", "variant": "insecure", "repetitions": 51}
                ]
            },
            "repetitions",
        ),
        (
            {
                "cells": [
                    {"group": "A", "target": "fixture", "variant": "insecure", "repetitions": 1},
                    {"group": "A", "target": "fixture", "variant": "insecure", "repetitions": 2},
                ]
            },
            "cells 的 id 不可重複",
        ),
        (
            {"groups": [{"id": "A", "engines": ["zap"]}, {"id": "A", "engines": ["nuclei"]}]},
            "groups",
        ),
    ],
)
def test_references_variants_and_repetitions_are_checked(
    overrides: dict[str, Any], problem: str
) -> None:
    _rejected(_document(**overrides), problem)


def test_the_platform_quota_per_group_and_target_is_respected() -> None:
    cells = [
        {"group": "A", "target": "fixture", "variant": variant, "repetitions": 10}
        for variant in ("insecure", "secure")
    ]
    many = [
        {
            "id": f"c{i}",
            "group": "A",
            "target": "fixture",
            "baseline": "insecure",
            "current": "secure",
        }
        for i in range(16)
    ]

    _rejected(_document(cells=cells, comparisons=many), "quota")


@pytest.mark.parametrize("name", ["t31-smoke", "A_1", "x" * 64])
def test_result_names_are_plain(name: str) -> None:
    assert check_name(name) == name


@pytest.mark.parametrize("name", ["", "x" * 65, "../x", "a/b", "a b", "名稱", ".hidden"])
def test_result_names_with_paths_or_other_characters_are_rejected(name: str) -> None:
    with pytest.raises(SpecError, match="BENCH_NAME"):
        check_name(name)


# --- 嚴格的 YAML --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "problem"),
    [
        (b"a: 1\na: 2\n", "重複的鍵"),
        (b"base: &x {b: 1}\nother: *x\n", "別名"),
        (b"? [1, 2]\n: value\n", "字串"),
        (b"1: value\n", "字串"),
        (b"a: [\n", "語法"),
        (b"a: 1\n---\nb: 2\n", "語法"),
        ("a: \udcff".encode("utf-8", "surrogateescape"), "UTF-8"),
        (b"a: " + b"x" * MAX_YAML_BYTES, "超過"),
    ],
)
def test_strict_yaml_rejects_ambiguous_documents(content: bytes, problem: str) -> None:
    with pytest.raises(StrictYamlError, match=problem):
        load_strict_yaml(content)


def test_strict_yaml_rejects_duplicate_keys_in_nested_mappings() -> None:
    with pytest.raises(StrictYamlError, match="重複的鍵"):
        load_strict_yaml(b"outer:\n  inner: 1\n  inner: 2\n")


def test_strict_yaml_loads_plain_documents() -> None:
    assert load_strict_yaml(b"a: 1\nb: [x, y]\nc: {d: true}\n") == {
        "a": 1,
        "b": ["x", "y"],
        "c": {"d": True},
    }


def test_a_spec_must_be_a_mapping() -> None:
    with pytest.raises(SpecError, match="mapping"):
        parse_spec(b"- 1\n- 2\n")


def test_yaml_errors_become_spec_errors() -> None:
    with pytest.raises(SpecError, match="重複的鍵"):
        parse_spec(b"name: a\nname: b\n")
