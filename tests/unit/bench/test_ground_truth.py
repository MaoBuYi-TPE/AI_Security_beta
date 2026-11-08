"""ground truth 與人工標記的格式（BENCH-05 的輸入；T27 撰寫正式的比對檔）。"""

import json
from pathlib import Path
from typing import Any

import pytest

from benchmarks.ground_truth import (
    Matcher,
    TruthError,
    load_adjudications,
    load_ground_truth,
    load_pair_labels,
)
from benchmarks.models import Signature
from tests.unit.bench.records import SQLI, TRUTH


def _write(tmp_path: Path, document: object, name: str = "x.yaml") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _cases(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(json.dumps(TRUTH))
    document["cases"][0].update(changes)
    return document


def test_a_ground_truth_is_loaded_with_its_digest(tmp_path: Path) -> None:
    truth, digest = load_ground_truth(_write(tmp_path, TRUTH))

    assert truth.target.value == "fixture"
    assert len(truth.cases) == len(TRUTH["cases"])
    assert len(digest) == 64


@pytest.mark.parametrize(
    ("document", "problem"),
    [
        ({**TRUTH, "version": 2}, "version"),
        ({**TRUTH, "extra": 1}, "extra"),
        ({**TRUTH, "cases": []}, "cases"),
        (_cases(matchers=[]), "比對條件"),
        (_cases(present_in=[]), "present_in"),
        (_cases(present_in=["insecure", "insecure"]), "不可重複"),
        (_cases(holdout="no"), "holdout"),
        (_cases(id="../x"), "id"),
        ({**TRUTH, "cases": [TRUTH["cases"][0], TRUTH["cases"][0]]}, "id 不可重複"),
        (_cases(matchers=[{"rule_group": "xss-reflected", "route": "/greet"}]), "相同的比對條件"),
        (_cases(matchers=[{"rule_group": "x", "parameter_location": []}]), "parameter_location"),
        ([1, 2], "dictionary"),
    ],
)
def test_the_ground_truth_is_strict(tmp_path: Path, document: object, problem: str) -> None:
    with pytest.raises(TruthError, match=problem):
        load_ground_truth(_write(tmp_path, document))


def test_duplicate_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "x.yaml"
    path.write_text("version: 1\nversion: 1\n", encoding="utf-8")

    with pytest.raises(TruthError, match="重複的鍵"):
        load_ground_truth(path)


@pytest.mark.parametrize(
    ("matcher", "matches"),
    [
        ({"rule_group": "sql-injection"}, True),
        ({"rule_group": "sql-injection", "route": "/search", "method": "GET"}, True),
        ({"rule_group": "sql-injection", "parameter_location": ["unknown", "query"]}, True),
        ({"rule_group": "sql-injection", "parameter_location": ["body"]}, False),
        ({"rule_group": "sql-injection", "parameter_name": "term"}, False),
        ({"rule_group": "sql-injection", "method": "POST"}, False),
        ({"rule_group": "xss-reflected"}, False),
    ],
)
def test_a_matcher_needs_every_given_field(matcher: dict[str, Any], matches: bool) -> None:
    assert Matcher.model_validate(matcher).matches(SQLI) is matches


def test_a_matcher_with_a_location_list_accepts_a_missing_location() -> None:
    """FX-03 這類案例：parser 可能給 unknown 或 body，兩者都列出來。"""
    signature = Signature("sql-injection", "POST", "/login", None, None)

    assert not Matcher(rule_group="sql-injection", parameter_location=("body",)).matches(signature)
    assert Matcher(rule_group="sql-injection").matches(signature)


ADJUDICATION = {
    "target": "fixture",
    "variant": "insecure",
    "finding": {"rule_group": "zap:10202", "method": "GET", "route": "/form"},
    "label": "false_positive",
    "issue": "CSRF",
}


def test_adjudications_are_loaded(tmp_path: Path) -> None:
    labels, digest = load_adjudications(_write(tmp_path, {"version": 1, "items": [ADJUDICATION]}))

    assert labels.items[0].finding.signature() == Signature("zap:10202", "GET", "/form", None, None)
    assert len(digest) == 64


@pytest.mark.parametrize(
    ("items", "problem"),
    [
        ([{**ADJUDICATION, "issue": None}], "issue"),
        ([{**ADJUDICATION, "label": "not_security"}], "issue"),
        ([ADJUDICATION, {**ADJUDICATION, "issue": "OTHER"}], "只能裁定一次"),
        ([{**ADJUDICATION, "label": "maybe"}], "label"),
    ],
)
def test_adjudications_are_strict(tmp_path: Path, items: list[Any], problem: str) -> None:
    with pytest.raises(TruthError, match=problem):
        load_adjudications(_write(tmp_path, {"version": 1, "items": items}))


def test_pair_labels_are_loaded(tmp_path: Path) -> None:
    finding = {"rule_group": "security-headers", "method": "GET", "route": "/"}
    document = {
        "version": 1,
        "complete": True,
        "merged": [{"target": "fixture", "finding": finding, "correct": True}],
        "missed": [{"target": "fixture", "first": finding, "second": {**finding, "route": "/x"}}],
    }

    labels, _ = load_pair_labels(_write(tmp_path, document))

    assert labels.complete is True
    assert labels.merged[0].correct is True


def test_pair_labels_need_the_complete_flag(tmp_path: Path) -> None:
    with pytest.raises(TruthError, match="complete"):
        load_pair_labels(_write(tmp_path, {"version": 1}))
