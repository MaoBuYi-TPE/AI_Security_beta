"""凍結的 DB 來源摘要仍需驗證；缺失及不正確的資料不能成為可比較定義。"""

import hashlib
import json
from dataclasses import replace

import pytest
from tests.unit.comparisons.test_provenance import ENGINE

from secscan.comparisons.inputs import _components, _definition, _time_limit
from secscan.scans.models import ScannerRunModel


def run(**overrides: object) -> ScannerRunModel:
    rules = ["active:40018", "passive-addon:pscanrules:71"]
    return ScannerRunModel(
        **{
            "engine": ENGINE.engine,
            "image_ref": ENGINE.image_ref,
            "engine_version": ENGINE.engine_version,
            "parser_version": ENGINE.parser_version,
            "profile_definition_sha256": ENGINE.profile_definition_sha256,
            "rule_set": rules,
            "rule_set_sha256": hashlib.sha256(
                json.dumps(rules, separators=(",", ":")).encode()
            ).hexdigest(),
            "status": "succeeded",
            "result_details": {
                "components": {"pscanrules": "71"},
                "time_limit_reached": False,
                "guard_traffic": {"exhausted": False},
            },
            **overrides,
        }
    )


def test_complete_stored_engine_facts_match_the_pure_definition() -> None:
    from secscan.comparisons.domain.provenance import definition_digest

    row = run()
    assert _definition(row) == definition_digest(
        replace(
            ENGINE,
            rule_set_sha256=row.rule_set_sha256,
            components=(("pscanrules", "71"),),
        )
    )


@pytest.mark.parametrize("rules", [None, [], [42], ["b", "a"], ["a", "a"]])
def test_invalid_rule_sets_do_not_create_a_definition(rules: object) -> None:
    assert _definition(run(rule_set=rules)) is None


def test_rule_set_digest_must_match_the_canonical_contents() -> None:
    assert _definition(run(rule_set_sha256="d" * 64)) is None


@pytest.mark.parametrize("components", [None, [], {"pscanrules": 71}])
def test_unknown_or_nonstring_component_versions_are_unknown(components: object) -> None:
    assert _components(run(result_details={"components": components})) is None


def test_explicitly_empty_components_are_known_unlike_missing_components() -> None:
    assert _components(run(result_details={"components": {}})) == ()
    assert _components(run(result_details=None)) is None


@pytest.mark.parametrize(
    ("details", "status", "expected"),
    [
        (None, "failed", None),
        ({}, "succeeded", None),
        ({"time_limit_reached": False}, "succeeded", None),
        ({"time_limit_reached": False, "guard_traffic": {"exhausted": False}}, "succeeded", False),
        ({"time_limit_reached": True}, "succeeded", True),
        ({"guard_traffic": {"exhausted": True}}, "succeeded", True),
        ({"time_limit_reached": False}, "timed_out", True),
        ({"time_limit_reached": 0, "guard_traffic": {"exhausted": 0}}, "succeeded", None),
    ],
)
def test_time_limit_requires_explicit_negative_evidence(
    details: object,
    status: str,
    expected: bool | None,
) -> None:
    assert _time_limit(run(result_details=details, status=status)) is expected
