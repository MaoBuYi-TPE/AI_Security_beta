"""rule_groups.yaml 和真實工具輸出的契約（T19；docs/DECISIONS.md §25.3）。

不連網、不碰 Docker 與 DB。

- Nuclei 的成員是凍結的 42 個模板之一，variant 是該模板中具名的 matcher／extractor。
- 群組審查後的 CWE 必須是成員工具自己回報的 CWE 之一（Nuclei 的模板分類、ZAP 在 golden fixture 中的
  cweid）：不為了對應 OWASP 改 CWE。ZAP 規則只在 gitignore 的錄製中出現過的（10055-13、20019-1、
  40003、40012、40018、6-5），CWE 由 docs/TOOLS.md §8 的審查紀錄記下。
- 已提交的 golden fixture 中出現的每個規則都有群組，或是刻意留給 fallback 的。
"""

import json
import re
from functools import cache
from pathlib import Path

import pytest

from secscan.findings.domain.taxonomy import RuleGroup, load_taxonomy
from secscan.scanners.domain.nuclei import policy as nuclei_policy
from secscan.scanners.domain.zap.report import ZapReport, parse_report
from secscan.scans.domain.catalog import Engine

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TEMPLATES_DIR = Path(nuclei_policy.__file__).with_name("templates")
# 動態的 variant（偵測到的技術、指紋名稱）與需要人工判斷嚴重程度的規則：刻意不建群組。
FALLBACK_BY_DESIGN = frozenset(
    {
        (Engine.NUCLEI, "tech-detect"),
        (Engine.NUCLEI, "fingerprinthub-web-fingerprints"),
        (Engine.NUCLEI, "werkzeug-debugger-detect"),
    }
)
_NAME = re.compile(r"^[ \t]+(?:- )?name:[ \t]*([A-Za-z0-9._-]+)[ \t]*\r?$", re.MULTILINE)
_CWE = re.compile(r"CWE-([0-9]+)", re.IGNORECASE)
_CLASSIFICATION_CWE = re.compile(r"^[ \t]+cwe-id:[ \t]*(.+)$", re.MULTILINE)


@cache
def _templates() -> dict[str, str]:
    return {
        template.id: (TEMPLATES_DIR / template.path).read_text(encoding="utf-8")
        for template in nuclei_policy.load_templates()
    }


def _nuclei_cwes(template_id: str) -> frozenset[int]:
    match = _CLASSIFICATION_CWE.search(_templates()[template_id])
    if match is None:
        return frozenset()
    return frozenset(int(cwe) for cwe in _CWE.findall(match.group(1)))


@cache
def _zap_alerts() -> dict[tuple[str, str | None], frozenset[int | None]]:
    """golden fixture 中 ZAP 的 (pluginid, variant) → cweid（即 source_rule、rule_variant）。"""
    alerts: dict[tuple[str, str | None], set[int | None]] = {}
    reports = [*FIXTURES.glob("zap/*/report.json"), *FIXTURES.glob("zap/zap-*.json")]
    for path in reports:
        report = parse_report(path.read_bytes())
        assert isinstance(report, ZapReport), path
        for alert in report.alerts:
            variant = None if alert.alert_ref == alert.plugin_id else alert.alert_ref
            alerts.setdefault((alert.plugin_id, variant), set()).add(alert.cwe_id)
    return {key: frozenset(cwes) for key, cwes in alerts.items()}


def _groups() -> tuple[RuleGroup, ...]:
    return load_taxonomy().groups


def test_nuclei_members_are_frozen_templates_and_named_matchers() -> None:
    for group in _groups():
        for engine, rule, variant in group.members:
            if engine is not Engine.NUCLEI:
                continue
            assert rule in nuclei_policy.INCLUDE_TEMPLATE_IDS, (group.id, rule)
            names = set(_NAME.findall(_templates()[rule]))
            if variant is not None:
                assert variant in names, (group.id, rule, variant)


@pytest.mark.parametrize("group", _groups(), ids=lambda group: group.id)
def test_a_reviewed_cwe_is_one_the_tools_report(group: RuleGroup) -> None:
    known: set[int | None] = set()
    checkable = False
    for engine, rule, variant in group.members:
        if engine is Engine.NUCLEI:
            known |= _nuclei_cwes(rule)
            checkable = True
        elif (rule, variant) in _zap_alerts():
            known |= _zap_alerts()[(rule, variant)]
            checkable = True
    if not checkable:
        pytest.skip("成員只出現在 gitignore 的錄製中（CWE 見 TOOLS.md §8）")
    if group.cwe is None:
        assert known <= {None}, (group.id, known)
    else:
        assert group.cwe in known, (group.id, group.cwe, known)


def test_every_cross_engine_group_has_a_checkable_cwe() -> None:
    cross = [group for group in _groups() if len(group.engines) > 1]

    assert cross
    for group in cross:
        assert any(engine is Engine.NUCLEI for engine, _, _ in group.members)


def test_every_rule_in_the_golden_fixtures_is_grouped_or_left_to_fallback() -> None:
    taxonomy = load_taxonomy()
    missing = [
        (Engine.ZAP, rule, variant)
        for rule, variant in _zap_alerts()
        if taxonomy.lookup(Engine.ZAP, rule, variant) is None
    ]
    for name in ("nuclei-juice-shop.jsonl", "nuclei-vampi-vuln.jsonl"):
        text = (FIXTURES / "nuclei" / name).read_text(encoding="utf-8")
        for template_id, variant in _nuclei_rules(text):
            if (Engine.NUCLEI, template_id) in FALLBACK_BY_DESIGN:
                continue
            if taxonomy.lookup(Engine.NUCLEI, template_id, variant) is None:
                missing.append((Engine.NUCLEI, template_id, variant))

    assert missing == []


def test_rules_left_to_fallback_are_not_grouped() -> None:
    taxonomy = load_taxonomy()

    for _engine, rule in FALLBACK_BY_DESIGN:
        assert not any(member[1] == rule for group in taxonomy.groups for member in group.members)


def _nuclei_rules(jsonl: str) -> set[tuple[str, str | None]]:
    """parser 的對應：source_rule 是 template-id，variant 是 extractor-name 或 matcher-name。"""
    rules: set[tuple[str, str | None]] = set()
    for line in jsonl.splitlines():
        record = json.loads(line)
        variant = record.get("extractor-name") or record.get("matcher-name")
        rules.add((record["template-id"], variant))
    return rules
