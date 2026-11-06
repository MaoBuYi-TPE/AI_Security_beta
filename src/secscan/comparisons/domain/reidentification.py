"""相同位置換成相關／佐證群組時只要求人工確認，不自動合併。"""

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from uuid import UUID

from secscan.comparisons.domain.facts import FindingFacts
from secscan.findings.domain.taxonomy import Taxonomy


def relations(taxonomy: Taxonomy) -> Mapping[str, frozenset[str]]:
    """包含 related 與佐證成員的原群組；不把現在的分類表拿來重算舊版 finding。"""
    edges = {group: set(others) for group, others in taxonomy.related.items()}
    for member, anchor in taxonomy.anchors.items():
        original = taxonomy.index[member].id
        edges.setdefault(anchor.id, set()).add(original)
        edges.setdefault(original, set()).add(anchor.id)
    return MappingProxyType({group: frozenset(others) for group, others in edges.items()})


def reidentified(
    baseline_id: UUID,
    current_id: UUID,
    findings: Sequence[FindingFacts],
    related: Mapping[str, frozenset[str]],
) -> frozenset[UUID]:
    # 先按位置及群組彙整，再一次標記整組，避免同一端點許多參數形成 N * M 比較。
    before = _index(findings, baseline_id, current_id)
    after = _index(findings, current_id, baseline_id)
    symmetric = {group: set(others) for group, others in related.items()}
    for group, others in related.items():
        for other in others:
            symmetric.setdefault(other, set()).add(group)
    found: set[UUID] = set()
    for position, groups in before.items():
        counterparts = after.get(position, {})
        for group, ids in groups.items():
            for candidate in {group} | symmetric.get(group, set()):
                matches = counterparts.get(candidate)
                if matches:
                    found.update(ids)
                    found.update(matches)
    return frozenset(found)


def _index(
    findings: Sequence[FindingFacts],
    present: UUID,
    absent: UUID,
) -> dict[tuple[str, str, str | None], dict[str, set[UUID]]]:
    grouped: dict[tuple[str, str, str | None], dict[str, set[UUID]]] = {}
    for item in findings:
        scans = {appearance.scan_id for appearance in item.appearances}
        if present in scans and absent not in scans:
            key = (item.method, item.route, item.resource)
            grouped.setdefault(key, {}).setdefault(item.rule_group, set()).add(item.finding_id)
    return grouped
