"""佐證／相關群組換身分要人工確認；相同位置大量 finding 不做兩兩乘積。"""

from dataclasses import replace
from uuid import UUID

import pytest
from tests.unit.comparisons.test_evaluation import finding, scan

from secscan.comparisons.domain.reidentification import reidentified, relations
from secscan.findings.domain.taxonomy import load_taxonomy


@pytest.mark.parametrize(
    "anchor",
    [
        "csp-header-missing",
        "x-content-type-options-missing",
        "anti-clickjacking-header-missing",
    ],
)
def test_corroboration_pairs_are_symmetric_reidentification_candidates(anchor: str) -> None:
    taxonomy = load_taxonomy()
    group = next(group for group in taxonomy.groups if group.id == anchor)
    fallback = taxonomy.index[group.corroborated_by[0]].id
    candidates = relations(taxonomy)
    assert fallback in candidates[anchor]
    assert anchor in candidates[fallback]
    baseline, current = scan(1), scan(2)
    before = replace(finding(baseline), rule_group=anchor)
    after = replace(finding(current), finding_id=UUID(int=2), rule_group=fallback)
    assert reidentified(
        baseline.scan.scan_id, current.scan.scan_id, (before, after), candidates
    ) == {
        before.finding_id,
        after.finding_id,
    }


def test_related_groups_remain_candidates_without_merging_them() -> None:
    taxonomy = load_taxonomy()
    assert relations(taxonomy)["zap-cors-wildcard-origin"] == frozenset(
        {
            "nuclei-cors-arbitrary-origin-with-credentials",
        }
    )


def test_shared_position_does_not_require_pairwise_rule_group_comparisons() -> None:
    class CountedGroup(str):
        comparisons = 0
        __hash__ = str.__hash__

        def __eq__(self, other: object) -> bool:
            type(self).comparisons += 1
            return super().__eq__(other)

    baseline, current = scan(1), scan(2)
    before, after = finding(baseline), finding(current)
    size = 1000
    findings = tuple(
        replace(
            source,
            finding_id=UUID(int=index + side * size + 1),
            rule_group=CountedGroup(f"group-{side}-{index}"),
        )
        for side, source in enumerate((before, after))
        for index in range(size)
    )
    assert not reidentified(baseline.scan.scan_id, current.scan.scan_id, findings, {})
    # 不用易受硬體／負載影響的時間斷言；原先的雙層迴圈會比較 size ** 2 次。
    assert CountedGroup.comparisons < size * 4
