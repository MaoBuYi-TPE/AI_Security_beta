"""舊版 mapping 不能借用目前 taxonomy 的 related／佐證關係。"""

from dataclasses import replace

import pytest
from tests.unit.comparisons.test_evaluation import scan

from secscan.comparisons.service import _relations
from secscan.findings.domain.taxonomy import mapping_identity


@pytest.mark.parametrize("side", [0, 1])
@pytest.mark.parametrize("field", ["mapping", "taxonomy"])
def test_relations_are_not_reconstructed_from_a_different_taxonomy(side: int, field: str) -> None:
    mapping, digest = mapping_identity()
    scans = tuple(
        replace(item, scan=replace(item.scan, mapping_version=mapping, taxonomy_sha256=digest))
        for item in (scan(1), scan(2))
    )
    assert _relations(*scans)
    changed = scans[side]
    changed = (
        replace(changed, scan=replace(changed.scan, mapping_version="rules-historical"))
        if field == "mapping"
        else replace(changed, scan=replace(changed.scan, taxonomy_sha256="0" * 64))
    )
    baseline, current = (changed, scans[1]) if side == 0 else (scans[0], changed)
    assert _relations(baseline, current) == {}
