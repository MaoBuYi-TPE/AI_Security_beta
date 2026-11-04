"""finding 的 domain model：OWASP 沒有對應的原因（使用者簽核，docs/DECISIONS.md §25.14）。"""

from secscan.findings.domain.model import (
    UnmappedReason,
    api_unmapped_reason,
    top10_unmapped_reason,
)


def test_a_mapped_category_has_no_reason() -> None:
    assert top10_unmapped_reason(942, "A02:2025") is None
    assert api_unmapped_reason("API8:2023") is None


def test_unmapped_top10_says_why() -> None:
    assert top10_unmapped_reason(None, None) is UnmappedReason.NO_CWE
    # 例如 ZAP 10098 的 CWE-264（分類節點）、FX-09 的 CWE-530：保留原始 CWE，標明不在清單。
    assert top10_unmapped_reason(264, None) is UnmappedReason.CWE_NOT_LISTED


def test_unmapped_api_2023_is_not_curated() -> None:
    assert api_unmapped_reason(None) is UnmappedReason.NOT_CURATED
