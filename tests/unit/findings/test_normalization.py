"""工具原始等級與信心的正規化（T19；docs/DECISIONS.md §25.4）。"""

import pytest

from secscan.findings.domain.normalization import (
    NORMALIZATION_VERSION,
    Confidence,
    Normalized,
    Severity,
    highest,
    normalization_document,
    normalize,
)
from secscan.scans.domain.catalog import Engine


@pytest.mark.parametrize(
    ("raw", "severity"),
    [("0", Severity.INFO), ("1", Severity.LOW), ("2", Severity.MEDIUM), ("3", Severity.HIGH)],
)
def test_zap_riskcodes(raw: str, severity: Severity) -> None:
    assert normalize(Engine.ZAP, raw, "2") == Normalized(severity, Confidence.MEDIUM, False)


@pytest.mark.parametrize(
    ("raw", "confidence"),
    [
        ("0", Confidence.FALSE_POSITIVE),
        ("1", Confidence.LOW),
        ("3", Confidence.HIGH),
        ("4", Confidence.CONFIRMED),
        ("9", Confidence.UNKNOWN),
    ],
)
def test_zap_confidence_follows_zaps_own_labels(raw: str, confidence: Confidence) -> None:
    assert normalize(Engine.ZAP, "1", raw).confidence is confidence


@pytest.mark.parametrize("raw", ["4", "-1", "", "High", " 2"])
def test_unexpected_zap_values_are_info_and_need_review(raw: str) -> None:
    assert normalize(Engine.ZAP, raw, "2") == Normalized(Severity.INFO, Confidence.MEDIUM, True)


@pytest.mark.parametrize("raw", ["info", "Low", " MEDIUM ", "high", "critical"])
def test_nuclei_severity_is_one_to_one_ignoring_case(raw: str) -> None:
    normalized = normalize(Engine.NUCLEI, raw, "unknown")

    assert normalized.severity is Severity(raw.strip().lower())
    assert (normalized.confidence, normalized.needs_review) == (Confidence.UNKNOWN, False)


@pytest.mark.parametrize("raw", ["unknown", "severe", ""])
def test_unknown_nuclei_severity_is_info_and_needs_review(raw: str) -> None:
    assert normalize(Engine.NUCLEI, raw, "unknown") == Normalized(
        Severity.INFO, Confidence.UNKNOWN, True
    )


def test_an_engine_without_a_table_needs_review() -> None:
    assert normalize(Engine.FAKE, "high", "high") == Normalized(
        Severity.INFO, Confidence.UNKNOWN, True
    )


def test_highest_follows_the_declared_order_not_the_count() -> None:
    assert highest([Severity.INFO, Severity.INFO, Severity.MEDIUM]) is Severity.MEDIUM
    assert highest([Severity.CRITICAL, Severity.LOW]) is Severity.CRITICAL
    assert highest([Severity.INFO]) is Severity.INFO
    with pytest.raises(ValueError):  # noqa: PT011 - 空的輸入是呼叫端的錯誤（max 的訊息）
        highest([])


def test_the_document_is_versioned_and_covers_both_engines() -> None:
    document = normalization_document()

    assert document["version"] == NORMALIZATION_VERSION
    assert document["severity"] == {
        "nuclei": {s.value: s.value for s in Severity},
        "zap": {"0": "info", "1": "low", "2": "medium", "3": "high"},
    }
    assert document["case_insensitive"] == ["nuclei"]
