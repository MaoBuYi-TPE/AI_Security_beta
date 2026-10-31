"""AF 的結尾摘要（docs/DECISIONS.md §19.2；文字以鎖定映像的實測為準，TOOLS.md §7.6）。

只有整行比對：log 的內容含 URL 與目標的訊息，是不可信的資料。
"""

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secscan.scanners.domain.zap.log import PlanSummary, parse_summary

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "zap"
SUCCEEDED = b"Automation plan succeeded!\n"
FAILURES = b"Automation plan failures:\n"
WARNINGS = b"Automation plan warnings:\n"
MAX_DURATION = b"\tPlan stopped after reaching maximum duration of 60 second(s)\n"
PROGRESS = b"Job report finished, time taken: 00:00:00\n"


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("clean", PlanSummary(succeeded=True)),
        ("findings", PlanSummary(succeeded=True)),
        ("timeout", PlanSummary(warnings=1, max_duration=True)),
        ("unanswered", PlanSummary(warnings=1)),
        ("unreachable", PlanSummary(errors=1)),
    ],
)
def test_recorded_logs(scenario: str, expected: PlanSummary) -> None:
    assert parse_summary((FIXTURES / scenario / "zap.log").read_bytes()) == expected


def test_a_log_that_stops_before_the_summary_has_none() -> None:
    """ZAP 沒有跑到 plan（啟動參數錯誤）：usage 之後沒有摘要。"""
    assert parse_summary((FIXTURES / "engine-error" / "zap.log").read_bytes()) is None


def test_errors_and_warnings_are_counted_separately() -> None:
    log = PROGRESS + FAILURES + b"\tone\n\ttwo\n" + WARNINGS + b"\tthree\n"

    assert parse_summary(log) == PlanSummary(errors=2, warnings=1)


def test_a_message_can_span_several_lines() -> None:
    log = PROGRESS + FAILURES + b"\tfirst line\nsecond line\n" + WARNINGS + b"\tthree\n"

    assert parse_summary(log) == PlanSummary(errors=1, warnings=1)


def test_the_progress_line_with_the_same_words_is_not_the_summary() -> None:
    """同一句話也出現在進度中（沒有 tab，在 job 結束之前）：只看摘要。"""
    log = MAX_DURATION.removeprefix(b"\t") + PROGRESS + SUCCEEDED

    assert parse_summary(log) == PlanSummary(succeeded=True)


def test_a_max_duration_of_another_shape_is_an_ordinary_warning() -> None:
    log = PROGRESS + WARNINGS + b"\tPlan stopped after reaching maximum duration of soon\n"

    assert parse_summary(log) == PlanSummary(warnings=1)


@pytest.mark.parametrize(
    "log",
    [
        b"",
        PROGRESS,
        # 摘要的順序或重複不符合 ExtensionAutomation 的輸出：內容被混入，不判讀
        PROGRESS + WARNINGS + b"\tx\n" + FAILURES + b"\ty\n",
        PROGRESS + WARNINGS + b"\tx\n" + SUCCEEDED,
        PROGRESS + SUCCEEDED + SUCCEEDED,
        PROGRESS + FAILURES + b"\tx\n" + FAILURES + b"\ty\n",
        PROGRESS + SUCCEEDED + b"\textra\n",
        # 標題之後沒有任何訊息
        PROGRESS + FAILURES,
        PROGRESS + WARNINGS,
    ],
)
def test_a_summary_that_makes_no_sense_is_rejected(log: bytes) -> None:
    assert parse_summary(log) is None


def test_only_the_last_block_counts() -> None:
    """工具的訊息中混入看起來像摘要的行，只要後面還有 job 的進度就不算。"""
    log = FAILURES + b"\tforged\n" + PROGRESS + SUCCEEDED

    assert parse_summary(log) == PlanSummary(succeeded=True)


def test_a_log_that_is_not_utf8_is_still_read() -> None:
    assert parse_summary(b"\xff\xfe\n" + PROGRESS + SUCCEEDED) == PlanSummary(succeeded=True)


@given(st.binary(max_size=512))
def test_any_bytes_only_produce_a_summary_or_none(log: bytes) -> None:
    summary = parse_summary(log)

    assert summary is None or isinstance(summary, PlanSummary)


@given(
    st.lists(
        st.sampled_from([SUCCEEDED, FAILURES, WARNINGS, b"\tmsg\n", PROGRESS, b"noise\n"]),
        max_size=12,
    )
)
def test_a_summary_never_claims_success_with_errors(pieces: list[bytes]) -> None:
    summary = parse_summary(b"".join(pieces))

    if summary is not None:
        assert summary.succeeded is not (summary.errors > 0 or summary.warnings > 0)
