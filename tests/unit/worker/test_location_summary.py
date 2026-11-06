"""複掃覆蓋摘要：不保存參數名稱，未知規則不得被當作 discovery。"""

from secscan.scans.domain.coverage import Exchange
from secscan.worker.locations import summarize_locations


def test_aggregates_responses_and_keeps_rule_signals_distinct() -> None:
    summary = summarize_locations(
        (
            Exchange("GET", "/items", True, 200, "40018", ("secret",), False),
            Exchange("GET", "/items", True, 401, "40018"),
            Exchange("GET", "/items", False, None),
            Exchange("POST", "/other", False, 204),
        )
    )
    first, second = summary.locations
    assert (first.method, first.path, first.answered, first.authenticated, first.unanswered) == (
        "GET",
        "/items",
        True,
        True,
        True,
    )
    assert first.discovery_answered is False
    assert second.discovery_answered is False
    [rule] = summary.rules
    assert (rule.rule, rule.answered, rule.parameters_unknown) == ("40018", True, True)
    assert "secret" not in repr(summary)


def test_redacted_path_is_not_used_as_a_location_match() -> None:
    exchange = Exchange("GET", "/items/secscan_0123456789abcdef_" + "a" * 64, False, 200, "40018")
    summary = summarize_locations((exchange,))
    assert summary.locations == ()
    assert summary.rules == ()
    assert summary.has_unusable_paths


def test_no_response_and_rejected_credentials_are_not_authenticated() -> None:
    summary = summarize_locations((Exchange("GET", "/me", True, 403),))
    [location] = summary.locations
    assert location.answered
    assert not location.authenticated
