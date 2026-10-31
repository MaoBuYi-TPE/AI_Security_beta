"""Independent expectations for coverage derived from frozen operations and raw telemetry."""

from typing import Any

import pytest

from tests.guard_path_coverage import coverage_from_evidence, decisions_for_run
from tests.guard_path_evidence import EvidenceError

VERSION = "encoded-params-1"


def operation(
    ordinal: int, path: str, *, method: str = "GET", eligible: bool = True
) -> dict[str, Any]:
    return {
        "ordinal": ordinal,
        "method": method,
        "path": path,
        "ineligible_reason": None if eligible else "PATH_EXCLUDED",
    }


def snapshot(operations: list[dict[str, Any]], *, authenticated: bool = True) -> dict[str, Any]:
    return {
        "scan_id": "scan",
        "api_spec_id": "spec",
        "auth_profile_id": "profile" if authenticated else None,
        "preflight_method": "GET" if authenticated else None,
        "preflight_path": "/private" if authenticated else None,
        "operations": operations,
    }


def run(
    run_id: str = "zap", *, engine: str = "zap", preflight: str | None = None
) -> dict[str, Any]:
    return {
        "id": run_id,
        "engine": engine,
        "status": "succeeded",
        "guard_policy_version": VERSION,
        "preflight_result": preflight,
    }


def traffic(*rows: tuple[str, str, bool, int | None]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for seq, (method, path, auth, status) in enumerate(rows, 1):
        entries.append({"e": "request", "seq": seq, "method": method, "path": path, "auth": auth})
        if status is not None:
            entries.append({"e": "response", "seq": seq, "status": status})
    return entries


def test_matches_only_answered_eligible_operations_and_the_most_specific_route() -> None:
    frozen = snapshot(
        [
            operation(0, "/a/{id}"),
            operation(1, "/a/special"),
            operation(2, "/a/{id}/"),
            operation(3, "/a/{id}", method="POST"),
            operation(4, "/private"),
            operation(5, "/blocked", eligible=False),
            operation(6, "/unanswered"),
            operation(7, "/static/name'"),
            operation(8, "/static/{id}"),
        ]
    )
    runs = [run("preflight", engine="preflight", preflight="passed"), run()]
    records = {
        "preflight": traffic(("GET", "/private", True, 200), ("GET", "/private", False, 401)),
        "zap": traffic(
            ("GET", "/a/special", False, 200),
            ("GET", "/a/name%27", True, 403),
            ("GET", "/a/another", True, 400),
            ("GET", "/a/special/", True, 200),
            ("POST", "/a/id", True, 200),
            ("GET", "/blocked", True, 200),
            ("GET", "/unanswered", True, None),
            ("GET", "/static/name%27", True, 200),
            ("HEAD", "/a/id", True, 200),
            ("GET", "/A/id", True, 200),
            ("GET", "/a/id/extra", True, 200),
            ("GET", "/a/another", True, 200),
        ),
    }

    result = coverage_from_evidence(frozen, runs, records, version=VERSION)

    assert result["coverage"] == {
        "eligible_operations": 8,
        "ineligible_operations": 1,
        "observed_operations": 5,
        "authenticated_operations": 4,
        "coverage_measured": True,
    }
    assert result["observed_ordinals"] == [0, 1, 2, 3, 8]
    assert result["authenticated_ordinals"] == [0, 2, 3, 8]
    assert result["answered_by_run"] == {"preflight": 2, "zap": 11}


def test_preflight_alone_never_contributes_coverage() -> None:
    result = coverage_from_evidence(
        snapshot([operation(0, "/private")]),
        [run("preflight", engine="preflight", preflight="passed"), run()],
        {"preflight": traffic(("GET", "/private", True, 200)), "zap": []},
        version=VERSION,
    )

    assert result["coverage"]["observed_operations"] == 0
    assert result["coverage"]["authenticated_operations"] == 0


@pytest.mark.parametrize("status", [401, 403])
def test_rejected_credentials_are_observed_but_not_authenticated(status: int) -> None:
    result = coverage_from_evidence(
        snapshot([operation(0, "/a/{id}")]),
        [run("preflight", engine="preflight", preflight="passed"), run()],
        {"preflight": [], "zap": traffic(("GET", "/a/x", True, status))},
        version=VERSION,
    )

    assert result["coverage"]["observed_operations"] == 1
    assert result["authenticated_ordinals"] == []
    assert result["coverage"]["authenticated_operations"] is None  # No accepted credentials: lost.


@pytest.mark.parametrize(
    ("authenticated", "preflight", "expected"),
    [
        (False, None, None),
        (True, "failed", 0),
        (True, "inconclusive", 0),
        (True, "passed", 1),
    ],
)
def test_authentication_exposure_obeys_binding_and_preflight(
    authenticated: bool, preflight: str | None, expected: int | None
) -> None:
    runs = [run()]
    records = {"zap": traffic(("GET", "/a/x", True, 200))}
    if authenticated:
        runs.insert(0, run("preflight", engine="preflight", preflight=preflight))
        records["preflight"] = []
    result = coverage_from_evidence(
        snapshot([operation(0, "/a/{id}")], authenticated=authenticated),
        runs,
        records,
        version=VERSION,
    )

    assert result["coverage"]["observed_operations"] == 1
    assert result["coverage"]["authenticated_operations"] == expected


@pytest.mark.parametrize(
    "rows",
    [
        (("GET", "/public", True, 200), ("GET", "/private", True, 403)),
        (
            ("GET", "/a/x%3c", True, 200),
            ("GET", "/a/y", True, 200),
            ("GET", "/a/x%3C", True, 401),
            ("GET", "/a/y", True, 403),
        ),
    ],
)
def test_authentication_loss_hides_coverage_even_after_accepted_requests(
    rows: tuple[tuple[str, str, bool, int | None], ...],
) -> None:
    result = coverage_from_evidence(
        snapshot([operation(0, "/a/{id}"), operation(1, "/public")]),
        [run("preflight", engine="preflight", preflight="passed"), run()],
        {"preflight": [], "zap": traffic(*rows)},
        version=VERSION,
    )

    assert result["authenticated_ordinals"]
    assert result["coverage"]["authenticated_operations"] is None
    assert result["auth_by_run"]["zap"]["lost"] is True


@pytest.mark.parametrize(
    "entries",
    [
        [{"e": "response", "seq": 1, "status": 200}],
        [*traffic(("GET", "/a/x", True, 200)), {"e": "response", "seq": 1, "status": 200}],
        [{"e": "request", "seq": 1, "method": "GET", "path": "/a/x", "auth": True}] * 2,
    ],
)
def test_unpaired_or_duplicate_telemetry_cannot_substantiate_coverage(
    entries: list[dict[str, Any]],
) -> None:
    with pytest.raises(EvidenceError):
        coverage_from_evidence(
            snapshot([operation(0, "/a/{id}")], authenticated=False),
            [run()],
            {"zap": entries},
            version=VERSION,
        )


def test_each_run_decision_version_is_checked_without_cross_run_attribution() -> None:
    decisions = [
        {"run_id": "first", "policy_version": "strict-1"},
        {"run_id": "second", "policy_version": VERSION},
    ]
    assert decisions_for_run(decisions, "second", VERSION) == [decisions[1]]
    with pytest.raises(EvidenceError):
        decisions_for_run(decisions, "first", VERSION)
    with pytest.raises(EvidenceError):
        decisions_for_run(decisions, "missing", VERSION)


@pytest.mark.parametrize("version", ["strict-1", "encoded-params-1"])
def test_equally_specific_routes_are_counted_under_both_policies(version: str) -> None:
    source = run()
    source["guard_policy_version"] = version
    result = coverage_from_evidence(
        snapshot([operation(0, "/a/{id}"), operation(1, "/{prefix}/x")], authenticated=False),
        [source],
        {"zap": traffic(("GET", "/a/x", False, 200))},
        version=version,
    )

    assert result["observed_ordinals"] == [0, 1]
    assert result["coverage"]["authenticated_operations"] is None


def test_strict_encoded_forwarding_is_an_evidence_error() -> None:
    source = run()
    source["guard_policy_version"] = "strict-1"
    with pytest.raises(EvidenceError):
        coverage_from_evidence(
            snapshot([operation(0, "/a/{id}")], authenticated=False),
            [source],
            {"zap": traffic(("GET", "/a/name%27", False, 200))},
            version="strict-1",
        )
