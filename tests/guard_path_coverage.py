"""Independent T33 coverage oracle; no product parser or route-matching imports.

Input paths are already forwarded Guard telemetry, whose admission is tested separately.
We preserve raw segments and distinguish literals, complete placeholders and trailing slashes.
This does not attribute target-side packet capture to individual runs.
"""

import re
from typing import Any

from tests.guard_path_evidence import EvidenceError

_PLACEHOLDER = re.compile(r"\{[^{}]+\}")
_TRIPLET = re.compile(r"%[0-9a-fA-F]{2}")
_TERMINAL = {"succeeded", "failed", "timed_out", "cancelled", "interrupted"}


def decisions_for_run(
    decisions: list[dict[str, Any]], run_id: str, version: str
) -> list[dict[str, Any]]:
    selected = [entry for entry in decisions if entry.get("run_id") == run_id]
    if not selected or any(entry.get("policy_version") != version for entry in selected):
        raise EvidenceError("run decisions absent or policy version inconsistent")
    return selected


def _exchanges(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    requests: dict[int, dict[str, Any]] = {}
    responses: dict[int, int] = {}
    for entry in entries:
        sequence = entry["seq"]
        if type(sequence) is not int or sequence < 1:
            raise EvidenceError("invalid telemetry sequence")
        if entry["e"] == "request":
            if sequence in requests or type(entry["auth"]) is not bool:
                raise EvidenceError("duplicate request or invalid authentication flag")
            requests[sequence] = entry
        elif entry["e"] == "response":
            if (
                sequence in responses
                or type(entry["status"]) is not int
                or not 100 <= entry["status"] <= 599
            ):
                raise EvidenceError("duplicate response or invalid response status")
            responses[sequence] = entry["status"]
        else:
            raise EvidenceError("unknown telemetry event")
    if not responses.keys() <= requests.keys():
        raise EvidenceError("response has no matching request")
    if list(requests) != list(range(1, len(requests) + 1)):
        raise EvidenceError("request sequences incomplete or out of order")
    return [{**request, "status": responses.get(seq)} for seq, request in requests.items()]


def _matching(operations: list[dict[str, Any]], exchange: dict[str, Any]) -> list[int]:
    actual = exchange["path"].split("/")
    candidates: list[tuple[int, int]] = []
    for operation in operations:
        expected = operation["path"].split("/")
        if operation["method"] != exchange["method"] or len(expected) != len(actual):
            continue
        placeholders = [_PLACEHOLDER.fullmatch(part) is not None for part in expected]
        if all(
            (bool(raw) if parameter else "%" not in raw and raw == literal)
            for raw, literal, parameter in zip(actual, expected, placeholders, strict=True)
        ):
            candidates.append((sum(placeholders), operation["ordinal"]))
    if not candidates:
        return []
    specificity = min(count for count, _ in candidates)
    return [ordinal for count, ordinal in candidates if count == specificity]


def _auth_health(exchanges: list[dict[str, Any]], probe: tuple[str, str] | None) -> dict[str, Any]:
    # Normalize only percent-triplet case for repeated raw request identity, never decode.
    accepted: set[tuple[str, str]] = set()
    last_refused: dict[tuple[str, str], bool] = {}
    accepted_count = rejected_count = probe_rejected = 0
    for exchange in exchanges:
        if not exchange["auth"] or exchange["status"] is None:
            continue
        key = (exchange["method"], _TRIPLET.sub(lambda m: m[0].upper(), exchange["path"]))
        refused = exchange["status"] in {401, 403}
        last_refused[key] = refused
        if refused:
            rejected_count += 1
            probe_rejected += key == probe
        else:
            accepted_count += 1
            accepted.add(key)
    regressed = sum(last_refused[key] for key in accepted)
    return {
        "accepted": accepted_count,
        "rejected": rejected_count,
        "regressed": regressed,
        "probe_rejected": probe_rejected,
        "lost": regressed >= 2
        or probe_rejected > 0
        or (accepted_count == 0 and rejected_count > 0),
    }


def coverage_from_evidence(
    snapshot: dict[str, Any],
    runs: list[dict[str, Any]],
    telemetry: dict[str, list[dict[str, Any]]],
    *,
    version: str,
) -> dict[str, Any]:
    if version not in {"strict-1", "encoded-params-1"} or snapshot["api_spec_id"] is None:
        raise EvidenceError("coverage requires a known policy and frozen API specification")
    if not runs or set(telemetry) != {run["id"] for run in runs}:
        raise EvidenceError("coverage requires telemetry for every run")
    operations = [op for op in snapshot["operations"] if op["ineligible_reason"] is None]
    bound = snapshot["auth_profile_id"] is not None
    probe = (snapshot["preflight_method"], snapshot["preflight_path"]) if bound else None
    observed: set[int] = set()
    authenticated: set[int] = set()
    auth_by_run: dict[str, Any] = {}
    answered_by_run: dict[str, int] = {}
    preflight = None
    for run in runs:
        if run["status"] not in _TERMINAL or run["guard_policy_version"] != version:
            raise EvidenceError("run unfinished or policy version inconsistent")
        exchanges = _exchanges(telemetry[run["id"]])
        answered_by_run[run["id"]] = sum(e["status"] is not None for e in exchanges)
        if run["engine"] == "preflight":
            preflight = run["preflight_result"]
            continue
        if run["engine"] != "zap":
            raise EvidenceError("unexpected T33 engine")
        auth_by_run[run["id"]] = _auth_health(exchanges, probe)
        for exchange in exchanges:
            if version == "strict-1" and "%" in exchange["path"]:
                raise EvidenceError("strict telemetry contains an encoded path")
            if exchange["status"] is None:
                continue
            matched = _matching(operations, exchange)
            observed.update(matched)
            if exchange["auth"] and exchange["status"] not in {401, 403}:
                authenticated.update(matched)
    lost = any(health["lost"] for health in auth_by_run.values())
    disclosed_authenticated = None
    if bound and not lost:
        disclosed_authenticated = len(authenticated) if preflight == "passed" else 0
    return {
        "coverage": {
            "eligible_operations": len(operations),
            "ineligible_operations": len(snapshot["operations"]) - len(operations),
            "observed_operations": len(observed),
            "authenticated_operations": disclosed_authenticated,
            "coverage_measured": True,
        },
        "observed_ordinals": sorted(observed),
        "authenticated_ordinals": sorted(authenticated),
        "preflight": preflight,
        "auth_by_run": auth_by_run,
        "answered_by_run": answered_by_run,
        "boundary": (
            "operation coverage from per-run answered telemetry; preflight excluded; "
            "no packet-to-run attribution"
        ),
    }
