"""T33：政策版本、逐請求的判斷與紀錄不可分離。"""

import json
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from secscan.grants.domain.request_paths import PathEncoding
from secscan.guard.domain.policy import (
    GuardPolicyVersion,
    PolicyError,
    compile_policy,
    decode_policy,
    encode_policy,
)
from secscan.guard.domain.requests import Reason, ambiguity_detail, request_reason, scope_reason
from secscan.guard.domain.telemetry import (
    ForwardedRequest,
    RunSummary,
    TelemetryError,
    decode_line,
    decode_summary,
    encode_summary,
    telemetry_file_name,
)
from secscan.guard.telemetry import TelemetryRecorder, TelemetryWriteError
from tests.unit.guard.addon_support import (
    RUN_ID,
    build_harness,
    make_flow,
    make_policy,
    reason_of,
    screen,
)
from tests.unit.guard.test_requests import POLICY, _compiled, _view

STRICT = GuardPolicyVersion.STRICT
EXPERIMENTAL = GuardPolicyVersion.ENCODED_PARAMS


@pytest.mark.parametrize("version", list(GuardPolicyVersion))
def test_policy_version_is_required_and_round_trips(version: GuardPolicyVersion) -> None:
    policy = replace(POLICY.policy, policy_version=version)
    raw = encode_policy(policy)
    document = json.loads(raw)
    assert document["schema"] == 3
    assert document["policy_version"] == version.value
    assert decode_policy(raw, run_id=policy.run_id) == policy
    document.pop("policy_version")
    with pytest.raises(PolicyError):
        decode_policy(json.dumps(document).encode(), run_id=policy.run_id)


def test_unknown_policy_version_is_not_a_strict_fallback() -> None:
    document = json.loads(encode_policy(POLICY.policy))
    document["policy_version"] = "future"
    with pytest.raises(PolicyError, match="policy_version"):
        decode_policy(json.dumps(document).encode(), run_id=POLICY.policy.run_id)
    with pytest.raises(PolicyError, match="policy_version"):
        replace(POLICY.policy, policy_version="strict-1")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("path", "reason", "detail"),
    [
        ("/users/v1/name%27", None, None),
        ("/users/v1/name%20part", None, None),
        ("/users/v1/%7Bx%7D", None, None),
        ("/users/v1/%41", Reason.PATH_AMBIGUOUS, "non-canonical"),
        ("/users/v1/%2F", Reason.PATH_AMBIGUOUS, "encoded-separator"),
        ("/users/v1/%252F", Reason.PATH_AMBIGUOUS, "double-encoding"),
        ("/users/v1/%27/extra", Reason.PATH_NOT_AUTHORIZED, None),
        ("/users/v1/%27?%255fmethod=DELETE", Reason.OVERRIDE_HEADER, None),
    ],
)
def test_full_guard_and_parser_share_explicit_policy(
    path: str,
    reason: Reason | None,
    detail: str | None,
) -> None:
    compiled = compile_policy(replace(POLICY.policy, policy_version=EXPERIMENTAL))
    assert request_reason(_view(path), compiled) is reason
    assert scope_reason("GET", path, compiled.rules, EXPERIMENTAL.encoding) is reason
    assert ambiguity_detail("GET", path, compiled.rules, EXPERIMENTAL.encoding) == detail
    assert scope_reason("GET", path, compiled.rules, STRICT.encoding) is not None


def test_exclusion_overlap_is_ambiguous_and_allow_all_is_not_permission() -> None:
    rules = _compiled(paths=("/users/v1/{id}",), excluded=("/users/v1/admin",)).rules
    assert (
        ambiguity_detail("GET", "/users/v1/a%27", rules, EXPERIMENTAL.encoding)
        == "exclusion-overlap"
    )
    broad = _compiled(paths=(), allow_all_paths=True).rules
    assert ambiguity_detail("GET", "/a%27", broad, EXPERIMENTAL.encoding) == "no-route-parameter"


def test_versions_map_to_grants_without_a_reverse_dependency() -> None:
    assert STRICT.encoding is PathEncoding.REJECT
    assert EXPERIMENTAL.encoding is PathEncoding.ROUTE_PARAMETERS


@pytest.mark.parametrize(("method", "target"), [("GET", "/a/#frag"), ("G T", "/a/name")])
def test_shape_ambiguity_has_a_safe_detail(method: str, target: str) -> None:
    assert ambiguity_detail(method, target, POLICY.rules, STRICT.encoding) == "syntax"


@pytest.mark.parametrize("version", list(GuardPolicyVersion))
def test_summary_reports_policy_version(version: GuardPolicyVersion) -> None:
    summary = RunSummary(
        run_id=UUID(int=1),
        scan_id=UUID(int=2),
        boot_id=UUID(int=3),
        forwarded=0,
        policy_version=version,
    )
    raw = encode_summary(summary)
    assert json.loads(raw)["schema"] == 2
    assert decode_summary(raw, run_id=summary.run_id) == summary


def test_legacy_summary_has_strict_semantics_but_must_have_exact_legacy_keys() -> None:
    summary = RunSummary(
        run_id=UUID(int=1),
        scan_id=UUID(int=2),
        boot_id=UUID(int=3),
        forwarded=0,
        policy_version=STRICT,
    )
    document = json.loads(encode_summary(summary))
    document.pop("policy_version")
    document["schema"] = 1
    assert decode_summary(json.dumps(document).encode(), run_id=summary.run_id) == summary
    document["policy_version"] = "encoded-params-1"
    with pytest.raises(TelemetryError):
        decode_summary(json.dumps(document).encode(), run_id=summary.run_id)


@pytest.mark.parametrize("path", ["/a/..+", "/a/name%20part", "/a/%27"])
def test_telemetry_syntax_is_the_union_not_an_authorization(path: str) -> None:
    assert (
        ForwardedRequest(sequence=1, at=1, method="GET", path=path, authenticated=False).path
        == path
    )


@pytest.mark.parametrize("path", ["/a/%41", "/a/%2527", "/a/%2F", "/a/{x}", "/a/%"])
def test_telemetry_rejects_paths_not_valid_in_either_policy(path: str) -> None:
    with pytest.raises(TelemetryError):
        ForwardedRequest(sequence=1, at=1, method="GET", path=path, authenticated=False)


@pytest.mark.parametrize("restart", [False, True])
def test_same_run_cannot_mix_policy_versions(tmp_path: Path, restart: bool) -> None:
    recorder = TelemetryRecorder(tmp_path, boot_id=uuid4())
    recorder.denied(POLICY.policy, Reason.PATH_AMBIGUOUS)
    recorder.flush()
    if restart:
        recorder = TelemetryRecorder(tmp_path, boot_id=uuid4())
    changed = replace(POLICY.policy, policy_version=EXPERIMENTAL)
    with pytest.raises(TelemetryWriteError, match="版本"):
        recorder.reserve(changed)


def test_allowed_encoded_wire_path_and_query_are_unchanged_and_log_is_complete(
    tmp_path: Path,
) -> None:
    harness = build_harness(tmp_path)
    harness.write(replace(make_policy(), policy_version=EXPERIMENTAL))
    path = "/api/items/" + "a" * 498 + "%27"
    assert len(path) == 512
    target = path + "?q=must-not-be-logged%20here"
    flow = make_flow(target)
    before = flow.request.data.path
    screen(harness, flow)
    harness.addon.request(flow)
    assert flow.response is None
    assert flow.request.data.path == before == target.encode("ascii")
    decision = harness.lines()[-1]
    assert decision["policy_version"] == EXPERIMENTAL.value
    assert decision["detail"] == "encoded-route-parameter"
    assert decision["path"] == path
    assert "must-not-be-logged" not in harness.stream.getvalue()
    record = decode_line((harness.telemetry / telemetry_file_name(RUN_ID)).read_bytes())
    assert isinstance(record, ForwardedRequest)
    assert record.path == path


@pytest.mark.parametrize(
    ("path", "detail"),
    [
        ("%41", "non-canonical"),
        ("%2f", "encoded-separator"),
        ("%2527", "double-encoding"),
        ("%GG", "invalid-percent"),
        ("..+", "dot-segment"),
    ],
)
def test_experimental_denial_precedes_dns_and_has_trusted_version(
    tmp_path: Path,
    path: str,
    detail: str,
) -> None:
    harness = build_harness(tmp_path)
    harness.write(replace(make_policy(), policy_version=EXPERIMENTAL))
    flow = screen(harness, make_flow(f"/api/items/{path}"))
    assert reason_of(flow) == "PATH_AMBIGUOUS"
    assert harness.resolver.calls == []
    decision = harness.lines()[-1]
    assert decision["policy_version"] == EXPERIMENTAL.value
    assert decision["detail"] == detail


def test_unauthenticated_decision_does_not_claim_a_policy_version(tmp_path: Path) -> None:
    harness = build_harness(tmp_path)
    flow = screen(harness, make_flow(authorization=False))
    assert reason_of(flow) == "PROXY_AUTH_REQUIRED"
    assert harness.lines()[-1]["policy_version"] is None


@pytest.mark.parametrize("version", ["future", "strict-1 ", None, True, 1])
def test_summary_unknown_or_missing_version_is_rejected(version: object) -> None:
    summary = RunSummary(
        run_id=UUID(int=1),
        scan_id=UUID(int=2),
        boot_id=UUID(int=3),
        forwarded=0,
        policy_version=STRICT,
    )
    document = json.loads(encode_summary(summary))
    document["policy_version"] = version
    with pytest.raises(TelemetryError, match="policy_version"):
        decode_summary(json.dumps(document).encode(), run_id=summary.run_id)
    document.pop("policy_version")
    with pytest.raises(TelemetryError):
        decode_summary(json.dumps(document).encode(), run_id=summary.run_id)


def test_summary_dataclass_also_rejects_unknown_version() -> None:
    with pytest.raises(TelemetryError, match="policy_version"):
        RunSummary(
            run_id=UUID(int=1),
            scan_id=UUID(int=2),
            boot_id=UUID(int=3),
            forwarded=0,
            policy_version="strict-1",  # type: ignore[arg-type]
        )
