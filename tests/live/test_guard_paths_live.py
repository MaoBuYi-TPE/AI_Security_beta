"""T33 two-policy validation. Only make test-live-guard-paths enables these phases."""

import base64
import json
import os
import time
from collections import Counter
from typing import Any
from urllib.parse import unquote

import pytest

from secscan.grants.domain.request_paths import canonical_path
from tests.guard_path_cases import PATH_CASES
from tests.live.guard_paths_regression import boundary_probes
from tests.live.guard_paths_support import (
    Capture,
    EvidenceStore,
    drained,
    echo_records,
    environment,
    route_echo,
    scan_runs,
)
from tests.live.guard_support import probe, raw_request, remove_policy, write_policy
from tests.live.lab_support import (
    Target,
    lab_call,
    start_juice_shop,
    start_vampi,
    stop_target,
    vampi_token,
)
from tests.live.support import (
    GUARD_LAB_IP,
    LAB_NET,
    TELEMETRY_VOLUME,
    Api,
    admin_key,
    container,
    inspect,
)
from tests.live.test_lab_zap_live import (
    VAMPI_ME,
    _all_observations,
    _bearer,
    _vampi_lab,
    _zap_container,
)
from tests.live.zap_support import RUNS_VOLUME, Lab, lab, requests_since, volume_file, wait_for_zap

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]
STRICT, ENCODED = "strict-1", "encoded-params-1"
ENCODED_SAFE = ("/a/name%27", "/a/name%3c", "/a/name%3C", "/a/a+%20b", "/a/%7Bid%7D")
DENIED = (
    "/a/%41",
    "/a/%7e",
    "/a/%2e",
    "/a/%2F",
    "/a/%5c",
    "/a/%3f",
    "/a/%23",
    "/a/%3b",
    "/a/%252e",
    "/a/%2500",
    "/a/%00",
    "/a/%FF",
    "/a/%",
    "/a/%G0",
    "/a/../b",
    "/a//b",
    "/a/{id}",
    "/other/name%27",
    "/a/admin/name%27",
)
PLAIN = ("/a/plain", "/a/x+y", "/a/x.y", "/a/plain?q=one%20two&q=%2f", "/a/plain")


def _counter(records: list[dict[str, Any]]) -> Counter[tuple[str, str]]:
    return Counter((str(r["method"]), str(r["path"])) for r in records)


def _echo_probes(version: str) -> None:
    for kind in ("flask", "express"):
        with route_echo(kind) as target:
            store = EvidenceStore.open(version, f"echo-{kind}")
            # Direct probes intentionally include unsupported transformations: they are
            # observations of the locked framework, not assertions that Guard accepts them.
            direct = [*PLAIN, *ENCODED_SAFE, "/a/x%2fy", "/a/admin.json/%27"]
            raw = [
                (str(i), raw_request(path, host=f"{target.host}:8080"))
                for i, path in enumerate(direct)
            ]
            probe(raw, target=f"{target.ip}:8080", network=LAB_NET)
            direct_records = echo_records(target)
            store.write("direct-probes.json", {"sent": direct, "received": direct_records})
            split = [r for r in direct_records if r.get("target") == "/a/x%2fy"]
            assert len(split) == 1
            assert split[0]["parameters"] == (
                {"x": "x", "y": "y"} if kind == "flask" else {"x": "x/y"}
            )
            policy = write_policy(
                origin=target.origin,
                ips=[target.ip],
                paths=["/a/{x}", "/a/{x}/{y}"],
                excluded=["/a/admin/{id}"],
                policy_version=version,
            )
            start = len([r for r in direct_records if r["kind"] == "request"])
            paths = [*PLAIN, *ENCODED_SAFE, *DENIED, "/a/plain"]
            raw = [
                (
                    str(i),
                    raw_request(
                        f"{target.origin}{path}",
                        host=f"{target.host}:8080",
                        authorization=policy.authorization(),
                    ),
                )
                for i, path in enumerate(paths)
            ]
            started = time.time()
            try:
                results = probe(raw)
                records = [r for r in echo_records(target) if r["kind"] == "request"][start:]
                expected = [
                    p for p in paths if p in PLAIN or (version == ENCODED and p in ENCODED_SAFE)
                ]
                store.write(
                    "raw-probes.json",
                    [{"name": n, "raw": base64.b64encode(b).decode()} for n, b in raw],
                )
                store.write("target-requests.log", records)
                store.write("guard-decisions.jsonl", requests_since(started))
                store.write("environment.json", environment(target))
                store.write("analysis.json", {"results": results, "expected": expected})
                assert [r["target"] for r in records] == expected
                assert all(str(r["peer"]).removeprefix("::ffff:") == GUARD_LAB_IP for r in records)
                for i, path in enumerate(paths):
                    if path in expected:
                        assert results[str(i)]["status"] == 200
                    else:
                        assert results[str(i)]["status"] == 403
                for record in records:
                    assert record["parameters"]["x"] == unquote(
                        str(record["target"]).partition("?")[0].split("/")[2]
                    )
                # The documented extension-removal counterexample must NOT alias to admin
                # on the accepted Lab framework chain.
                alias = [r for r in direct_records if r.get("target") == "/a/admin.json/%27"]
                assert alias
                assert alias[0]["parameters"]["x"] == "admin.json"
            finally:
                remove_policy(policy)
                store.seal()
            _golden_echo(version, target)


def _golden_echo(version: str, target: Target) -> None:
    """The same fixed corpus is checked against independently specified decisions."""
    policy = write_policy(
        origin=target.origin,
        ips=[target.ip],
        paths=["/a/{id}"],
        excluded=[],
        policy_version=version,
    )
    store = EvidenceStore.open(version, f"golden-{target.host}")
    before = len([r for r in echo_records(target) if r["kind"] == "request"])
    started = time.time()
    try:
        cases = [
            (
                str(i),
                raw_request(
                    f"{target.origin}{case.path}",
                    host=f"{target.host}:8080",
                    authorization=policy.authorization(),
                ),
            )
            for i, case in enumerate(PATH_CASES)
        ]
        results = probe(cases)
        decisions = [e for e in requests_since(started) if e.get("run_id") == policy.run_id]
        received = [r for r in echo_records(target) if r["kind"] == "request"][before:]
        telemetry, summary, entries = _telemetry(policy.run_id)
        sent = [e for e in entries if e["e"] == "request"]
        store.write(
            "raw-probes.json", [{"name": n, "raw": base64.b64encode(b).decode()} for n, b in cases]
        )
        store.write("guard-decisions.jsonl", decisions)
        store.write("target-requests.log", received)
        store.write("telemetry.jsonl", telemetry)
        store.write("summary.json", summary)
        store.write("probe-results.json", results)
        store.write("environment.json", environment(target))
        assert [d["path"] for d in decisions] == [c.path for c in PATH_CASES]
        accepted = []
        for i, case in enumerate(PATH_CASES):
            reason = case.strict_reason if version == STRICT else case.encoded_reason
            detail = case.strict_detail if version == STRICT else case.encoded_detail
            if reason is None:
                accepted.append(case.path)
                if version == ENCODED and "%" in case.path:
                    detail = "encoded-route-parameter"
            assert results[str(i)]["status"] == (200 if reason is None else 403)
            assert decisions[i]["reason"] == reason
            assert decisions[i]["detail"] == detail
            assert decisions[i]["policy_version"] == version
        assert [r["target"] for r in received] == accepted
        assert [r["path"] for r in sent] == accepted
        store.write(
            "analysis.json",
            {"cases": len(cases), "received": len(received), "byte_preserving": True},
        )
    finally:
        remove_policy(policy)
        store.seal()


def _telemetry(run_id: str) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
    raw = volume_file(TELEMETRY_VOLUME, f"{run_id}.jsonl")
    summary = volume_file(TELEMETRY_VOLUME, f"{run_id}.summary.json")
    assert raw is not None
    assert summary is not None
    return raw, json.loads(summary), [json.loads(line) for line in raw.splitlines()]


def _measure(version: str, label: str, item: Lab, target: Target, **options: Any) -> None:
    store = EvidenceStore.open(version, label)
    store.write("environment.json", environment(target))
    capture = Capture(target, store).start()
    started = time.time()
    try:
        scan_id = item.scan("api_active_lab", **options)
        zap_container = _zap_container(scan_id)
        scanner_image = inspect(zap_container)
        store.write(
            "scanner-image.json",
            {"image_id": scanner_image["Image"], "image": scanner_image["Config"]["Image"]},
        )
        engine = item.finished_zap(scan_id, timeout=1800)
        records = capture.finish()
        scan = item.operator.data("GET", f"/scans/{scan_id}")
        observations = _all_observations(item, scan_id)
        decisions = requests_since(started)
        runs = scan_runs(scan_id)
        store.write("scan.json", {"scan": scan, "observations": observations, "runs": runs})
        store.write("guard-decisions.jsonl", decisions)
        store.write("target-requests.log", records)
        forwarded: list[dict[str, Any]] = []
        zap_forwarded: list[dict[str, Any]] = []
        for run in runs:
            raw, summary, entries = _telemetry(run["id"])
            sent = [e for e in entries if e["e"] == "request"]
            assert summary["policy_version"] == version == run["guard_policy_version"]
            assert summary["forwarded"] == len(sent)
            forwarded.extend(sent)
            prefix = "" if run["engine"] == "zap" else "preflight-"
            store.write(prefix + "telemetry.jsonl", raw)
            store.write(prefix + "summary.json", summary)
            if run["engine"] == "zap":
                zap_forwarded = sent
        run_id = zap_container.removeprefix("secscan-run-")
        for name, source in (
            ("report.json", "out/zap-report.json"),
            ("zap.log", "out/zap.log"),
            ("manifest.json", "manifest.json"),
        ):
            content = volume_file(RUNS_VOLUME, f"{run_id}/{source}")
            if content is not None:
                store.write(name, content)
        store.write("scan.json", {"scan": scan, "observations": observations, "runs": runs})
        store.write("guard-decisions.jsonl", decisions)
        store.write("target-requests.log", records)
        missing, extra = (
            _counter(forwarded) - _counter(records),
            _counter(records) - _counter(forwarded),
        )
        encoded_count = sum("%" in r["path"] for r in zap_forwarded)
        sqli = [o for o in observations if o["source_rule"] == "40018"]
        analysis = {
            "policy_version": version,
            "run_id": run_id,
            "forwarded": len(forwarded),
            "received": len(records),
            "forwarded_encoded": encoded_count,
            "missing": [[*key, n] for key, n in missing.items()],
            "extra": [[*key, n] for key, n in extra.items()],
            "sqli": len(sqli),
            "detail_counts": dict(Counter(d.get("detail") for d in decisions)),
            "evidence_boundary": (
                "raw method/path multiset, including preflight; query is preserved "
                "in capture but absent from telemetry"
            ),
        }
        store.write("analysis.json", analysis)
        # Only aggregate values are printed; paths and secret material stay encrypted.
        print(  # noqa: T201
            f"T33 {version} {label}: sent={len(forwarded)} received={len(records)} "
            f"encoded={encoded_count} SQLi={len(sqli)} status={engine['status']}"
        )
        assert not missing, "target missing requests; see encrypted evidence"
        assert not extra, "target received extra requests; see encrypted evidence"
        assert engine["guard_policy_version"] == version
        assert engine["status"] in {"succeeded", "timed_out"}
        assert engine["result"]["traffic_verified"] is True
        assert engine["result"]["guard_traffic"]["policy_version"] == version
        assert engine["result"]["guard_traffic"]["forwarded_encoded"] == encoded_count
        assert scan["coverage"]["observed_operations"] is not None
        sent_keys = {(r["method"], canonical_path(r["path"])) for r in zap_forwarded}
        assert all((o["method"], canonical_path(o["path"])) in sent_keys for o in observations)
        if version == STRICT:
            assert encoded_count == 0
        if label == "vampi-secure":
            assert not sqli
        if label.startswith("vampi"):
            denied = [
                d
                for d in decisions
                if d.get("path") == "/users/v1/name1%27" and d.get("decision") == "deny"
            ]
            if version == STRICT:
                assert denied
            else:
                assert encoded_count > 0
                assert not denied
                assert any(r["path"] == "/users/v1/name1%27" for r in records)
    finally:
        capture.cleanup()
        store.seal()


JUICE_PATHS = ["/rest/products/{id}/reviews", "/api/Products/{id}"]
JUICE_EXCLUDED = ["/api/Products/999"]
JUICE_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "T33 Juice Shop paths", "version": "1"},
    "paths": {
        path: {
            "get": {
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "example": "1"},
                    }
                ],
                "responses": {"200": {"description": "ok"}},
            }
        }
        for path in JUICE_PATHS
    },
}


def _juice_probes(version: str, target: Target) -> None:
    store = EvidenceStore.open(version, "juice-shop-fixed-probes")
    policy = write_policy(
        origin=target.origin,
        ips=[target.ip],
        paths=JUICE_PATHS,
        excluded=JUICE_EXCLUDED,
        policy_version=version,
    )
    capture = Capture(target, store)
    paths = [
        "/rest/products/1/reviews",
        "/rest/products/1%27/reviews",
        "/api/Products/1%27",
        "/rest/products/1%2500/reviews",
        "/api/Products/1",
    ]
    started = time.time()
    try:
        capture.start()
        raw = [
            (
                str(i),
                raw_request(
                    target.origin + path,
                    host=f"{target.host}:{target.port}",
                    authorization=policy.authorization(),
                ),
            )
            for i, path in enumerate(paths)
        ]
        results = probe(raw)
        receipts = capture.finish()
        telemetry, summary, entries = _telemetry(policy.run_id)
        sent = [e for e in entries if e["e"] == "request"]
        decisions = [e for e in requests_since(started) if e.get("run_id") == policy.run_id]
        store.write(
            "raw-probes.json", [{"name": n, "raw": base64.b64encode(b).decode()} for n, b in raw]
        )
        store.write("guard-decisions.jsonl", decisions)
        store.write("target-requests.log", receipts)
        store.write("telemetry.jsonl", telemetry)
        store.write("summary.json", summary)
        store.write("environment.json", environment(target))
        store.write(
            "analysis.json", {"results": results, "forwarded": len(sent), "received": len(receipts)}
        )
        assert _counter(sent) == _counter(receipts)
        expected = [paths[0], *([paths[1]] if version == ENCODED else []), paths[-1]]
        assert [r["target"] for r in receipts] == expected
        assert results["2"]["reason"] == "PATH_AMBIGUOUS"
        assert results["3"]["reason"] == "PATH_AMBIGUOUS"
        if version == ENCODED:
            assert decisions[2]["detail"] == "exclusion-overlap"
            assert decisions[3]["detail"] == "double-encoding"
    finally:
        capture.cleanup()
        remove_policy(policy)
        store.seal()


def test_guard_paths_phase() -> None:
    version = os.environ.get("T33_POLICY_PHASE")
    if version not in {STRICT, ENCODED}:
        pytest.skip("only the dedicated test-live-guard-paths target selects a phase")
    assert version is not None
    env = inspect(container("runner"))["Config"]["Env"]
    assert f"RUNNER_GUARD_POLICY_VERSION={version}" in env
    admin = Api(admin_key())
    wait_for_zap(admin)
    drained()
    boundary_probes(version)
    _echo_probes(version)
    for vulnerable in [True] if version == STRICT else [True, False]:
        target = start_vampi(vulnerable=vulnerable, host="lab-t33-vampi")
        try:
            item, spec = _vampi_lab(admin, target)
            profile = _bearer(item, vampi_token(target), VAMPI_ME)
            _measure(
                version,
                "vampi-vuln" if vulnerable else "vampi-secure",
                item,
                target,
                spec_id=spec,
                auth_profile_id=profile,
            )
        finally:
            stop_target(target)
    target = start_juice_shop(host="lab-t33-juice")
    try:
        # Validate real endpoints, rather than treating fabricated routes as scanner coverage.
        assert lab_call(target, "GET", "/rest/products/1/reviews")[0] == 200
        assert lab_call(target, "GET", "/api/Products/1")[0] == 200
        _juice_probes(version, target)
        item = lab(
            admin,
            kind="api",
            paths=JUICE_PATHS,
            excluded=JUICE_EXCLUDED,
            methods=["GET"],
            host=target.host,
            ip=target.ip,
            port=target.port,
        )
        spec = item.operator.data(
            "POST",
            f"/targets/{item.target_id}/api-specs",
            raw=json.dumps(JUICE_SPEC).encode(),
            content_type="application/json",
        )
        _measure(version, "juice-shop-paths", item, target, spec_id=str(spec["id"]))
    finally:
        stop_target(target)
    drained()
