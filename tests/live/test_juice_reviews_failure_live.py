"""Original T33 Juice reviews crash regression on the ordinary strict runner.

Run through make test-live-runner with LIVE_TESTS pointing at this file. This deliberately
expects the complete original measurement to fail; it cannot satisfy normal A/B acceptance.
"""

import json
import os
import uuid
from pathlib import Path

import pytest

from tests.guard_path_evidence import EvidenceError
from tests.juice_reviews_failure import (
    FAILURE_LABEL,
    STRICT,
    assert_original_reviews_failure,
    read_failure_artifacts,
)
from tests.live import test_guard_paths_live as measurement
from tests.live.guard_paths_support import EvidenceStore, drained
from tests.live.lab_support import (
    JUICE_SHOP_IP,
    JUICE_SHOP_PORT,
    PREFIX,
    Target,
    lab_call,
    start_juice_shop,
    stop_target,
)
from tests.live.support import LAB_NET, Api, admin_key, container, docker, inspect
from tests.live.zap_support import lab, wait_for_zap

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]

ORIGINAL_JUICE_PATHS = ("/rest/products/{id}/reviews", "/api/Products/{id}")
ORIGINAL_JUICE_EXCLUDED = ("/api/Products/999",)
# A separate immutable JSON snapshot survives changes to the normal A/B candidate.
ORIGINAL_JUICE_SPEC = json.dumps(
    {
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
            for path in ORIGINAL_JUICE_PATHS
        },
    }
)
ORIGINAL_JUICE_BUDGET = (
    ("requests_per_second", 2),
    ("max_requests", 5000),
    ("max_duration_seconds", 1500),
)


def test_original_juice_reviews_crash_retains_failed_measurement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert os.environ.get("T33_POLICY_PHASE") is None, "use the ordinary strict runner"
    runner_env = inspect(container("runner"))["Config"]["Env"]
    uses_strict = f"RUNNER_GUARD_POLICY_VERSION={STRICT}" in runner_env
    assert uses_strict, "ordinary runner must keep strict-1"
    assert (
        docker(
            "exec",
            container("runner"),
            "python",
            "-c",
            "from secscan.core.config import Settings; print(Settings().lab_only)",
        ).strip()
        == "True"
    ), "live regression requires LAB_ONLY"
    [network] = json.loads(docker("network", "inspect", LAB_NET))
    assert network["Internal"] is True
    admin = Api(admin_key())
    wait_for_zap(admin)
    drained()
    if "SECSCAN_GUARD_PATH_RECORD_DIR" not in os.environ:
        monkeypatch.setenv(
            "SECSCAN_GUARD_PATH_RECORD_DIR",
            str(Path(__file__).resolve().parents[2] / "recordings" / "guard-paths-failures"),
        )
    target = Target(
        f"{PREFIX}juice-shop",
        f"lab-t33-juice-failure-{uuid.uuid4().hex[:8]}",
        JUICE_SHOP_IP,
        JUICE_SHOP_PORT,
    )
    try:
        assert start_juice_shop(host=target.host) == target
        assert lab_call(target, "GET", "/rest/products/1/reviews")[0] == 200
        assert lab_call(target, "GET", "/api/Products/1")[0] == 200
        item = lab(
            admin,
            kind="api",
            paths=list(ORIGINAL_JUICE_PATHS),
            excluded=list(ORIGINAL_JUICE_EXCLUDED),
            methods=["GET"],
            host=target.host,
            ip=target.ip,
            port=target.port,
        )
        spec = item.operator.data(
            "POST",
            f"/targets/{item.target_id}/api-specs",
            raw=ORIGINAL_JUICE_SPEC.encode(),
            content_type="application/json",
        )
        store = EvidenceStore.open(STRICT, FAILURE_LABEL)
        with monkeypatch.context() as patch:
            patch.setattr(EvidenceStore, "open", classmethod(lambda _cls, _v, _label: store))
            with pytest.raises(EvidenceError) as failure:
                measurement._measure(
                    STRICT,
                    FAILURE_LABEL,
                    item,
                    target,
                    spec_id=str(spec["id"]),
                    budget=dict(ORIGINAL_JUICE_BUDGET),
                )
        artifacts = read_failure_artifacts(store)
        assert_original_reviews_failure(artifacts, str(failure.value))
        assert not (store.directory / "analysis.json.fernet").exists()
        assert not (store.directory / "coverage-analysis.json.fernet").exists()
    finally:
        stop_target(target)
    drained()
