"""runner 單元測試共用的 plan 與政策。"""

from uuid import UUID

from secscan.runner.domain.policy import ContainerPolicy
from secscan.scanners.domain.fake import FakeScript, plan_fake_run
from secscan.scanners.domain.plan import ExecutionPlan

RUN_ID = UUID("6f1c2d3e-4b5a-4c6d-8e7f-001122334455")
SCAN_ID = UUID("0a1b2c3d-4e5f-4a6b-9c7d-8e9fa0b1c2d3")
POLICY = ContainerPolicy(
    scan_network="secscan_scan_net",
    runs_volume="secscan_runs",
    secrets_volume="secscan_run_secrets",
)


def fake_plan(
    script: FakeScript | None = None, *, target_auth: bool = False, run_id: UUID = RUN_ID
) -> ExecutionPlan:
    return plan_fake_run(
        run_id=run_id,
        scan_id=SCAN_ID,
        script=script if script is not None else FakeScript(hold_seconds=5),
        target_auth=target_auth,
        max_duration_seconds=1500,
    )
