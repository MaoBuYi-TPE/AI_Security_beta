"""fake 引擎（docs/DECISIONS.md §13.7、§14.3）：不連任何位址，結果一律標為 fixture。

- 腳本（FakeScript）：成功或失敗，以及在 running 停留的秒數。in-process 的 FakeRunner 與容器的
  runner 共用。
- 容器版的 ExecutionPlan：成功 → `sleep <秒數>`，失敗 → `false`。busybox 以 digest 鎖定，
  沒有 shell、不需要任何輸入檔以外的東西。
"""

import json
import math
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from secscan.scanners.domain.plan import ExecutionPlan, ImageReference, InputFile, ResourceLimits
from secscan.scans.domain.catalog import Engine

MAX_HOLD_SECONDS = 300
# T03 鎖定的 busybox（docs/TOOLS.md §1）：只 pull 使用、不散布（GPL-2.0-only）。
FAKE_IMAGE = ImageReference.parse(
    "busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"
)
# 停留最多 300 秒，再留一些餘裕；scan 的時間上限更短時以它為準。
FAKE_MAX_WALL_CLOCK_SECONDS = 600
FAKE_MEMORY_BYTES = 64 * 1024 * 1024
FAKE_NANO_CPUS = 500_000_000
FAKE_PIDS = 64
RUN_FILE = "run.json"


class FakeOutcome(StrEnum):
    SUCCEED = "succeed"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class FakeScript:
    """結果與在 running 停留的秒數。"""

    outcome: FakeOutcome = FakeOutcome.SUCCEED
    hold_seconds: float = 0

    def __post_init__(self) -> None:
        if not (math.isfinite(self.hold_seconds) and 0 <= self.hold_seconds <= MAX_HOLD_SECONDS):
            raise ValueError(f"hold_seconds 必須介於 0 與 {MAX_HOLD_SECONDS} 秒之間")


def plan_fake_run(
    *,
    run_id: UUID,
    scan_id: UUID,
    script: FakeScript,
    target_auth: bool,
    max_duration_seconds: int,
) -> ExecutionPlan:
    """容器版的 fake run。停留的秒數無條件進位成整數（sleep 的參數只用整數）。"""
    hold = math.ceil(script.hold_seconds)
    entrypoint: tuple[str, ...]
    arguments: tuple[str, ...]
    if script.outcome is FakeOutcome.SUCCEED:
        entrypoint, arguments = ("/bin/sleep",), (str(hold),)
    else:
        entrypoint, arguments = ("/bin/false",), ()
    description = {
        "engine": Engine.FAKE.value,
        "hold_seconds": hold,
        "outcome": script.outcome.value,
        "run_id": str(run_id),
        "scan_id": str(scan_id),
    }
    return ExecutionPlan(
        run_id=run_id,
        scan_id=scan_id,
        engine=Engine.FAKE,
        image=FAKE_IMAGE,
        entrypoint=entrypoint,
        arguments=arguments,
        environment=(),
        inputs=(InputFile(RUN_FILE, json.dumps(description, sort_keys=True).encode()),),
        target_auth=target_auth,
        limits=ResourceLimits(
            memory_bytes=FAKE_MEMORY_BYTES,
            nano_cpus=FAKE_NANO_CPUS,
            pids=FAKE_PIDS,
            wall_clock_seconds=min(max_duration_seconds, FAKE_MAX_WALL_CLOCK_SECONDS),
        ),
    )
