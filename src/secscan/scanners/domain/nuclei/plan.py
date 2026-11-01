"""Nuclei 的 ExecutionPlan（T18；docs/DECISIONS.md §14.3、§23）。純函式，不接任何外部狀態。

- 直接以 nuclei 為 entrypoint、逐旗標組參數（映像 ENTRYPOINT 是 nuclei；免 shell）。
- 凍結的型別過濾與輸出（FROZEN_FLAGS）加 -dut（只跑簽章模板）與凍結的速率/並行
  （-rl 不超過 guard、-c 1、-bs 1、-retries 0）：nuclei 預設 150rps/25 並行會灌爆 2req/s 的 guard。
- 42 個凍結模板以 InputFile 掛進 /scan/in（唯讀）；plan_hash 涵蓋每檔內容，runner 掛載前 admission
  再以 ContentDigest 驗一次（獨立白名單，fail-closed）。
- 目標流量只能經 egress guard：proxy 從 /scan/secret/proxy-url 讀（含 token 的機密檔，不上命令列）。
- 本輪匿名掃描（target_auth=False）：42 個模板多為未認證偵測，目標 secret 的 -sf 留待後續。
- nuclei 需可寫的 HOME 放 config/cache：唯讀 rootfs 下以 HOME=/tmp 指向 tmpfs（runner 的 scratch）。
"""

from dataclasses import dataclass
from uuid import UUID

from secscan.scanners.domain.nuclei.policy import (
    FROZEN_FLAGS,
    NUCLEI_IMAGE,
    load_template_files,
)
from secscan.scanners.domain.plan import ExecutionPlan, InputFile, ResourceLimits
from secscan.scans.domain.catalog import Engine
from secscan.targets.domain import Origin

# 掃描容器內的固定路徑（比照 runner/domain/admission 的字面值，刻意重複：任一邊寫錯另一邊擋下）。
IN_DIR = "/scan/in"
OUT_DIR = "/scan/out"
PROXY_PATH = "/scan/secret/proxy-url"
RESULTS_NAME = "results.jsonl"
RESULTS_FILE = f"{OUT_DIR}/{RESULTS_NAME}"
# nuclei 寫 config/cache 的 HOME：唯讀 rootfs 下指向可寫的 tmpfs。
HOME_VARIABLE = "HOME"
HOME_DIR = "/tmp"  # noqa: S108 - 容器內的 tmpfs（runner 的 scratch），非主機暫存目錄
# 每個請求的逾時（秒）；整體時間由 runner 的牆鐘上限與 guard 的共享預算把關。
REQUEST_TIMEOUT_SECONDS = 15
MIN_PLAN_SECONDS = 60

# 資源上限起始值（nuclei 無 JVM，較 ZAP 輕；記憶體含 /tmp 的 tmpfs）。T18 後續依量測調整。
NUCLEI_MEMORY_BYTES = 1 * 1024 * 1024 * 1024
NUCLEI_NANO_CPUS = 2_000_000_000
NUCLEI_PIDS = 512


class NucleiPlanError(ValueError):
    """無法組出合法的 nuclei plan（預算不足或參數不合法）。"""


class PlanWindowTooSmallError(NucleiPlanError):
    """剩下的時間不夠 nuclei 執行（runner 以 BUDGET_EXHAUSTED 結束，不送流量）。"""


@dataclass(frozen=True, slots=True)
class NucleiBudget:
    """這個 run 分到的速率（req/s，不超過 guard）與剩下的牆鐘秒數。"""

    requests_per_second: int
    remaining_seconds: int


def plan_nuclei_run(
    *, run_id: UUID, scan_id: UUID, origin: Origin, budget: NucleiBudget
) -> ExecutionPlan:
    if budget.requests_per_second < 1:
        raise NucleiPlanError("速率必須是正整數")
    if budget.remaining_seconds < MIN_PLAN_SECONDS:
        raise PlanWindowTooSmallError("剩下的時間不夠 nuclei 執行")
    inputs = tuple(InputFile(name, content) for name, content in load_template_files())
    arguments = (
        *FROZEN_FLAGS,
        "-dut",
        "-t", IN_DIR,
        "-p", PROXY_PATH,
        "-o", RESULTS_FILE,
        "-rl", str(budget.requests_per_second),
        "-c", "1",
        "-bs", "1",
        "-retries", "0",
        "-timeout", str(REQUEST_TIMEOUT_SECONDS),
        "-u", str(origin),
    )  # fmt: skip
    return ExecutionPlan(
        run_id=run_id,
        scan_id=scan_id,
        engine=Engine.NUCLEI,
        image=NUCLEI_IMAGE,
        entrypoint=("nuclei",),
        arguments=arguments,
        environment=((HOME_VARIABLE, HOME_DIR),),
        inputs=inputs,
        target_auth=False,
        limits=ResourceLimits(
            memory_bytes=NUCLEI_MEMORY_BYTES,
            nano_cpus=NUCLEI_NANO_CPUS,
            pids=NUCLEI_PIDS,
            wall_clock_seconds=budget.remaining_seconds,
        ),
    )
