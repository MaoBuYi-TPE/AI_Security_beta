"""每個引擎的 ExecutionPlan 與額外的 secret 檔（docs/DECISIONS.md §14.3、§18.2、§18.7）。

- 依引擎完整分派，沒有預設的分支：沒有 plan 的引擎被拒絕，不會拿到別的引擎的映像與指令
  （T14 之前 zap 的 lease 會拿到 fake 的 plan、記成 zap）。
- 建好的 plan 再核對一次：引擎等於 lease 的引擎、映像等於 prepare 記下的 image_ref。
- zap：輸入取自 prepare 的結果（profile、grant 的範圍、預算、grant 的期限、認證的 header 名稱、
  規格的原料）。規格在這裡（transaction 之外）過濾成只含 eligible operation 的文件。
  時間或請求數不夠時拋 PlanWindowTooSmallError（runner 以 BUDGET_EXHAUSTED 結束，不送流量）。
"""

import math
import time
from collections.abc import Callable, Mapping
from types import MappingProxyType

from secscan.runner.domain.admission import PlanRejectedError, PlanRejection
from secscan.runner.egress import RunEgress
from secscan.scanners.domain.fake import FAKE_IMAGE, FakeScript, plan_fake_run
from secscan.scanners.domain.plan import ExecutionPlan, ImageReference
from secscan.scanners.domain.preflight import PREFLIGHT_IMAGE, plan_preflight_run
from secscan.scanners.domain.zap.plan import (
    ANONYMOUS,
    PlanWindowTooSmallError,
    ToolSpec,
    ZapAuth,
    ZapBudget,
    ZapPlanError,
    plan_zap_run,
)
from secscan.scanners.domain.zap.policy import ZAP_IMAGE
from secscan.scanners.domain.zap.script import CONFIG_FILE, SCAN_SCRIPT
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.model import Lease
from secscan.scans.queue import EgressScope, Launch
from secscan.specs.domain.tool_document import ToolDocumentError, tool_document

# 有 plan 的引擎與它的映像（prepare 時記下 image_ref）。
ENGINE_IMAGES: Mapping[Engine, ImageReference] = MappingProxyType(
    {Engine.FAKE: FAKE_IMAGE, Engine.PREFLIGHT: PREFLIGHT_IMAGE, Engine.ZAP: ZAP_IMAGE}
)


class RunPlanner:
    def __init__(self, *, script: FakeScript, clock: Callable[[], float] = time.time) -> None:
        self._script = script
        self._clock = clock

    def plan(self, lease: Lease, launch: Launch, *, image_ref: str) -> ExecutionPlan:
        """不能建立時拋 PlanRejectedError；ZAP 的時間或請求數不夠時拋 PlanWindowTooSmallError。"""
        plan = self._build(lease, launch)
        if plan.engine is not lease.engine:
            raise PlanRejectedError(PlanRejection.ENGINE_NOT_ALLOWED)
        if str(plan.image) != image_ref:
            raise PlanRejectedError(PlanRejection.IMAGE_NOT_APPROVED)
        return plan

    def _build(self, lease: Lease, launch: Launch) -> ExecutionPlan:
        match lease.engine:
            case Engine.FAKE:
                return plan_fake_run(
                    run_id=lease.run_id,
                    scan_id=lease.scan_id,
                    script=self._script,
                    target_auth=launch.secret is not None,
                    max_duration_seconds=launch.max_duration_seconds,
                )
            case Engine.PREFLIGHT:
                return _preflight(lease, launch)
            case Engine.ZAP:
                return self._zap(lease, launch)
            case _:
                raise PlanRejectedError(PlanRejection.ENGINE_NOT_ALLOWED)

    def _zap(self, lease: Lease, launch: Launch) -> ExecutionPlan:
        egress = launch.egress
        if egress is None or launch.scan_profile is None:
            raise PlanRejectedError(PlanRejection.ENGINE_NOT_ALLOWED)
        header = launch.secret.credential.wire_header if launch.secret is not None else None
        try:
            return plan_zap_run(
                run_id=lease.run_id,
                scan_id=lease.scan_id,
                profile=launch.scan_profile,
                origin=egress.origin,
                scope=egress.scope,
                auth=ZapAuth(header=header) if header is not None else ANONYMOUS,
                budget=self._budget(egress, launch.max_duration_seconds),
                spec=_tool_spec(launch, egress),
            )
        except PlanWindowTooSmallError:
            raise
        except (ZapPlanError, ToolDocumentError):
            raise PlanRejectedError(PlanRejection.INPUT_NOT_ALLOWED) from None

    def _budget(self, egress: EgressScope, remaining_seconds: int) -> ZapBudget:
        valid_for = math.floor(egress.valid_until.timestamp() - self._clock())
        return ZapBudget(
            requests_per_second=egress.budget.requests_per_second,
            max_requests=egress.budget.max_requests,
            remaining_seconds=remaining_seconds,
            valid_for_seconds=max(0, valid_for),
        )


def secret_files(plan: ExecutionPlan, egress: RunEgress) -> Mapping[str, str]:
    """引擎額外需要的 secret 檔：ZAP 掃描的 -configfile（proxy 的帳密與速率，§18.3）。"""
    if plan.engine is Engine.ZAP and plan.arguments == (SCAN_SCRIPT,):
        return {CONFIG_FILE: egress.zap_properties().value}
    return {}


def _tool_spec(launch: Launch, egress: EgressScope) -> ToolSpec | None:
    if launch.spec is None:
        return None
    document = tool_document(
        launch.spec.document,
        eligible=launch.spec.eligible,
        base_path=launch.spec.base_path,
        origin=egress.origin,
    )
    return ToolSpec(document=document, base_path=launch.spec.base_path)


def _preflight(lease: Lease, launch: Launch) -> ExecutionPlan:
    # preflight 一定有綁定的 profile 與 secret；缺少就是資料不一致，不啟動（fail closed）。
    if launch.preflight is None or launch.secret is None or launch.egress is None:
        raise PlanRejectedError(PlanRejection.ENGINE_NOT_ALLOWED)
    try:
        return plan_preflight_run(
            run_id=lease.run_id,
            scan_id=lease.scan_id,
            url=f"{launch.egress.origin}{launch.preflight.path}",
            max_duration_seconds=launch.max_duration_seconds,
        )
    except ValueError:
        raise PlanRejectedError(PlanRejection.INPUT_NOT_ALLOWED) from None
