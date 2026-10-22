"""目前的 LAB_CIDR（create_app 依設定建立，放在 app.state.lab）。"""

from typing import Annotated

from fastapi import Depends, Request

from secscan.targets.domain import LabNetwork


def lab_network(request: Request) -> LabNetwork:
    lab = getattr(request.app.state, "lab", None)
    if not isinstance(lab, LabNetwork):
        # 沒有設定就不能判斷 IP 是否在 lab 內：直接失敗，不默認放行。
        raise RuntimeError("lab 網段尚未初始化（create_app 應設定 app.state.lab）")
    return lab


CurrentLab = Annotated[LabNetwork, Depends(lab_network)]
