"""目前的 LAB_CIDR 由 create_app 放在 app.state；沒有設定時直接失敗，不默認放行。"""

from ipaddress import IPv4Network
from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import Request

from secscan.core.config import Settings
from secscan.main import create_app
from secscan.targets.dependencies import lab_network
from secscan.targets.domain import LabNetwork


def _request(state: object) -> Request:
    return cast(Request, SimpleNamespace(app=SimpleNamespace(state=state)))


def test_app_uses_the_configured_lab_network() -> None:
    settings = Settings(app_env="test", lab_cidr=IPv4Network("192.168.56.0/24"), _env_file=None)

    app = create_app(settings)

    assert lab_network(_request(app.state)) == LabNetwork(IPv4Network("192.168.56.0/24"))


@pytest.mark.parametrize("lab", [None, "10.89.7.0/24", IPv4Network("10.89.7.0/24")])
def test_missing_or_wrong_lab_network_fails_closed(lab: object) -> None:
    state = SimpleNamespace() if lab is None else SimpleNamespace(lab=lab)

    with pytest.raises(RuntimeError, match=r"app\.state\.lab"):
        lab_network(_request(state))
