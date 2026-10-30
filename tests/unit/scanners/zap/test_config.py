"""zap.properties（docs/DECISIONS.md §18.3）：guard 的 proxy 帳密與 ZAP 自己的速率限制。

ZAP 以 -configfile 讀它；對不認得的 key 不報錯，所以 key 逐字核對
（T14 以鎖定的映像確認 ZAP 讀得到）。
值都以嚴格的字元集核對：一行一個 key，不能被值中的換行或跳脫字元改寫。
"""

from ipaddress import IPv4Address
from uuid import UUID

import pytest

from secscan.guard.domain.credentials import PROXY_REALM, ProxyCredentials
from secscan.scanners.domain.zap.config import zap_properties

RUN_ID = UUID("00000000-0000-4000-8000-000000000001")
TOKEN = "A" * 21 + "-_" + "z9" * 10
GUARD = IPv4Address("10.89.9.254")


def _render(token: str = TOKEN, requests_per_second: int = 2) -> str:
    return zap_properties(
        address=GUARD,
        port=8080,
        credentials=ProxyCredentials(RUN_ID, token),
        requests_per_second=requests_per_second,
    ).value


def test_renders_the_proxy_and_the_rate_limit() -> None:
    assert _render().splitlines() == [
        "network.connection.httpProxy.enabled=true",
        "network.connection.httpProxy.host=10.89.9.254",
        "network.connection.httpProxy.port=8080",
        "network.connection.httpProxy.authEnabled=true",
        f"network.connection.httpProxy.realm={PROXY_REALM}",
        f"network.connection.httpProxy.username={RUN_ID}",
        f"network.connection.httpProxy.password={TOKEN}",
        "network.ratelimit.rules.rule(0).description=secscan",
        "network.ratelimit.rules.rule(0).enabled=true",
        "network.ratelimit.rules.rule(0).matchStr=.*",
        "network.ratelimit.rules.rule(0).regex=true",
        "network.ratelimit.rules.rule(0).reqsPerSec=2",
        "network.ratelimit.rules.rule(0).groupBy=RULE",
    ]


def test_the_result_does_not_show_the_token_when_printed() -> None:
    rendered = zap_properties(
        address=GUARD,
        port=8080,
        credentials=ProxyCredentials(RUN_ID, TOKEN),
        requests_per_second=1,
    )

    assert TOKEN not in repr(rendered)
    assert TOKEN not in str(rendered)


@pytest.mark.parametrize(
    "token",
    [
        "A" * 42,
        "A" * 44,
        "A" * 42 + "\n",
        "A" * 42 + "=",
        "A" * 42 + "\\",
        "A" * 41 + "\r\n",
    ],
)
def test_a_token_outside_the_base64url_form_is_rejected(token: str) -> None:
    with pytest.raises(ValueError, match="token"):
        _render(token=token)


@pytest.mark.parametrize("requests_per_second", [0, -1, 3])
def test_the_rate_must_be_within_the_grant_cap(requests_per_second: int) -> None:
    with pytest.raises(ValueError, match="速率"):
        _render(requests_per_second=requests_per_second)


@pytest.mark.parametrize("port", [0, 65536])
def test_the_port_must_be_valid(port: int) -> None:
    with pytest.raises(ValueError, match="port"):
        zap_properties(
            address=GUARD,
            port=port,
            credentials=ProxyCredentials(RUN_ID, TOKEN),
            requests_per_second=2,
        )
