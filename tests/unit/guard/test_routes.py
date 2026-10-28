"""guard 啟動時的路由檢查（docs/DECISIONS.md §15.1、SEC-06）：只有 scan 與 lab 兩條直連的路由。

fixture 是實測時 guard 容器內的 /proc/net/route（§15 實測 8）。
"""

from ipaddress import IPv4Network

import pytest

from secscan.guard.domain.routes import route_problem

SCAN = IPv4Network("10.89.250.0/24")
LAB = IPv4Network("10.89.251.0/24")
EXPECTED = frozenset({SCAN, LAB})
HEADER = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT"
    "                                                       \n"
)
SCAN_ROW = "eth0\t00FA590A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
LAB_ROW = "eth1\t00FB590A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
DEFAULT_ROW = "eth0\t00000000\t01FA590A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
OTHER_ROW = "eth2\t000A590A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
GATEWAY_ROW = "eth1\t0000A8C0\t01FB590A\t0003\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
# lab 的網段本身經 gateway 到達（網段的集合相同，但不是直連）。
LAB_VIA_GATEWAY_ROW = "eth1\t00FB590A\t01FA590A\t0003\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"


def test_two_direct_routes_pass() -> None:
    assert route_problem(HEADER + SCAN_ROW + LAB_ROW, expected=EXPECTED) is None


@pytest.mark.parametrize(
    "table",
    [
        HEADER + SCAN_ROW + LAB_ROW + DEFAULT_ROW,  # 有預設路由：可以出網
        HEADER + SCAN_ROW + LAB_ROW + OTHER_ROW,  # 多接了一個網路（例如 control_net）
        HEADER + SCAN_ROW + LAB_ROW + GATEWAY_ROW,  # 經 gateway 的路由
        HEADER + SCAN_ROW + LAB_VIA_GATEWAY_ROW,  # 網段相同，卻經 gateway
        HEADER + SCAN_ROW,  # 少了 lab_net
        HEADER,
        "",
        HEADER + "eth0\tZZZZ\t00000000\t0001\n",
        HEADER + "eth0\t00FA590A\t00000000\t0001\t0\t0\t0\t00FF00FF\t0\t0\t0\n",  # 不連續的 mask
    ],
)
def test_anything_else_is_a_problem(table: str) -> None:
    assert route_problem(table, expected=EXPECTED) is not None
