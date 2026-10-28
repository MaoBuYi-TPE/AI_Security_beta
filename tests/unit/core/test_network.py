"""LAB_CIDR 的規則（docs/DECISIONS.md §10.1、§15.6）：config 與 guard 共用同一個純函式。"""

from ipaddress import IPv4Network

import pytest

from secscan.core.network import lab_cidr_problem


@pytest.mark.parametrize(
    "cidr", ["10.89.7.0/24", "10.89.0.0/16", "172.16.5.0/24", "192.168.56.0/30"]
)
def test_narrow_private_networks_are_accepted(cidr: str) -> None:
    assert lab_cidr_problem(IPv4Network(cidr)) is None


@pytest.mark.parametrize(
    ("cidr", "reason"),
    [
        ("8.8.8.0/24", "RFC 1918"),
        ("100.64.0.0/16", "RFC 1918"),
        ("127.0.0.0/16", "RFC 1918"),
        ("169.254.0.0/16", "RFC 1918"),
        ("10.0.0.0/8", "前綴長度"),
        ("10.88.0.0/15", "前綴長度"),
        ("10.89.7.0/31", "前綴長度"),
        ("10.89.7.4/32", "前綴長度"),
    ],
)
def test_wide_or_public_networks_are_rejected(cidr: str, reason: str) -> None:
    problem = lab_cidr_problem(IPv4Network(cidr))

    assert problem is not None
    assert reason in problem
