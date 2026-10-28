"""target 的 domain 規則：LAB_CIDR（docs/DECISIONS.md §10.1）、名稱與可修改的欄位。"""

from ipaddress import IPv4Address, IPv4Network
from uuid import uuid4

import pytest

from secscan.targets.domain import (
    TARGET_NAME_MAX_LENGTH,
    LabNetwork,
    NewTarget,
    OutsideLabError,
    TargetKind,
    TargetUpdate,
    parse_ipv4,
    parse_origin,
)

LAB = LabNetwork(IPv4Network("10.89.7.0/24"))
BAD_NAMES = ["", "   ", "　", "\t\n", "lab\x00", "x" * (TARGET_NAME_MAX_LENGTH + 1)]


@pytest.mark.parametrize("address", ["10.89.7.1", "10.89.7.20", "10.89.7.253"])
def test_lab_hosts_are_accepted(address: str) -> None:
    LAB.check_host(IPv4Address(address))


@pytest.mark.parametrize(
    ("cidr", "reserved", "usable"),
    [
        ("10.89.7.0/24", "10.89.7.254", "10.89.7.253"),
        ("10.89.0.0/16", "10.89.255.254", "10.89.255.253"),
        ("192.168.56.0/30", "192.168.56.2", "192.168.56.1"),
    ],
)
def test_last_host_is_reserved_for_the_egress_guard(cidr: str, reserved: str, usable: str) -> None:
    """guard 在 lab_net 上固定用最後一個主機位址（DECISIONS §15.6）：target 與 grant 不可指向它。"""
    lab = LabNetwork(IPv4Network(cidr))

    assert lab.guard_address == IPv4Address(reserved)
    lab.check_host(IPv4Address(usable))
    with pytest.raises(OutsideLabError, match="保留給 egress guard"):
        lab.check_host(IPv4Address(reserved))
    with pytest.raises(OutsideLabError, match="保留給 egress guard"):
        lab.check_origin(parse_origin(f"http://{reserved}:8080"))


@pytest.mark.parametrize(
    "address",
    [
        "10.89.7.0",  # 網段位址
        "10.89.7.255",  # 廣播位址
        "10.89.8.1",
        "10.89.6.255",
        "192.168.1.10",
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",  # noqa: S104 - 測試資料，不是要綁定的位址
    ],
)
def test_addresses_outside_the_lab_hosts_are_rejected(address: str) -> None:
    with pytest.raises(OutsideLabError, match=r"LAB_CIDR（10\.89\.7\.0/24）"):
        LAB.check_host(IPv4Address(address))


def test_origin_with_an_ip_host_must_be_in_the_lab() -> None:
    LAB.check_origin(parse_origin("http://10.89.7.20:5000"))
    LAB.check_origin(parse_origin("http://vampi-vuln:5000"))  # 名稱由 guard 在執行時綁定 IP

    with pytest.raises(OutsideLabError):
        LAB.check_origin(parse_origin("http://192.168.1.10:5000"))


def test_lab_network_needs_an_ipv4_network() -> None:
    with pytest.raises(TypeError, match="IPv4Network"):
        LabNetwork("10.89.7.0/24")  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["10.89.7.20", "0.0.0.0", "255.255.255.255"])  # noqa: S104
def test_parse_ipv4_accepts_dotted_decimal(value: str) -> None:
    assert str(parse_ipv4(value)) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "10.89.7",
        "10.89.7.20.1",
        "010.89.7.20",
        "0x0a.89.7.20",
        "167772160",
        "10.89.7.20/32",
        "10.89.7.0/24",
        " 10.89.7.20",
        "10.89.7.20\n",
        "::1",
        chr(0xFF11) + chr(0xFF10) + ".89.7.20",  # 全形數字
        "lab",
    ],
)
def test_parse_ipv4_rejects_everything_else(value: str) -> None:
    with pytest.raises(ValueError, match="IPv4"):
        parse_ipv4(value)


def test_new_target_accepts_a_valid_target() -> None:
    target = NewTarget(
        project_id=uuid4(),
        name="API 教學靶場",
        kind=TargetKind.API,
        origin=parse_origin("http://vampi-vuln:5000"),
    )

    assert str(target.origin) == "http://vampi-vuln:5000"


@pytest.mark.parametrize("name", BAD_NAMES, ids=repr)
def test_new_target_rejects_invalid_names(name: str) -> None:
    with pytest.raises(ValueError, match="name"):
        NewTarget(
            project_id=uuid4(),
            name=name,
            kind=TargetKind.WEB,
            origin=parse_origin("http://lab"),
        )


def test_target_update_needs_at_least_one_change() -> None:
    with pytest.raises(ValueError, match="至少"):
        TargetUpdate()


@pytest.mark.parametrize("name", BAD_NAMES, ids=repr)
def test_target_update_rejects_invalid_names(name: str) -> None:
    with pytest.raises(ValueError, match="name"):
        TargetUpdate(name=name)


def test_target_update_accepts_partial_changes() -> None:
    assert TargetUpdate(enabled=False).name is None
    assert TargetUpdate(name="新名稱").enabled is None
