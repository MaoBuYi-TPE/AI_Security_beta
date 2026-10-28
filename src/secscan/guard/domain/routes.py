"""guard 的路由檢查（docs/DECISIONS.md §15.1、SEC-06）：只有 scan 與 lab 兩條直連的路由。

guard 只接 scan_net 與 lab_net；多出一個網路（例如 control_net）、預設路由或經 gateway 的路由，
都代表 guard 能連到 grant 以外的地方，啟動就失敗。輸入是 /proc/net/route 的內容
（位址是 little-endian 的十六進位）。
"""

from collections.abc import Collection
from ipaddress import IPv4Address, IPv4Network

_RTF_GATEWAY = 0x2
_COLUMNS = 11


def route_problem(table: str, *, expected: Collection[IPv4Network]) -> str | None:
    """路由正好是 expected 中每個網段一條直連的路由時回傳 None，否則回傳原因。"""
    lines = table.splitlines()
    if not lines or not lines[0].startswith("Iface"):
        return "讀不到路由表"
    networks: list[IPv4Network] = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) != _COLUMNS:
            return "路由表的格式不符"
        try:
            destination, gateway, mask = (_address(fields[index]) for index in (1, 2, 7))
            flags = int(fields[3], 16)
            network = IPv4Network(f"{destination}/{mask}")
        except ValueError:
            return "路由表的格式不符"
        if gateway != IPv4Address(0) or flags & _RTF_GATEWAY:
            return "有經 gateway 的路由（含預設路由）"
        networks.append(network)
    if sorted(networks) != sorted(set(expected)):
        return "直連的網段必須正好是 scan_net 與 lab_net"
    return None


def _address(text: str) -> IPv4Address:
    if len(text) != 8:
        raise ValueError
    return IPv4Address(int.from_bytes(bytes.fromhex(text), "little"))
