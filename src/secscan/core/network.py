"""LAB_CIDR 的規則（docs/DECISIONS.md §10.1、§15.6）；只用標準函式庫，config 與 egress guard 共用。

只接受 RFC 1918 私有網段內、前綴 /16 到 /30 的網段：太寬（例如 10.0.0.0/8）可能涵蓋校園網路，
/31、/32 沒有一般意義的網段與廣播位址。
"""

from ipaddress import IPv4Network

RFC1918_NETWORKS = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)
MIN_LAB_PREFIX_LENGTH = 16
MAX_LAB_PREFIX_LENGTH = 30


def lab_cidr_problem(network: IPv4Network) -> str | None:
    """不合規則時回傳原因（不含輸入），合規則時回傳 None。"""
    if not any(network.subnet_of(private) for private in RFC1918_NETWORKS):
        return "LAB_CIDR 必須在 RFC 1918 私有網段內（10/8、172.16/12、192.168/16）"
    if not MIN_LAB_PREFIX_LENGTH <= network.prefixlen <= MAX_LAB_PREFIX_LENGTH:
        return f"LAB_CIDR 的前綴長度必須介於 /{MIN_LAB_PREFIX_LENGTH} 與 /{MAX_LAB_PREFIX_LENGTH}"
    return None
