"""上游位址的檢查（docs/DECISIONS.md §15.5 第 7 步；SEC-04、SEC-06）。

origin 的名稱解析出的**每一個**答案都必須合格，不是只看第一個：混合的答案（DNS rebinding、兩個
容器共用 alias）一律拒絕。合格的答案中取最小的位址，連線綁定到它。
"""

from collections.abc import Collection, Sequence
from ipaddress import IPv4Address

from secscan.targets.domain import LabNetwork, OutsideLabError, parse_ipv4

MAX_DNS_ANSWERS = 16


def pick_upstream(
    answers: Sequence[str],
    *,
    allowed: Collection[IPv4Address],
    lab: LabNetwork,
    guard: Collection[IPv4Address],
) -> IPv4Address | None:
    """每個答案都是 canonical 的 IPv4、在 allowed_ips 中、是目前 LAB_CIDR 內可用的主機位址，而且
    不是 guard 自己；都符合時回傳要連的位址，否則 None。
    """
    if not 1 <= len(answers) <= MAX_DNS_ANSWERS:
        return None
    addresses = [_acceptable(answer, allowed, lab, guard) for answer in answers]
    if any(address is None for address in addresses):
        return None
    return min(address for address in addresses if address is not None)


def _acceptable(
    answer: str,
    allowed: Collection[IPv4Address],
    lab: LabNetwork,
    guard: Collection[IPv4Address],
) -> IPv4Address | None:
    try:
        address = parse_ipv4(answer)
    except ValueError:
        return None
    if str(address) != answer or address not in allowed or address in guard:
        return None
    try:
        lab.check_host(address)
    except OutsideLabError:
        return None
    return address
