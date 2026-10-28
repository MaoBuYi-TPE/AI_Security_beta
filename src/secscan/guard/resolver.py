"""guard 的 DNS 解析（docs/DECISIONS.md §15.5 第 7 步）。

只解析 policy origin 的名稱（guard 不替 client 解析任意名稱，不會變成 DNS 外洩的管道）；只要 IPv4；
2 秒逾時。答案的檢查（每一個都要合格）在 domain.addresses。
"""

import asyncio
import socket

DNS_TIMEOUT_SECONDS = 2.0


class ResolveError(Exception):
    """解析失敗或逾時。"""


async def resolve_ipv4(host: str, *, timeout: float = DNS_TIMEOUT_SECONDS) -> tuple[str, ...]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM),
            timeout,
        )
    except TimeoutError:
        raise ResolveError("DNS 解析逾時") from None
    except (OSError, UnicodeError):
        raise ResolveError("DNS 解析失敗") from None
    answers = tuple(dict.fromkeys(str(info[4][0]) for info in infos))
    if not answers:
        raise ResolveError("DNS 沒有回傳 IPv4 位址")
    return answers
