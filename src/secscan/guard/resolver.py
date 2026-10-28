"""guard 的 DNS 解析（docs/DECISIONS.md §15.5 第 7 步）。

只解析 policy origin 的名稱（guard 不替 client 解析任意名稱，不會變成 DNS 外洩的管道）；只要 IPv4；
2 秒逾時。答案的檢查（每一個都要合格）在 domain.addresses。
"""

import asyncio
import socket

DNS_TIMEOUT_SECONDS = 2.0
# 同時進行的解析上限：DNS 卡住時不佔滿執行緒池與 pids（審查建議）。逾時之後執行緒可能還在等，
# 所以這是近似的上限；超過時等待，等待的時間也算在逾時內。
MAX_CONCURRENT_LOOKUPS = 8


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


class BoundedResolver:
    """限制同時進行的解析數量；必須在 guard 的 event loop 內使用。"""

    def __init__(
        self, *, limit: int = MAX_CONCURRENT_LOOKUPS, timeout: float = DNS_TIMEOUT_SECONDS
    ) -> None:
        self._slots = asyncio.Semaphore(limit)
        self._timeout = timeout

    async def __call__(self, host: str) -> tuple[str, ...]:
        async with self._slots:
            return await resolve_ipv4(host, timeout=self._timeout)
