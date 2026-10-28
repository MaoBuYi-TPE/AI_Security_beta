"""guard 的 DNS 解析（docs/DECISIONS.md §15.5 第 7 步）：只解析 policy origin 的名稱、
只要 IPv4、有逾時；錯誤一律轉成 ResolveError。測試不連網：替換 event loop 的 getaddrinfo。
"""

import asyncio
import socket
from typing import Any

import pytest

from secscan.guard.resolver import BoundedResolver, ResolveError, resolve_ipv4

_Info = tuple[Any, Any, Any, Any, tuple[str, int]]


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _patch(monkeypatch: pytest.MonkeyPatch, result: object, *, delay: float = 0.0) -> list[Any]:
    calls: list[Any] = []

    async def fake(self: object, host: str, port: object, **kwargs: Any) -> list[_Info]:
        calls.append((host, port, kwargs))
        if delay:
            await asyncio.sleep(delay)
        if isinstance(result, BaseException):
            raise result
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in result]  # type: ignore[attr-defined]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", fake)
    return calls


def test_returns_unique_ipv4_answers_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch(monkeypatch, ["10.89.7.21", "10.89.7.20", "10.89.7.21"])

    assert _run(resolve_ipv4("lab-target")) == ("10.89.7.21", "10.89.7.20")
    [(host, port, kwargs)] = calls
    assert host == "lab-target"
    assert port is None
    assert kwargs["family"] == socket.AF_INET
    assert kwargs["type"] == socket.SOCK_STREAM


@pytest.mark.parametrize(
    "error", [socket.gaierror(-3, "Temporary failure"), OSError(1, "x"), UnicodeError("idna")]
)
def test_lookup_errors_become_resolve_errors(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    _patch(monkeypatch, error)

    with pytest.raises(ResolveError):
        _run(resolve_ipv4("lab-target"))


def test_slow_lookups_time_out(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, ["10.89.7.20"], delay=1.0)

    with pytest.raises(ResolveError, match="逾時"):
        _run(resolve_ipv4("lab-target", timeout=0.01))


def test_empty_answers_are_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [])

    with pytest.raises(ResolveError):
        _run(resolve_ipv4("lab-target"))


def test_concurrent_lookups_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """DNS 卡住時，同時進行的解析有上限（不佔滿執行緒池與 pids；審查建議）。"""
    active = [0, 0]

    async def slow(self: object, host: str, port: object, **kwargs: Any) -> list[_Info]:
        active[0] += 1
        active[1] = max(active[1], active[0])
        await asyncio.sleep(0.01)
        active[0] -= 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.89.7.20", 0))]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", slow)

    async def scenario() -> None:
        resolver = BoundedResolver(limit=2)
        await asyncio.gather(*(resolver("lab-target") for _ in range(10)))

    asyncio.run(scenario())

    assert active[1] == 2
