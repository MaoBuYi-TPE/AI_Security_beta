"""guard 的流量明細與認證的健康度（docs/DECISIONS.md §20.3、§20.4）。

guard 的 telemetry 在 tmpfs、6 小時後刪除：worker 解析時把明細寫進 result_details，之後仍查得到。
- 流量明細：summary 的轉送數、各原因的拒絕數、是否用盡預算、第一個與最後一個轉送的時間，以及
  telemetry 中得到上游回應的數量。telemetry 讀不到或和轉送數對不上（§16.6 的條件）時，回應數與
  認證的計數是 None：殘缺的檔案不能當作依據。
- 認證的健康度：帶認證 header、得到上游回應的請求中，被接受（401、403 以外）與被拒絕的數量。
  同一個 (method, path) 接受過憑證、最後一次卻被拒絕，是「退化」；退化的 operation 達到門檻就是
  失效（token 在掃描中途過期）。不管憑證的公開端點拿過期的 token 仍回 200，所以不能只看最後幾個
  請求。auth profile 的 preflight 端點是已知需要認證的探針：掃描中帶憑證打它被拒絕，憑證在那時已
  無效（也涵蓋 preflight 之後、掃描開始之前就過期，沒有任何退化可看的情形）。帶認證的請求一個都
  沒有被接受（只有被拒絕）也算：ZAP 沒打到探針時的備援。
  這只是揭露（coverage 的限制），不重新登入（§16.8 延後）。
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from secscan.guard.domain.telemetry import RunSummary
from secscan.scans.domain.coverage import REJECTED_CREDENTIALS, Exchange, telemetry_complete

# 一個 operation 最後一次被拒絕可能是 payload 造成的；兩個以上才判定為失效（T16 量測，§20.4）。
MIN_REGRESSED_OPERATIONS = 2


@dataclass(frozen=True, slots=True)
class AuthHealth:
    accepted: int
    rejected: int
    regressed: int
    # 帶憑證打 preflight 的端點被拒絕的次數（沒有綁定 auth profile 時是 0）。
    probe_rejected: int = 0

    @property
    def lost(self) -> bool:
        never_accepted = self.accepted == 0 and self.rejected > 0
        return (
            self.regressed >= MIN_REGRESSED_OPERATIONS or self.probe_rejected > 0 or never_accepted
        )


NO_AUTHENTICATED_TRAFFIC = AuthHealth(accepted=0, rejected=0, regressed=0, probe_rejected=0)


@dataclass(frozen=True, slots=True)
class GuardTraffic:
    forwarded: int
    denied: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    exhausted: bool = False
    first_at: float | None = None
    last_at: float | None = None
    # telemetry 不能用時是 None。
    answered: int | None = None
    auth: AuthHealth | None = None


def auth_health(
    exchanges: Iterable[Exchange], *, probe: tuple[str, str] | None = None
) -> AuthHealth:
    """exchanges 依轉送的順序（guard 依序號寫入）；probe 是 preflight 的 (method, path)。"""
    accepted = rejected = probe_rejected = 0
    ever_accepted: set[tuple[str, str]] = set()
    last_rejected: dict[tuple[str, str], bool] = {}
    for exchange in exchanges:
        if not exchange.authenticated or exchange.status is None:
            continue
        key = (exchange.method, exchange.path)
        refused = exchange.status in REJECTED_CREDENTIALS
        if refused:
            rejected += 1
            probe_rejected += key == probe
        else:
            accepted += 1
            ever_accepted.add(key)
        last_rejected[key] = refused
    regressed = sum(1 for key in ever_accepted if last_rejected[key])
    return AuthHealth(
        accepted=accepted, rejected=rejected, regressed=regressed, probe_rejected=probe_rejected
    )


def guard_traffic(
    summary: RunSummary | None,
    exchanges: tuple[Exchange, ...] | None,
    *,
    probe: tuple[str, str] | None = None,
) -> GuardTraffic | None:
    """summary 是 None：guard 沒有這個 run 的紀錄（沒有任何請求經過，或檔案已不在）。

    guard 記下轉送 0 個時，沒有 telemetry 的檔案也是有依據的（和 zap 的判定相同）。
    """
    if summary is None:
        return None
    answered: int | None = None
    health: AuthHealth | None = None
    if summary.forwarded == 0:
        answered, health = 0, NO_AUTHENTICATED_TRAFFIC
    elif exchanges is not None and telemetry_complete(exchanges, forwarded=summary.forwarded):
        answered = sum(1 for exchange in exchanges if exchange.status is not None)
        health = auth_health(exchanges, probe=probe)
    return GuardTraffic(
        forwarded=summary.forwarded,
        denied=MappingProxyType(dict(sorted(summary.denied.items()))),
        exhausted=summary.exhausted,
        first_at=summary.first_at,
        last_at=summary.last_at,
        answered=answered,
        auth=health,
    )
