"""一個 run 的出站設定（docs/DECISIONS.md §15.3、§15.4、§15.7）：proxy 帳密與 guard 的 policy。

- token 每個 run 重新產生；policy 只存 sha256，掃描容器拿到 0400 的 proxy-url 檔。
- not_after = min(grant 的 valid_until, 啟動時間 + plan 的牆鐘上限)。
- renew_until = DB 心跳成功之前讀到的時間 + lease 的長度：只在心跳成功之後寫入，runner 當掉時
  guard 最晚在 lease 到期時停止放行（dead-man switch）。
- 封鎖後不再續約；還沒寫入就封鎖或刪除，不產生任何檔案。時間一律取整數秒（無條件捨去）。
"""

import math
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Self

from secscan.grants.domain.scope import Scope
from secscan.guard.config import GUARD_PORT
from secscan.guard.domain.credentials import (
    ProxyCredentials,
    new_token,
    proxy_url,
    token_digest,
)
from secscan.guard.domain.policy import Policy, PolicyState
from secscan.runner.guard import GuardChannel
from secscan.scans.domain.model import Lease
from secscan.scans.queue import EgressScope
from secscan.targets.domain import parse_ipv4

MAX_PORT = 65535


@dataclass(frozen=True, slots=True)
class GuardEndpoint:
    """掃描容器連 guard 的位址（guard 在 scan_net 上的固定 IP 與 port）。"""

    address: IPv4Address
    port: int = GUARD_PORT

    @classmethod
    def parse(cls, text: str) -> Self:
        host, separator, port = text.rpartition(":")
        if not separator or not port.isdigit() or port != str(int(port)):
            raise ValueError("GUARD 的位址必須是 IPv4:port（例如 10.89.8.254:8080）")
        try:
            address = parse_ipv4(host)
        except ValueError:
            raise ValueError("GUARD 的位址必須是四段十進位的 IPv4") from None
        if not 1 <= int(port) <= MAX_PORT:
            raise ValueError(f"GUARD 的 port 必須介於 1 與 {MAX_PORT}")
        return cls(address=address, port=int(port))

    @property
    def listen(self) -> str:
        return f"{self.address}:{self.port}"


class RunEgress:
    def __init__(
        self,
        channel: GuardChannel,
        policy: Policy,
        credentials: ProxyCredentials,
        endpoint: GuardEndpoint,
    ) -> None:
        self._channel = channel
        self._policy = policy
        self._credentials = credentials
        self._endpoint = endpoint
        self._written = False

    @classmethod
    def open(
        cls,
        channel: GuardChannel,
        *,
        lease: Lease,
        egress: EgressScope,
        endpoint: GuardEndpoint,
        now: float,
        wall_clock_seconds: int,
        renew_until: float,
    ) -> Self:
        token = new_token()
        grant = egress.scope
        policy = Policy(
            run_id=lease.run_id,
            scan_id=lease.scan_id,
            state=PolicyState.ACTIVE,
            token_sha256=token_digest(token),
            not_after=min(
                math.floor(egress.valid_until.timestamp()), math.floor(now) + wall_clock_seconds
            ),
            renew_until=math.floor(renew_until),
            scope=Scope(
                origins=(egress.origin,),
                ips=grant.ips,
                paths=grant.paths,
                allow_all_paths=grant.allow_all_paths,
                excluded_paths=grant.excluded_paths,
                methods=grant.methods,
            ),
            budget=egress.budget,
            auth_header=egress.auth_header,
        )
        return cls(channel, policy, ProxyCredentials(lease.run_id, token), endpoint)

    def __repr__(self) -> str:
        return f"RunEgress(run_id={self._policy.run_id}, state={self._policy.state.value})"

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def proxy_url(self) -> str:
        """寫進掃描容器的 proxy-url 檔（含 token；不可寫進 log、label 或事件）。"""
        return proxy_url(self._credentials, host=self._endpoint.address, port=self._endpoint.port)

    def activate(self) -> None:
        # 先記下：寫入失敗時檔案仍可能已經生效（os.replace 之後的 fsync 失敗），之後的封鎖與刪除
        # 都要處理它（審查發現）。
        self._written = True
        self._channel.write(self._policy)

    def renew(self, renew_until: float) -> None:
        if self._policy.state is PolicyState.BLOCKED:
            return
        renewed = self._policy.renewed(math.floor(renew_until))
        self._channel.write(renewed)
        self._policy = renewed
        self._written = True

    def block(self) -> None:
        if not self._written or self._policy.state is PolicyState.BLOCKED:
            return
        blocked = self._policy.blocked()
        self._channel.write(blocked)
        self._policy = blocked

    def discard(self) -> None:
        if self._written:
            self._channel.remove(self._policy.run_id)
