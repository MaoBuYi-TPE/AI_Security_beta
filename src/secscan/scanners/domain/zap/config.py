"""zap.properties（docs/DECISIONS.md §18.3）：guard 的 proxy 帳密與 ZAP 自己的速率限制。

runner 寫成 0400 的 secret 檔，ZAP 以 -configfile 讀取。ZAP 對不認得的 key 不報錯，所以 key 是
固定的字面值（T14 以鎖定的映像確認讀得到）；值都以嚴格的字元集核對，一行一個 key，不會被值中的
換行或反斜線改寫。回傳 SecretValue：含 token，repr 與 str 都不顯示內容。
"""

import re
from ipaddress import IPv4Address

from secscan.auth_profiles.domain.credentials import SecretValue
from secscan.grants.domain.scope import MAX_REQUESTS_PER_SECOND
from secscan.guard.domain.credentials import PROXY_REALM, ProxyCredentials

# secrets.token_urlsafe(32)：43 個 base64url 字元（guard 只接受這個格式）。
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_MAX_PORT = 65535
_PROXY = "network.connection.httpProxy"
_RATE_LIMIT = "network.ratelimit.rules.rule(0)"


def zap_properties(
    *,
    address: IPv4Address,
    port: int,
    credentials: ProxyCredentials,
    requests_per_second: int,
) -> SecretValue:
    if _TOKEN.fullmatch(credentials.token) is None:
        raise ValueError("proxy 的 token 必須是 43 個 base64url 字元")
    if not 1 <= port <= _MAX_PORT:
        raise ValueError(f"guard 的 port 必須介於 1 與 {_MAX_PORT} 之間")
    if not 1 <= requests_per_second <= MAX_REQUESTS_PER_SECOND:
        raise ValueError(f"速率必須介於 1 與 {MAX_REQUESTS_PER_SECOND} req/s 之間")
    lines = (
        f"{_PROXY}.enabled=true",
        f"{_PROXY}.host={address}",
        f"{_PROXY}.port={port}",
        f"{_PROXY}.authEnabled=true",
        f"{_PROXY}.realm={PROXY_REALM}",
        f"{_PROXY}.username={credentials.run_id}",
        f"{_PROXY}.password={credentials.token}",
        f"{_RATE_LIMIT}.description=secscan",
        f"{_RATE_LIMIT}.enabled=true",
        f"{_RATE_LIMIT}.matchStr=.*",
        f"{_RATE_LIMIT}.regex=true",
        f"{_RATE_LIMIT}.reqsPerSec={requests_per_second}",
        f"{_RATE_LIMIT}.groupBy=RULE",
    )
    return SecretValue("".join(f"{line}\n" for line in lines))
