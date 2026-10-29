"""preflight 的執行與判斷（docs/DECISIONS.md §12.5、§16.5）。

- plan：T03 的 busybox（同一個 digest）執行 `/bin/sh -c <PREFLIGHT_SCRIPT>`。script 是常數，不含
  任何輸入；輸入只有 in/request（完整的 URL）。proxy 的帳密與目標的認證 header 從 secrets 目錄的
  檔案讀進管線（printf 是 ash 的內建指令），不進 argv、環境變數或 log。帶認證與匿名各送一次
  HTTP/1.0 GET（經 guard），原始回應存成 out/authenticated.http 與 out/anonymous.http。
- 解析：原始的 HTTP 回應；有大小上限，格式不合就當成沒有回應（None）。chunked 會解碼。
- 判斷：§12.5 的比對（auth_profiles.domain.preflight.matches）加上匿名的對照。
"""

import json
import re
from dataclasses import dataclass
from uuid import UUID

from secscan.auth_profiles.domain.preflight import NOT_JSON, Preflight, matches
from secscan.grants.domain.scope import path_problem
from secscan.guard.domain.requests import GUARD_HEADER
from secscan.scanners.domain.plan import ExecutionPlan, ImageReference, InputFile, ResourceLimits
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.preflight import PreflightResult
from secscan.targets.domain import InvalidOriginError, parse_origin

# T03 鎖定的 busybox（docs/TOOLS.md §1），和 fake 引擎相同。
PREFLIGHT_IMAGE = ImageReference.parse(
    "busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"
)
PREFLIGHT_MAX_WALL_CLOCK_SECONDS = 60
PREFLIGHT_MEMORY_BYTES = 64 * 1024 * 1024
PREFLIGHT_NANO_CPUS = 500_000_000
PREFLIGHT_PIDS = 64
REQUEST_FILE = "request"
AUTHENTICATED_OUTPUT = "authenticated.http"
ANONYMOUS_OUTPUT = "anonymous.http"
MAX_RESPONSE_BYTES = 64 * 1024
RESPONSE_WAIT_SECONDS = 5
_HTTP_PREFIX = "http://"

# busybox ash。set -u：變數沒有值就停止；每個請求失敗都繼續（沒有回應由 worker 判斷）。
# 送完請求之後 stdin 再開著 RESPONSE_WAIT_SECONDS 秒：nc 在 stdin 結束時會半關閉連線，mitmproxy
# 把它當成 client 斷線、丟掉回應（live 實測）。nc -w：連線與最後的讀取最多等這麼久；
# head -c：回應最多 MAX_RESPONSE_BYTES + 1 bytes。
PREFLIGHT_SCRIPT = f"""set -u
umask 077
proxy=$(cat /scan/secret/proxy-url)
rest=${{proxy#http://}}
credentials=${{rest%@*}}
endpoint=${{rest##*@}}
host=${{endpoint%:*}}
port=${{endpoint##*:}}
basic=$(printf '%s' "$credentials" | base64 -w 0)
url=$(cat /scan/in/{REQUEST_FILE})
authority=${{url#http://}}
authority=${{authority%%/*}}
send() {{
  {{
    printf 'GET %s HTTP/1.0\\r\\nHost: %s\\r\\n' "$url" "$authority"
    printf 'Proxy-Authorization: Basic %s\\r\\n' "$basic"
    if [ "$1" = authenticated ]; then
      cat /scan/secret/auth-header
      printf '\\r\\n'
    fi
    printf 'Accept: application/json\\r\\nConnection: close\\r\\n\\r\\n'
    sleep {RESPONSE_WAIT_SECONDS}
  }} | nc -w {RESPONSE_WAIT_SECONDS} "$host" "$port" | head -c {MAX_RESPONSE_BYTES + 1} \\
    > "/scan/out/$1.http" || true
}}
send authenticated
send anonymous
"""

_STATUS_LINE = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?")
# header 分成名稱與值各自比對（沒有重疊的量詞）：靶機控制回應，有歧義的 regex 會災難性回溯
# （審查發現的 ReDoS）。
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_HEADER_VALUE = re.compile(rb"[\x20-\x7e\t]*")
_CHUNK_SIZE = re.compile(rb"([0-9A-Fa-f]{1,8})(?:;[\x20-\x7e]*)?")


def plan_preflight_run(
    *, run_id: UUID, scan_id: UUID, url: str, max_duration_seconds: int
) -> ExecutionPlan:
    """url 是 target 的 origin 加上 preflight 的 path（runner 組好、已在 grant 的範圍內）。"""
    _check_url(url)
    return ExecutionPlan(
        run_id=run_id,
        scan_id=scan_id,
        engine=Engine.PREFLIGHT,
        image=PREFLIGHT_IMAGE,
        entrypoint=("/bin/sh", "-c"),
        arguments=(PREFLIGHT_SCRIPT,),
        environment=(),
        inputs=(InputFile(REQUEST_FILE, url.encode("ascii")),),
        target_auth=True,
        limits=ResourceLimits(
            memory_bytes=PREFLIGHT_MEMORY_BYTES,
            nano_cpus=PREFLIGHT_NANO_CPUS,
            pids=PREFLIGHT_PIDS,
            wall_clock_seconds=min(max_duration_seconds, PREFLIGHT_MAX_WALL_CLOCK_SECONDS),
        ),
    )


def _check_url(url: str) -> None:
    authority, slash, path = url.removeprefix(_HTTP_PREFIX).partition("/")
    problem = "preflight 的 URL 必須是 http://<target 的 origin><path>（沒有 query 與帳密）"
    if not url.startswith(_HTTP_PREFIX) or not slash or path_problem(f"/{path}") is not None:
        raise ValueError(problem)
    try:
        parse_origin(f"{_HTTP_PREFIX}{authority}")
    except InvalidOriginError:
        raise ValueError(problem) from None
    if "@" in authority:
        raise ValueError(problem)


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    headers: tuple[tuple[str, str], ...]  # (小寫的名稱, 值)
    body: bytes

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        return next((value for key, value in self.headers if key == wanted), None)


def parse_response(raw: bytes) -> HttpResponse | None:
    """原始的 HTTP/1.x 回應；超過上限、缺少 header 的結尾或格式不合時回傳 None。"""
    if len(raw) > MAX_RESPONSE_BYTES:
        return None
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        return None
    status_line, *lines = head.split(b"\r\n")
    status = _STATUS_LINE.fullmatch(status_line)
    if status is None:
        return None
    headers: list[tuple[str, str]] = []
    for line in lines:
        name, separator, value = line.partition(b":")
        value = value.strip(b" \t")
        if not separator or _HEADER_NAME.fullmatch(name) is None:
            return None
        if _HEADER_VALUE.fullmatch(value) is None:
            return None
        headers.append((name.decode("ascii").lower(), value.decode("ascii")))
    if any(name == "transfer-encoding" and "chunked" in value.lower() for name, value in headers):
        decoded = _dechunk(body)
        if decoded is None:
            return None
        body = decoded
    return HttpResponse(status=int(status[1]), headers=tuple(headers), body=body)


def _dechunk(body: bytes) -> bytes | None:
    chunks: list[bytes] = []
    position = 0
    while True:
        end = body.find(b"\r\n", position)
        size = _CHUNK_SIZE.fullmatch(body[position:end]) if end >= 0 else None
        if size is None:
            return None
        length, start = int(size[1], 16), end + 2
        if length == 0:
            return b"".join(chunks)
        if body[start + length : start + length + 2] != b"\r\n":
            return None
        chunks.append(body[start : start + length])
        position = start + length + 2


def evaluate(
    preflight: Preflight, authenticated: bytes | None, anonymous: bytes | None
) -> PreflightResult:
    """帶認證的回應決定結果；匿名的回應證明端點有受保護。匿名的也符合，或沒有匿名的有效回應
    （沒有輸出、被 guard 拒絕），都證明不了認證有效 → inconclusive（審查發現）。
    """
    response = parse_response(authenticated) if authenticated else None
    if response is None:
        return PreflightResult.NOT_EXECUTED
    if response.header(GUARD_HEADER) is not None:
        return PreflightResult.BLOCKED
    if not _passes(preflight, response):
        return PreflightResult.FAILED
    control = parse_response(anonymous) if anonymous else None
    if control is None or control.header(GUARD_HEADER) is not None or _passes(preflight, control):
        return PreflightResult.INCONCLUSIVE
    return PreflightResult.PASSED


def _passes(preflight: Preflight, response: HttpResponse) -> bool:
    return matches(preflight, response.status, _json(response.body))


def _json(body: bytes) -> object:
    """嚴格的 JSON（UTF-8、不接受 NaN 與 Infinity）；不是 JSON 時回傳 NOT_JSON。"""

    def reject(_: str) -> object:
        raise ValueError("非標準的數值")

    try:
        return json.loads(body.decode("utf-8"), parse_constant=reject)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return NOT_JSON
