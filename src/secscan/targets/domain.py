"""target 的 domain model、origin 的嚴格解析與 lab 網段規則；只用標準函式庫。

- origin：只接受 `http://host[:port]`（結尾可以有一個 `/`）。同一個字串，不同的 URL parser 可能
  解出不同的 host，所以只接受各家解讀一致的子集（docs/DECISIONS.md §10.2、SEC-05）。
- LAB_CIDR：IP 必須是設定網段內的主機位址（§10.1）。是否檢查、用哪個網段，由呼叫端傳入。

這裡只判斷字串本身，不解析 DNS、不連線。錯誤訊息只說明原因，不含輸入（URL 可能帶帳密）。
"""

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from uuid import UUID

from secscan.core.text import require_text

TARGET_NAME_MAX_LENGTH = 100
ORIGIN_MAX_LENGTH = 256
HTTP_SCHEME = "http"
DEFAULT_HTTP_PORT = 80
MAX_PORT = 65535
HOST_LABEL_MAX_LENGTH = 63
DELETE_CHARACTER = "\x7f"

_SCHEME_AND_REST = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<rest>.*)")
# 主機名稱的一段：小寫英數字與連字號，不以連字號開頭或結尾（RFC 1123）。
_HOST_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")
_PORT = re.compile(r"[1-9][0-9]{0,4}")
# 這些字元在不同 parser 中的意義不同（例如 WHATWG 把反斜線當成斜線），一律拒絕。
_FORBIDDEN_CHARACTERS = (
    ("@", "不可包含帳密（userinfo）"),
    ("\\", "不可包含反斜線"),
    ("%", "不可包含 percent-encoding"),
    ("?", "不可包含 query"),
    ("#", "不可包含 fragment"),
    ("[", "不支援 IPv6 位址"),
    ("]", "不支援 IPv6 位址"),
)


class TargetKind(StrEnum):
    WEB = "web"
    API = "api"
    HYBRID = "hybrid"


class TargetEnvironment(StrEnum):
    """P0 只有 lab（docs/API_CONTRACT.md §3）。"""

    LAB = "lab"


class InvalidOriginError(ValueError):
    """URL 不是可接受的 origin。訊息只說明原因，不含輸入內容。"""


class OutsideLabError(ValueError):
    """IP 不是 LAB_CIDR 內的主機位址。"""


def parse_ipv4(value: str) -> IPv4Address:
    """四段十進位、沒有前導 0 的 IPv4；不接受網段、整數、十六進位或其他寫法。"""
    try:
        return IPv4Address(value)
    except AddressValueError:
        # 不接上原始例外：它的訊息含輸入內容。
        raise ValueError("不是合法的 IPv4 位址（四段十進位，不可有前導 0）") from None


@dataclass(frozen=True, slots=True)
class Origin:
    """canonical origin：scheme 固定是 http；host 是小寫的名稱或 IPv4；port 一定有值。"""

    host: str
    port: int

    def __post_init__(self) -> None:
        _check_host(self.host)
        if not 1 <= self.port <= MAX_PORT:
            raise InvalidOriginError(f"port 必須介於 1 與 {MAX_PORT} 之間")

    @property
    def ip(self) -> IPv4Address | None:
        """host 是 IPv4 時回傳位址；是名稱時回傳 None（執行時由 guard 綁定 IP）。"""
        try:
            return IPv4Address(self.host)
        except AddressValueError:
            return None

    def __str__(self) -> str:
        if self.port == DEFAULT_HTTP_PORT:
            return f"{HTTP_SCHEME}://{self.host}"
        return f"{HTTP_SCHEME}://{self.host}:{self.port}"


def parse_origin(value: str) -> Origin:
    """把使用者給的 URL 轉成 canonical origin；不合規則時拋出 InvalidOriginError。"""
    if len(value) > ORIGIN_MAX_LENGTH:
        raise InvalidOriginError(f"URL 不可超過 {ORIGIN_MAX_LENGTH} 個字元")
    if not value.isascii():
        raise InvalidOriginError("URL 只能使用 ASCII 字元（不接受全形字元或國際化網域名稱）")
    if any(character <= " " or character == DELETE_CHARACTER for character in value):
        raise InvalidOriginError("URL 不可包含空白或控制字元")
    for character, reason in _FORBIDDEN_CHARACTERS:
        if character in value:
            raise InvalidOriginError(f"URL {reason}")
    match = _SCHEME_AND_REST.fullmatch(value)
    if match is None:
        raise InvalidOriginError("URL 必須是 http://主機[:port] 的形式")
    if match["scheme"].lower() != HTTP_SCHEME:
        raise InvalidOriginError("P0 只支援 http（HTTPS 要等 CA 與 guard 的測試完成）")
    authority = match["rest"].removesuffix("/")
    if "/" in authority:
        raise InvalidOriginError("URL 只能是 origin，不可包含 path")
    host, has_port, port = authority.partition(":")
    return Origin(host=host.lower(), port=_parse_port(port) if has_port else DEFAULT_HTTP_PORT)


def _parse_port(text: str) -> int:
    if _PORT.fullmatch(text) is None or int(text) > MAX_PORT:
        raise InvalidOriginError(f"port 必須是 1 到 {MAX_PORT} 的十進位數字，不可有前導 0")
    return int(text)


def _check_host(host: str) -> None:
    if not host:
        raise InvalidOriginError("缺少主機名稱")
    labels = host.split(".")
    if labels[-1][:1].isdigit():
        # 最後一段以數字開頭：WHATWG 會試著當成 IPv4（含八進位、十六進位與整數寫法），
        # 這裡只接受標準的四段十進位，其他一律拒絕。
        try:
            parse_ipv4(host)
        except ValueError:
            raise InvalidOriginError(
                "IP 位址必須是四段十進位，不可有前導 0、十六進位或整數寫法"
            ) from None
        return
    if host == "localhost" or host.endswith(".localhost"):
        raise InvalidOriginError("不可指向本機（localhost）")
    if not all(_is_host_label(label) for label in labels):
        raise InvalidOriginError(
            "主機名稱只能由小寫英數字與連字號組成；每一段不可為空、"
            f"不可以連字號開頭或結尾，最長 {HOST_LABEL_MAX_LENGTH} 個字元"
        )


def _is_host_label(label: str) -> bool:
    # 第 3、4 個字元是 "--" 的標籤保留給國際化網域名稱（例如 xn--，RFC 5891），不接受。
    return (
        len(label) <= HOST_LABEL_MAX_LENGTH
        and _HOST_LABEL.fullmatch(label) is not None
        and label[2:4] != "--"
    )


@dataclass(frozen=True, slots=True)
class LabNetwork:
    """LAB_ONLY 時允許的靶場網段（設定 LAB_CIDR，docs/DECISIONS.md §10.1）。

    最後一個主機位址保留給 egress guard（§15.6）：guard 在 lab_net 上固定用它，target 與 grant
    都不可指向它（否則掃描流量會經 guard 送回 guard 自己）。
    """

    cidr: IPv4Network

    def __post_init__(self) -> None:
        if not isinstance(self.cidr, IPv4Network):
            raise TypeError("LabNetwork 需要 IPv4Network")

    @property
    def guard_address(self) -> IPv4Address:
        return self.cidr.broadcast_address - 1

    def check_host(self, address: IPv4Address) -> None:
        """address 必須在網段內，而且不是網段位址、廣播位址或保留給 guard 的位址。"""
        edges = (self.cidr.network_address, self.cidr.broadcast_address)
        if address not in self.cidr or address in edges:
            raise OutsideLabError(
                f"IP 必須是 LAB_CIDR（{self.cidr}）內的主機位址，不可是網段或廣播位址"
            )
        if address == self.guard_address:
            raise OutsideLabError(
                f"IP 不可是 LAB_CIDR（{self.cidr}）的最後一個主機位址：它保留給 egress guard"
            )

    def check_origin(self, origin: Origin) -> None:
        """host 是 IP 時同樣要在 LAB_CIDR 內；是名稱時由 guard 在執行時綁定 IP。"""
        if origin.ip is not None:
            self.check_host(origin.ip)


@dataclass(frozen=True, slots=True)
class NewTarget:
    """建立 target 的輸入。origin 已正規化；是否在 LAB_CIDR 內由 service 以當下的設定檢查。"""

    project_id: UUID
    name: str
    kind: TargetKind
    origin: Origin
    environment: TargetEnvironment = TargetEnvironment.LAB

    def __post_init__(self) -> None:
        require_text(self.name, field="name", max_length=TARGET_NAME_MAX_LENGTH)


@dataclass(frozen=True, slots=True)
class Target:
    id: UUID
    project_id: UUID
    name: str
    kind: TargetKind
    origin: Origin
    environment: TargetEnvironment
    enabled: bool
    created_at: datetime


@dataclass(frozen=True, slots=True)
class TargetChange:
    """修改前後的 target（audit 只記有變動的欄位）。"""

    before: Target
    after: Target


@dataclass(frozen=True, slots=True)
class TargetUpdate:
    """PATCH 可以修改的欄位，None 代表不修改。origin 不能改：要改就建立新的 target。"""

    name: str | None = None
    enabled: bool | None = None

    def __post_init__(self) -> None:
        if self.name is None and self.enabled is None:
            raise ValueError("至少要修改一個欄位（name 或 enabled）")
        if self.name is not None:
            require_text(self.name, field="name", max_length=TARGET_NAME_MAX_LENGTH)
