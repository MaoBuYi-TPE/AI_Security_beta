"""遮罩：寫進 audit、log 或一般 API 回應的資料先經過這裡（CLAUDE.md §9）。只用標準函式庫。

- 欄位名稱看起來是秘密（authorization、cookie、password、secret、token、API key、key hash、
  credential、private key、session、signature、auth、jwt…）：整個值換成 REDACTED，不論型別。
  名稱先做 NFKC 正規化（全形字元也認得）。
- 文字中的平台 API key、`Bearer`／`Basic` 認證值與 JWT：換成 REDACTED。遮掉一段之後，前後文字
  可能才成為新的比對（例如 key 緊接 bearer），所以重複遮罩到結果不再改變。
- 大小有上限：字串最多 MAX_STRING_LENGTH 個字元，清單與物件最多 MAX_ITEMS 項；
  最外層算第 0 層，第 MAX_DEPTH 層的容器換成 TRUNCATED。

先遮罩再截斷，秘密剛好跨過截斷位置時也不會留下一段。結果仍是 JSON 值，重複套用結果不變
（audit 的 domain 檢查依賴這一點）。

取捨與已知限制（依名稱與樣式判斷，不保證認得所有秘密；呼叫端仍應只放必要的欄位）：
- 寧可多遮：例如名稱裡的「Basic scan」也會被當成認證值遮掉。
- 緊接在英數字後面的 JWT 不遮（為了讓比對維持線性時間）；前面有空白、`=`、`:`、引號等就會遮。
- 還不處理：HAR 那種 `{"name": "Cookie", "value": …}` 成對的格式、URL 中的帳密與 query 參數、
  `password=…` 之類的文字。T08（認證設定）與 M3（證據遮罩）需要時再擴充，並補對應的測試。
"""

import re
import unicodedata
from collections.abc import Mapping, Sequence

from secscan.core.json_types import JsonObject, JsonValue

REDACTED = "<REDACTED>"
TRUNCATED = "<TRUNCATED>"
ELLIPSIS = "…"
MAX_DEPTH = 4
MAX_ITEMS = 50
MAX_STRING_LENGTH = 256
# 每一輪至少遮掉一段原文，一般輸入兩、三輪就不再變化；到了上限仍在變化就整段遮掉（fail closed）。
MAX_MASK_PASSES = 16

# 名稱轉小寫、去掉 - 與 _ 之後，包含這些片段就視為秘密。
_SENSITIVE_NAME_PARTS = (
    "authorization",
    "cookie",
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "keyhash",
    "credential",
    "privatekey",
    "session",
    "signature",
    "connectionstring",
)
# 名稱中以 -、_ 等分隔的某一段完全等於這些字才算，避免 keyboard、monkey、author 之類的誤判。
_SENSITIVE_NAME_SEGMENTS = frozenset({"key", "pwd", "pass", "auth", "jwt", "bearer", "dsn"})
_NAME_SEPARATORS = re.compile(r"[^0-9a-z]+")

_SECRET_TEXT = re.compile(
    # 平台 API key
    r"secscan_[0-9a-f]{16}_[0-9a-f]{64}"
    # Authorization 的認證值（RFC 6750 的 b64token 字元集）
    r"|\b(?:bearer|basic)\s+[A-Za-z0-9\-._~+/]+=*"
    # JWT（header 與 payload 都是以 eyJ 開頭的 base64url JSON）。前面不可緊接 base64url 字元：
    # 否則 eyJeyJeyJ… 這種輸入會讓比對變成 O(n²)。
    r"|(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
    re.IGNORECASE,
)


def is_sensitive_key(name: str) -> bool:
    normalized = unicodedata.normalize("NFKC", name).lower()
    compact = normalized.replace("-", "").replace("_", "")
    segments = set(_NAME_SEPARATORS.split(normalized))
    return bool(segments & _SENSITIVE_NAME_SEGMENTS) or any(
        part in compact for part in _SENSITIVE_NAME_PARTS
    )


def redact_object(data: Mapping[str, JsonValue]) -> JsonObject:
    """遮罩一個 JSON 物件（例如 audit 的 redacted_changes），回傳新的 dict，不修改輸入。"""
    return _redact_mapping(data, depth=0)


def redact_json(value: JsonValue) -> JsonValue:
    """遮罩任意 JSON 值，回傳新的值，不修改輸入。"""
    return _redact(value, depth=0)


def _redact(value: JsonValue, depth: int) -> JsonValue:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, Mapping):
        return TRUNCATED if depth >= MAX_DEPTH else _redact_mapping(value, depth)
    # tuple 不是 JSON 型別，但 json.dumps 會接受；當成 list 處理，不能因此繞過遮罩。
    if isinstance(value, list | tuple):
        return TRUNCATED if depth >= MAX_DEPTH else _redact_list(value, depth)
    return value


def _redact_mapping(data: Mapping[str, JsonValue], depth: int) -> JsonObject:
    redacted: JsonObject = {}
    for count, (name, value) in enumerate(data.items()):
        if count == MAX_ITEMS:
            redacted[TRUNCATED] = TRUNCATED
            break
        redacted[_redact_text(name)] = (
            REDACTED if is_sensitive_key(name) else _redact(value, depth + 1)
        )
    return redacted


def _redact_list(items: Sequence[JsonValue], depth: int) -> list[JsonValue]:
    redacted = [_redact(item, depth + 1) for item in items[:MAX_ITEMS]]
    if len(items) > MAX_ITEMS:
        redacted.append(TRUNCATED)
    return redacted


def _redact_text(text: str) -> str:
    masked = _mask(text)
    if len(masked) > MAX_STRING_LENGTH:
        return masked[:MAX_STRING_LENGTH] + ELLIPSIS
    return masked


def _mask(text: str) -> str:
    current = text
    for _ in range(MAX_MASK_PASSES):
        masked = _SECRET_TEXT.sub(REDACTED, current)
        if masked == current:
            return masked
        current = masked
    return REDACTED
