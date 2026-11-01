"""Nuclei 凍結清單的純函式：解析 nuclei -tl 輸出、擷取模板 id、內容閘門、lock 讀寫與對帳（T17）。

產生器（tools/freeze_nuclei_templates.py）在容器內跑 nuclei -tl、讀模板檔、算 sha256，再用這裡的
純函式整理成 lock 檔；載入與驗證（policy.py、測試）也用同一組函式。全部只用標準函式庫，不連網、
不碰容器。lock 檔每行格式固定為 `id sha256 path`。
"""

import re
from collections import Counter
from collections.abc import Collection, Sequence
from dataclasses import dataclass

# http/ 底下的相對路徑：每段以英數或底線開頭，不含 `..` 或空段（擋路徑穿越）。
_SEGMENT = r"[A-Za-z0-9_][A-Za-z0-9._-]*"
_HTTP_PATH = rf"http/(?:{_SEGMENT}/)*{_SEGMENT}\.yaml"
# nuclei -tl 會印 banner、讀不到 nuclei-ignore 的 ERR 與「Listing available」標題；真正的模板是每行
# 一個絕對路徑。只收 /templates/http/*.yaml（一律 http；非 http 協定在型別過濾與內容閘門排除）。
_TL_LINE_RE = re.compile(rf"^/templates/({_HTTP_PATH})$")
# 模板 id 是頂層（行首無縮排）、整行只有一個純量；`id: foo bar` 或 `id: "x"` 會回 None 讓產生器大聲
# 失敗。nuclei-templates 用 CRLF，所以允許 id 後面有一個 \r（否則 MULTILINE 的 $ 在 \r 前不成立）。
_ID_RE = re.compile(r"^id:[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)[ \t]*\r?$", re.MULTILINE)
# lock 檔每行：id、64 位小寫十六進位 sha256、http/ 底下的相對路徑。
_LOCK_RE = re.compile(rf"^(\S+) ([0-9a-f]{{64}}) ({_HTTP_PATH})$")

# 內容閘門（CLAUDE.md §7）：凍結清單只收純 http 模板。-pt http 擋不住多協定模板（nuclei 以第一個協定
# 歸類），所以產生時另外讀模板全文，排除含非 http／多協定區塊或主動 fuzz／OAST tag 的模板。
PROHIBITED_TOP_LEVEL_KEYS: frozenset[str] = frozenset(
    {
        "flow",
        "javascript",
        "code",
        "headless",
        "tcp",
        "dns",
        "file",
        "ssl",
        "websocket",
        "whois",
        "workflow",
        "network",
    }
)
PROHIBITED_TAGS: frozenset[str] = frozenset({"fuzz", "dast", "intrusive", "dos", "oast"})
_TOP_KEY_RE = re.compile(r"^([A-Za-z0-9_-]+):", re.MULTILINE)
_TAGS_RE = re.compile(r"^[ \t]*tags:[ \t]*(.+)$", re.MULTILINE)


@dataclass(frozen=True, slots=True)
class Template:
    """凍結清單中的一個模板：穩定的 template id、檔案 sha256 與相對路徑。"""

    id: str
    sha256: str
    path: str


def parse_tl_paths(stdout: str) -> tuple[str, ...]:
    """從 nuclei -tl 的輸出擷取相對模板路徑（去重、依字典序排序）；banner 與非 http 行一律略過。"""
    paths = {match.group(1) for line in stdout.splitlines() if (match := _TL_LINE_RE.match(line))}
    return tuple(sorted(paths))


def extract_template_id(yaml_text: str) -> str | None:
    """擷取模板 YAML 的頂層 id；找不到（或該行有多餘內容）回 None，由呼叫端大聲失敗。"""
    match = _ID_RE.search(yaml_text)
    return match.group(1) if match else None


def template_violations(yaml_text: str) -> tuple[str, ...]:
    """檢查模板全文：回傳違規原因（非 http／多協定區塊、危險 tag）；空 tuple 表示通過內容閘門。"""
    reasons: list[str] = []
    top_keys = {match.group(1) for match in _TOP_KEY_RE.finditer(yaml_text)}
    reasons.extend(f"protocol:{key}" for key in sorted(top_keys & PROHIBITED_TOP_LEVEL_KEYS))
    tags_match = _TAGS_RE.search(yaml_text)
    if tags_match:
        tags = {tag.strip().lower() for tag in tags_match.group(1).replace(",", " ").split()}
        reasons.extend(f"tag:{tag}" for tag in sorted(tags & PROHIBITED_TAGS))
    return tuple(reasons)


def format_lock(templates: Sequence[Template]) -> str:
    """產生 lock 檔內容：依 (id, path) 排序，每行 `id sha256 path`，結尾換行。"""
    ordered = sorted(templates, key=lambda template: (template.id, template.path))
    return "".join(f"{t.id} {t.sha256} {t.path}\n" for t in ordered)


def parse_lock(text: str) -> tuple[Template, ...]:
    """解析 lock 檔內容；空行略過，格式錯誤或 id／path 重複都拋 ValueError（不默默跳過）。"""
    templates: list[Template] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        match = _LOCK_RE.match(raw)
        if match is None:
            raise ValueError(f"lock 檔第 {number} 行格式錯誤：{raw!r}")
        template = Template(id=match.group(1), sha256=match.group(2), path=match.group(3))
        if template.id in seen_ids:
            raise ValueError(f"lock 檔第 {number} 行 id 重複：{template.id}")
        if template.path in seen_paths:
            raise ValueError(f"lock 檔第 {number} 行 path 重複：{template.path}")
        seen_ids.add(template.id)
        seen_paths.add(template.path)
        templates.append(template)
    return tuple(templates)


def reconcile(expected_ids: Collection[str], templates: Sequence[Template]) -> None:
    """確認模板集合的 id 與預期的 include 清單完全一致；缺少、多出或重複都拋 ValueError。"""
    present = Counter(template.id for template in templates)
    duplicates = sorted(template_id for template_id, count in present.items() if count > 1)
    expected = set(expected_ids)
    missing = sorted(expected - present.keys())
    extra = sorted(present.keys() - expected)
    if missing or extra or duplicates:
        message = f"模板清單與 include 不符：缺少={missing} 多出={extra} 重複={duplicates}"
        raise ValueError(message)
