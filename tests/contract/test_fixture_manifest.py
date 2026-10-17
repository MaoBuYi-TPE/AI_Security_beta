"""T03 fixture 完整性與秘密防護（contract 測試，不碰網路或 Docker）。

守住三件事：
  1. tests/fixtures 下每個檔案都登記在 manifest.json 且 sha256 相符（防止默默改動 golden fixture）。
  2. 遮罩後的 fixture 不含 JWT、私鑰、未遮罩的 Authorization/Bearer/Basic 值或 URL userinfo；
     也會解碼 Schemathesis 的 {"$base64": …} body 再檢查。
  3. fixture 非空，且 json/jsonl/ndjson 仍可解析。
只讀 tests/fixtures；不 import spikes/。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
MANIFEST_PATH = FIXTURES_DIR / "manifest.json"
DATA_SUFFIXES = {".json", ".jsonl", ".ndjson", ".xml"}

# 第三段允許為空（alg=none 的 JWT）。base64 編碼的 JSON 沒有兩個 "."，不會誤判。
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
# 只盯「憑證樣式」的 token：≥16 字元且含數字或 +/=/_ 等非字母字元，
# 以免誤判英文散文（例如 "basic information"）。真實的 Bearer/Basic 憑證都符合。
BEARER_RE = re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9+/._=-]{16,})")
USERINFO_RE = re.compile(r"://[^/\s:@\"']+:[^/\s:@\"']+@")
BASE64_FIELD_RE = re.compile(r'"\$base64"\s*:\s*"([A-Za-z0-9+/=_-]+)"')
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUIRED_TOOLS = {"zap", "nuclei", "schemathesis"}
# 工具自身或遮罩後的佔位值，不算洩漏。
PLACEHOLDERS = ("[filtered]", "***", "redacted_")


def _manifest() -> dict[str, object]:
    data: dict[str, object] = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return data


def _fixture_files() -> list[Path]:
    return sorted(
        p
        for p in FIXTURES_DIR.rglob("*")
        if p.is_file() and p != MANIFEST_PATH and p.suffix in DATA_SUFFIXES
    )


def _entries() -> list[dict[str, str]]:
    entries: list[dict[str, str]] = _manifest()["fixtures"]  # type: ignore[assignment]
    return entries


def _is_placeholder(value: str) -> bool:
    low = value.lower()
    return any(p in low for p in PLACEHOLDERS)


def _decoded_base64_bodies(text: str) -> list[str]:
    out: list[str] = []
    for token in BASE64_FIELD_RE.findall(text):
        try:
            out.append(base64.b64decode(token + "===", validate=False).decode("utf-8", "replace"))
        except (binascii.Error, ValueError):
            continue
    return out


def test_manifest_covers_three_tools() -> None:
    tools = {entry["tool"] for entry in _entries()}
    assert tools >= REQUIRED_TOOLS, f"manifest 缺少工具樣本：{REQUIRED_TOOLS - tools}"


def test_every_fixture_is_listed() -> None:
    listed = {(FIXTURES_DIR / entry["path"]).resolve() for entry in _entries()}
    on_disk = {p.resolve() for p in _fixture_files()}
    assert on_disk == listed, f"未登記：{on_disk - listed}；登記但不存在：{listed - on_disk}"


@pytest.mark.parametrize("entry", _entries(), ids=lambda e: e["run_id"] + ":" + e["path"])
def test_fixture_sha256_matches_manifest(entry: dict[str, str]) -> None:
    path = FIXTURES_DIR / entry["path"]
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual == entry["sha256"], f"{entry['path']} 內容與 manifest 不符"


@pytest.mark.parametrize("entry", _entries(), ids=lambda e: e["run_id"] + ":" + e["path"])
def test_fixture_metadata_well_formed(entry: dict[str, str]) -> None:
    assert DIGEST_RE.match(entry["image_digest"]), entry["image_digest"]
    assert entry["tool_version"]
    assert entry["recorded_utc"]
    assert entry["target"]


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.name)
def test_fixture_is_non_empty_and_parseable(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert text.strip(), f"{path.name} 是空的"
    if path.suffix == ".json":
        json.loads(text)
    elif path.suffix in (".jsonl", ".ndjson"):
        for line in text.splitlines():
            if line.strip():
                json.loads(line)


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.name)
def test_fixture_has_no_secrets(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    segments = [text, *_decoded_base64_bodies(text)]
    for segment in segments:
        assert not JWT_RE.search(segment), f"{path.name} 疑似含 JWT"
        assert not PRIVATE_KEY_RE.search(segment), f"{path.name} 疑似含私鑰"
        assert not USERINFO_RE.search(segment), f"{path.name} 疑似含 URL userinfo 密碼"
        for token in BEARER_RE.findall(segment):
            # 全字母的長 token 多半是散文；憑證會含數字或符號。
            if not re.search(r"[0-9+/=_]", token):
                continue
            assert _is_placeholder(token), f"{path.name} 含未遮罩的 Bearer/Basic 值：{token[:8]}…"
