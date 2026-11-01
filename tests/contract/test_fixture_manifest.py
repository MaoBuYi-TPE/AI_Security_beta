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

from secscan.scanners.domain.nuclei import policy as nuclei_policy

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
REPO_ROOT = FIXTURES_DIR.parents[1]
MANIFEST_PATH = FIXTURES_DIR / "manifest.json"
DATA_SUFFIXES = {".json", ".jsonl", ".ndjson", ".xml", ".log"}

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


# --- T07 的 OpenAPI 規格 fixture（上傳用的輸入，不是工具輸出）--------------------------------

OPENAPI_DIR = FIXTURES_DIR / "openapi"


def _openapi_entries() -> list[dict[str, str]]:
    entries: list[dict[str, str]] = _manifest()["openapi_fixtures"]  # type: ignore[assignment]
    return entries


def test_every_openapi_fixture_is_listed_with_its_sha256() -> None:
    listed = {(FIXTURES_DIR / entry["path"]).resolve(): entry for entry in _openapi_entries()}
    on_disk = {path.resolve() for path in OPENAPI_DIR.iterdir() if path.is_file()}

    assert on_disk == set(listed), (
        f"未登記：{on_disk - set(listed)}；登記但不存在：{set(listed) - on_disk}"
    )
    for path, entry in listed.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"], entry["path"]


def test_vampi_spec_is_the_t03_input() -> None:
    inputs: dict[str, str] = _manifest()["inputs"]  # type: ignore[assignment]
    [entry] = [e for e in _openapi_entries() if e["path"] == "openapi/vampi-openapi3.yml"]

    assert entry["raw_sha256"] == inputs["vampi_openapi3.yml_sha256"]
    assert entry["sha256"] != entry["raw_sha256"]


@pytest.mark.parametrize("entry", _openapi_entries(), ids=lambda e: e["path"])
def test_openapi_fixtures_have_no_secrets(entry: dict[str, str]) -> None:
    text = (FIXTURES_DIR / entry["path"]).read_text(encoding="utf-8")

    assert not JWT_RE.search(text)
    assert not PRIVATE_KEY_RE.search(text)
    assert not USERINFO_RE.search(text)


# --- T17 的 Nuclei 凍結模板清單（provenance 帳本；和 policy.py 與 lock 檔交叉核對）---------------


def _nuclei_block() -> dict[str, object]:
    block: dict[str, object] = _manifest()["nuclei_templates"]  # type: ignore[assignment]
    return block


def test_nuclei_release_matches_policy() -> None:
    block = _nuclei_block()
    assert block["release"] == nuclei_policy.TEMPLATE_RELEASE
    assert block["commit"] == nuclei_policy.TEMPLATE_COMMIT
    assert block["archive_sha256"] == nuclei_policy.TEMPLATE_ARCHIVE_SHA256


def test_nuclei_image_digest_matches_policy() -> None:
    # policy 手抄的映像 digest 必須和 manifest 的 nuclei fixture（T03 記錄的）一致。
    digests = {entry["image_digest"] for entry in _entries() if entry["tool"] == "nuclei"}
    assert digests, "manifest 沒有 nuclei fixture"
    for digest in digests:
        assert digest in str(nuclei_policy.NUCLEI_IMAGE), digest


def test_nuclei_frozen_list_matches_lock_file_and_policy() -> None:
    frozen: dict[str, object] = _nuclei_block()["frozen_list"]  # type: ignore[assignment]

    lock_path = REPO_ROOT / str(frozen["path"])
    assert lock_path.is_file(), frozen["path"]
    digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()

    # manifest 的 lock_sha256、policy 的常數、lock 檔實際內容三者必須一致（任一改動都被抓到）。
    assert digest == frozen["lock_sha256"]
    assert digest == nuclei_policy.TEMPLATES_LOCK_SHA256
    assert frozen["definition_sha256"] == nuclei_policy.nuclei_definition_sha256()
    assert frozen["template_count"] == len(nuclei_policy.load_templates())
    categories = frozen["selected_categories"]
    assert isinstance(categories, list)
    assert sorted(map(str, categories)) == sorted(nuclei_policy.ALLOWED_CATEGORIES)
    assert frozen["added_by"] == "T17"
