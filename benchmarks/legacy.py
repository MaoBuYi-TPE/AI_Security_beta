"""把 T23a 之前的明文結果目錄轉成加密的結果目錄（make bench-seal；BSEAL-03；DECISIONS §30.7）。

- 原目錄只讀：先核對它的 SHA256SUMS（明文的 sha256）與 manifest 的版本，絕不修改或刪除它。
- 先寫到 `<名稱>.partial-<隨機值>`（O_EXCL 建立），每個檔案以最後的名稱為 context 加密；manifest
  升到目前的版本：files 記下明文與密文的 sha256，揭露事項改為加密，並記下原本 manifest 的 sha256。
- 寫完之後完整驗證（SHA256SUMS、解密、和原目錄的 sha256 逐一比對），通過才 rename 成正式的名稱：
  正式名稱存在就代表完整。驗證失敗時刪除這次產生的 partial 目錄；程序被中斷時 partial 目錄留著
  （名稱已標示），不自動刪除。原目錄由使用者確認之後自行處理。
"""

import hashlib
import json
import secrets
import shutil
from pathlib import Path
from typing import Any

from benchmarks.manifest import DISCLOSURES, MANIFEST_FILE, MANIFEST_VERSION
from benchmarks.models import FileDigests
from benchmarks.results import (
    CHECKSUMS,
    DIRECTORY_MODE,
    ResultsError,
    read_bytes,
    verify,
    write_bytes,
    write_checksums,
    write_json,
)
from benchmarks.sealing import BenchKeys
from benchmarks.spec import check_name

LEGACY_MANIFEST_VERSION = 1
PARTIAL_MARK = ".partial-"


def seal_legacy(source: Path, root: Path, name: str, keys: BenchKeys) -> Path:
    """回傳新的結果目錄；原目錄不動。"""
    check_name(name)
    final = root / name
    if final.exists():
        raise ResultsError("結果目錄已經存在；請換一個新的名稱")
    expected = _legacy_digests(source)
    manifest = json.loads((source / MANIFEST_FILE).read_bytes())
    if (
        not isinstance(manifest, dict)
        or manifest.get("manifest_version") != LEGACY_MANIFEST_VERSION
    ):
        raise ResultsError("原目錄不是 T23a 之前（manifest 版本 1）的明文結果")
    root.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
    partial = root / f"{name}{PARTIAL_MARK}{secrets.token_hex(4)}"
    partial.mkdir(mode=DIRECTORY_MODE)
    try:
        _write(source, partial, name, manifest, expected, keys)
        _check(partial, name, expected, keys)
    except (OSError, ValueError):
        shutil.rmtree(partial)
        raise
    if final.exists():
        shutil.rmtree(partial)
        raise ResultsError("結果目錄已經存在；請換一個新的名稱")
    partial.rename(final)
    return final


def _legacy_digests(source: Path) -> dict[str, str]:
    """原目錄的 SHA256SUMS（明文）和實際的檔案一致；回傳檔名 → 明文的 sha256。"""
    checksums = source / CHECKSUMS
    if not checksums.is_file():
        raise ResultsError("原目錄缺少 SHA256SUMS（session 沒有正常結束），不轉換")
    expected: dict[str, str] = {}
    for line in checksums.read_text(encoding="ascii").splitlines():
        digest, _, file_name = line.partition("  ")
        expected[file_name] = digest
    actual: dict[str, str] = {}
    for path in sorted(source.iterdir()):
        if path.name == CHECKSUMS:
            continue
        if not path.is_file() or path.is_symlink():
            raise ResultsError("原目錄只能有一般檔案")
        actual[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected or MANIFEST_FILE not in expected:
        raise ResultsError("原目錄的檔案和 SHA256SUMS 不符，不轉換")
    return expected


def _write(
    source: Path,
    partial: Path,
    name: str,
    manifest: dict[str, Any],
    expected: dict[str, str],
    keys: BenchKeys,
) -> None:
    files: dict[str, FileDigests] = {}
    for file_name in sorted(expected):
        if file_name == MANIFEST_FILE:
            continue
        content = (source / file_name).read_bytes()
        files[file_name] = write_bytes(partial, file_name, content, keys=keys, batch=name)
    upgraded = {
        **manifest,
        "manifest_version": MANIFEST_VERSION,
        "files": {
            file_name: {"sha256": digests.sha256, "sealed_sha256": digests.sealed_sha256}
            for file_name, digests in sorted(files.items())
        },
        "disclosures": list(DISCLOSURES),
        "sealed_from": {
            "manifest_version": LEGACY_MANIFEST_VERSION,
            "manifest_sha256": expected[MANIFEST_FILE],
        },
    }
    write_json(partial, MANIFEST_FILE, upgraded, keys=keys, batch=name)
    write_checksums(partial)


def _check(partial: Path, name: str, expected: dict[str, str], keys: BenchKeys) -> None:
    verify(partial)
    for file_name, digest in expected.items():
        if file_name == MANIFEST_FILE:
            continue
        content = read_bytes(partial, file_name, keys=keys, batch=name)
        if hashlib.sha256(content).hexdigest() != digest:
            raise ResultsError("轉換之後的內容和原目錄不符")
    read_bytes(partial, MANIFEST_FILE, keys=keys, batch=name)
