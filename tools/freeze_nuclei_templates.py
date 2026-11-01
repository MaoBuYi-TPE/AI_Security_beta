#!/usr/bin/env python3
"""產生／驗證 Nuclei 的凍結模板清單（T17；docs/DECISIONS.md §23、docs/TOOLS.md §2.1）。

這是 src/ 之外的開發／維運工具（比照 make images 拉映像），不是產品程式，也不接任何目標：

1. 讀一次鎖定的 nuclei-templates archive，驗證 sha256，再從記憶體解壓（避免 TOCTOU）。
2. 在鎖定的 nuclei 映像裡離線（--network none）跑 `nuclei -tl`，以 policy.INCLUDE_TEMPLATE_IDS
   為白名單、policy.LIST_TYPE_FILTER（-pt http -ni）為型別過濾，列出符合的模板。
3. 讀每個模板全文：擷取頂層 id、過內容閘門（排除非 http／多協定區塊與危險 tag）、算 sha256，
   再和 INCLUDE 對帳（缺少、多出、重複、違規都失敗，不杜撰）。
4. 寫出 templates.lock.txt，印出要填回 policy.py 與 manifest.json 的 lock sha256、定義 sha256、
   數量與類別分布。

--check：重新產生到記憶體並和已提交的 lock 逐位元組比對（供 gated live 重現性測試），不覆寫檔案。

用法：
  orb start
  uv run python tools/freeze_nuclei_templates.py            # 產生並覆寫 lock
  uv run python tools/freeze_nuclei_templates.py --check     # 只驗證，不覆寫
"""

import argparse
import hashlib
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from secscan.scanners.domain.nuclei import policy
from secscan.scanners.domain.nuclei.selection import (
    Template,
    extract_template_id,
    format_lock,
    parse_tl_paths,
    reconcile,
    template_violations,
)

_ROOT = Path(__file__).resolve().parents[1]
_RELEASE = policy.TEMPLATE_RELEASE.lstrip("v")  # archive 檔名用不含 v 的版本號
_TEMPLATES_SUBDIR = f"nuclei-templates-{_RELEASE}"
_ARCHIVE_REL = f"runs/spike-t03/templates/v{_RELEASE}/archive/{_TEMPLATES_SUBDIR}.tar.gz"
_DEFAULT_ARCHIVE = _ROOT / _ARCHIVE_REL
_EXTRACT_ROOT = _ROOT / "runs/t17-nuclei"
_LOCK_PATH = _ROOT / "src/secscan/scanners/domain/nuclei/templates.lock.txt"

_INSPECT_TIMEOUT = 30
_PULL_TIMEOUT = 600
_LIST_TIMEOUT = 300


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_archive(archive: Path) -> bytes:
    """讀一次 archive 並驗證 sha256（讀一次用於 hash 與解壓，避免 TOCTOU）。"""
    if not archive.is_file():
        raise SystemExit(
            f"找不到 archive：{archive}\n"
            f"  從 nuclei-templates release {policy.TEMPLATE_RELEASE} 下載 "
            f"{_TEMPLATES_SUBDIR}.tar.gz 放到該路徑（或以 --archive 指定）。"
        )
    data = archive.read_bytes()
    digest = _sha256(data)
    if digest != policy.TEMPLATE_ARCHIVE_SHA256:
        raise SystemExit(
            f"archive sha256 不符：{archive}\n"
            f"  實得 {digest}\n  預期 {policy.TEMPLATE_ARCHIVE_SHA256}"
        )
    print(f"[ok] archive sha256 = {digest}")
    return data


def extract(data: bytes, dest: Path) -> Path:
    """從記憶體乾淨地重新解壓，回傳模板根目錄。"""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        tar.extractall(dest, filter="data")  # filter=data：擋路徑穿越與特殊檔
    root = dest / _TEMPLATES_SUBDIR
    if not root.is_dir():
        raise SystemExit(f"解壓後找不到 {root}")
    print(f"[ok] extracted -> {root}")
    return root


def ensure_image() -> None:
    """確認鎖定的 nuclei 映像在本機；不在就以 digest 拉取（比照 make images）。"""
    reference = str(policy.NUCLEI_IMAGE)
    inspect = subprocess.run(
        ["docker", "image", "inspect", reference],
        capture_output=True,
        text=True,
        check=False,
        timeout=_INSPECT_TIMEOUT,
    )
    if inspect.returncode == 0:
        return
    print(f"[..] pulling {reference}")
    pull = subprocess.run(
        ["docker", "pull", reference],
        capture_output=True,
        text=True,
        check=False,
        timeout=_PULL_TIMEOUT,
    )
    if pull.returncode != 0:
        raise SystemExit(f"docker pull 失敗（exit {pull.returncode}）：\n{pull.stderr}")


def run_nuclei_tl(templates_root: Path) -> str:
    """在鎖定映像裡離線跑 nuclei -tl，回傳 stdout（符合白名單與型別過濾的模板路徑）。"""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write("\n".join(policy.INCLUDE_TEMPLATE_IDS) + "\n")
        ids_file = Path(handle.name)
    try:
        command = [
            "docker", "run", "--rm",
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--pids-limit", "512",
            "--memory", "2g",
            "--tmpfs", "/root/.config",
            "--tmpfs", "/root/.cache",
            "--tmpfs", "/tmp",  # noqa: S108 - 容器內的 tmpfs，非主機暫存檔
            "-v", f"{templates_root}:/templates:ro",
            "-v", f"{ids_file}:/ids.txt:ro",
            str(policy.NUCLEI_IMAGE),
            "-t", "/templates", "-id", "/ids.txt", "-tl",
            *policy.LIST_TYPE_FILTER,
        ]  # fmt: skip
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=_LIST_TIMEOUT
        )
        if result.returncode != 0:
            raise SystemExit(f"nuclei -tl 失敗（exit {result.returncode}）：\n{result.stderr}")
        return result.stdout
    finally:
        ids_file.unlink(missing_ok=True)


def build_templates(stdout: str, templates_root: Path) -> list[Template]:
    """把 nuclei -tl 的路徑整理成 Template（讀 id、過內容閘門、算 sha256），並和 INCLUDE 對帳。"""
    templates: list[Template] = []
    violations: list[str] = []
    for path in parse_tl_paths(stdout):
        data = (templates_root / path).read_bytes()
        text = data.decode("utf-8")
        template_id = extract_template_id(text)
        if template_id is None:
            raise SystemExit(f"模板缺少頂層 id：{path}")
        reasons = template_violations(text)
        if reasons:
            violations.append(f"{path}: {', '.join(reasons)}")
            continue
        templates.append(Template(id=template_id, sha256=_sha256(data), path=path))
    if violations:
        joined = "\n  ".join(violations)
        raise SystemExit(f"內容閘門擋下模板（請從 policy.INCLUDE_TEMPLATE_IDS 移除）：\n  {joined}")
    reconcile(policy.INCLUDE_TEMPLATE_IDS, templates)
    return templates


def _report(lock: str, templates: list[Template]) -> None:
    categories: dict[str, int] = {}
    for template in templates:
        category = template.path.split("/")[1]
        categories[category] = categories.get(category, 0) + 1
    print(f"[ok] templates = {len(templates)}")
    for category in sorted(categories):
        print(f"       {category}: {categories[category]}")
    print(f"[ok] TEMPLATES_LOCK_SHA256 = {_sha256(lock.encode('ascii'))}")
    print(f"[ok] definition_sha256     = {policy.definition_sha256_for(templates)}")


def _freeze(archive: Path, *, check: bool) -> int:
    data = load_archive(archive)
    ensure_image()
    templates_root = extract(data, _EXTRACT_ROOT / "extracted")
    templates = build_templates(run_nuclei_tl(templates_root), templates_root)
    lock = format_lock(templates)
    if check:
        current = _LOCK_PATH.read_text(encoding="ascii") if _LOCK_PATH.exists() else ""
        if current != lock:
            print("[FAIL] 重新產生的 lock 與已提交的不同（來源有變？）", file=sys.stderr)
            return 1
        print("[ok] lock 與重新產生的結果一致")
        _report(lock, templates)
        return 0
    _LOCK_PATH.write_text(lock, encoding="ascii")
    print(f"[ok] wrote {_LOCK_PATH.relative_to(_ROOT)}")
    _report(lock, templates)
    print("\n下一步：把 TEMPLATES_LOCK_SHA256 填回 policy.py，並更新 manifest.json。")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="產生／驗證 Nuclei 凍結模板清單（T17）")
    parser.add_argument(
        "--archive", type=Path, default=_DEFAULT_ARCHIVE, help="nuclei-templates tar.gz"
    )
    parser.add_argument("--check", action="store_true", help="只驗證、不覆寫 lock")
    args = parser.parse_args(argv)
    try:
        return _freeze(args.archive, check=args.check)
    except ValueError as error:  # reconcile 等純函式的驗證錯誤，轉成訊息、非零退出
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
