#!/usr/bin/env python3
"""產生／驗證 OWASP Top 10:2025 的官方 CWE 對應表（T19；docs/DECISIONS.md §25.5）。

這是 src/ 之外的開發工具（比照 tools/freeze_nuclei_templates.py），不連網、不接任何目標：

1. 讀手動下載、鎖定 commit 的 10 個官方分類 markdown（放在 gitignore 的 runs/t19-owasp/<commit>/），
   逐檔驗證 sha256（和下面的 SOURCES 一致才繼續；下載的內容是不可信的資料，只當文字解析）。
2. 以 secscan.findings.domain.owasp 的純函式擷取「List of Mapped CWEs」並驗證（分類齊全、
   CWE 不重複；重複或格式改變就失敗，由人決定，不猜）。
3. 寫出 src/secscan/findings/taxonomy/owasp_top10_2025.json，印出要填回 owasp.py 的 sha256。

--check：重新產生到記憶體並和已提交的 JSON 逐位元組比對，不覆寫檔案。

下載（鎖定的 commit，不要用 master）：
  for f in <SOURCES 的檔名>; do
    curl -fsSL https://raw.githubusercontent.com/OWASP/Top10/<COMMIT>/2025/docs/en/$f \\
      -o runs/t19-owasp/<COMMIT>/$f
  done
用法：
  uv run python tools/freeze_owasp_top10.py            # 產生並覆寫 JSON
  uv run python tools/freeze_owasp_top10.py --check    # 只驗證，不覆寫
"""

import argparse
import hashlib
import sys
from pathlib import Path

from secscan.findings.domain.owasp import (
    TABLE_PATH,
    Source,
    build_table,
    parse_category,
    table_json,
)

_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/OWASP/Top10"
DIRECTORY = "2025/docs/en"
# 2026-11-03 時 2025/docs/en 最新的 commit（2026-04-06）。
COMMIT = "57db8ec5ddbca1dfef5aa77cbb81951e94f714cf"
# 該 commit 的每個分類檔與 sha256（下載後以 shasum -a 256 記下；內容改變就要重新審查）。
SOURCES = {
    "A01_2025-Broken_Access_Control.md": (
        "d6ebc4e65422ff4fa32c310dec3c20ed6e804edfd2d06c7e5b8a802645f556ec"
    ),
    "A02_2025-Security_Misconfiguration.md": (
        "0df66f6c3e23ee8234567b20de786bf579dac1561632dd532d64130bb2aa2d75"
    ),
    "A03_2025-Software_Supply_Chain_Failures.md": (
        "d4108c04991ef2f5ab1d8ef301b51cfeef0fea35c550665c3dcfba7aa346758e"
    ),
    "A04_2025-Cryptographic_Failures.md": (
        "43d7da6637dc9d7ad7d9f7a017afc36123beb96c13d4e35d986f89bca341eaad"
    ),
    "A05_2025-Injection.md": "d617676bd8d03ab656a481d97a3e8abd2a6241f22ea10326ad05120ba07494ec",
    "A06_2025-Insecure_Design.md": (
        "e2b2f572b43ed5a4a82d2b1207c067687c321ecc683893f6bd4c2d2d467e22e4"
    ),
    "A07_2025-Authentication_Failures.md": (
        "9f98e0c8f055b0c87b67078ae9af4799a9f8caf0736a3fdcd66b1b092b1c60da"
    ),
    "A08_2025-Software_or_Data_Integrity_Failures.md": (
        "3739748e2cb72c3935dbab9236ac5cb5061da39a1891362369af0c27102a26ca"
    ),
    "A09_2025-Security_Logging_and_Alerting_Failures.md": (
        "87121126d307ea09dbf073b090609c861c9ded6dc654f73c5ea6436b9522e9c8"
    ),
    "A10_2025-Mishandling_of_Exceptional_Conditions.md": (
        "1e05837530582feb3e96d84160cd2286d5ba93348fedca2d8f8fb35eecc27ac4"
    ),
}
_DEFAULT_SOURCE = _ROOT / "runs" / "t19-owasp" / COMMIT


def generate(source_dir: Path) -> str:
    categories = []
    for name, expected in SOURCES.items():
        path = source_dir / name
        if not path.is_file():
            raise SystemExit(f"找不到 {path}：依檔頭的說明從鎖定的 commit 下載")
        data = path.read_bytes()  # 讀一次，同一份內容用於 hash 與解析（避免 TOCTOU）
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            raise SystemExit(f"{name} 的 sha256 不符：實得 {digest}，預期 {expected}")
        categories.append(parse_category(data.decode("utf-8"), file=name, sha256=digest))
    table = build_table(Source(REPOSITORY, COMMIT, DIRECTORY), categories)
    for category in table.categories:
        print(f"[ok] {category.id} {category.title}: {len(category.cwes)} 個 CWE")
    return table_json(table)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="產生／驗證 OWASP Top 10:2025 對應表（T19）")
    parser.add_argument("--source", type=Path, default=_DEFAULT_SOURCE, help="分類 markdown 目錄")
    parser.add_argument("--check", action="store_true", help="只驗證、不覆寫")
    args = parser.parse_args(argv)
    try:
        text = generate(args.source)
    except ValueError as error:  # 純函式的驗證錯誤：轉成訊息、非零退出
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    digest = hashlib.sha256(text.encode("ascii")).hexdigest()
    if args.check:
        current = TABLE_PATH.read_text(encoding="ascii") if TABLE_PATH.exists() else ""
        if current != text:
            print("[FAIL] 重新產生的對應表與已提交的不同（來源有變？）", file=sys.stderr)
            return 1
        print(f"[ok] 對應表與重新產生的結果一致；sha256 = {digest}")
        return 0
    TABLE_PATH.write_text(text, encoding="ascii")
    print(f"[ok] wrote {TABLE_PATH.relative_to(_ROOT)}")
    print(f"[ok] OWASP_TOP10_2025_SHA256 = {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
