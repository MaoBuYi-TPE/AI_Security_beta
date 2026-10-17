"""遮罩工具輸出，再寫成可提交的 fixture。原始檔不修改。

用法：
    python -I mask_fixture.py --secrets <file> --in <raw> --out <fixture>

遮罩內容：
  - --secrets 檔列出的字面秘密（每行一個，例如 lab token、proxy 密碼）→ REDACTED_SECRET
  - JWT 樣式字串（eyJ.....，含 Bearer token；第三段可為空） → REDACTED_JWT
  - Werkzeug debugger 的 SECRET = "..." → REDACTED_WERKZEUG
  - Schemathesis 的 {"$base64": "..."} body：解碼後套用同一套規則再重新編碼
遮罩用的替換字串刻意不含 < > : 等字元，確保遮罩後仍是合法 JSON/XML。
與 tests/contract/test_fixture_manifest.py 共用同一條 JWT 樣式（第三段 `*`）。
"""

from __future__ import annotations

import argparse
import base64
import binascii
import re
from pathlib import Path

# JWT（含 VAmPI 的 Bearer token）與字面秘密即涵蓋本 spike 所有秘密。
# 不用通用的 Authorization 正則：工具輸出的 header 結構各異（例如 Schemathesis 以陣列存放
# 且已先把值換成 [Filtered]），通用正則容易破壞 JSON 結構。
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
# Werkzeug debugger 的 SECRET，可能是 JSON 轉義的 \"...\" 或一般 "..."。
WERKZEUG_SECRET_RE = re.compile(r'(SECRET\s*=\s*\\?")[A-Za-z0-9]{10,}(\\?")')
BASE64_FIELD_RE = re.compile(r'("\$base64"\s*:\s*")([A-Za-z0-9+/=_-]+)(")')


def _mask_plain(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "REDACTED_SECRET")
    text = JWT_RE.sub("REDACTED_JWT", text)
    return WERKZEUG_SECRET_RE.sub(r"\1REDACTED_WERKZEUG\2", text)


def _mask_base64_bodies(text: str, secrets: list[str]) -> str:
    def repl(match: re.Match[str]) -> str:
        try:
            decoded = base64.b64decode(match.group(2) + "===", validate=False).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return match.group(0)
        masked = _mask_plain(decoded, secrets)
        if masked == decoded:
            return match.group(0)
        reencoded = base64.b64encode(masked.encode("utf-8")).decode("ascii")
        return f"{match.group(1)}{reencoded}{match.group(3)}"

    return BASE64_FIELD_RE.sub(repl, text)


def mask_text(text: str, secrets: list[str]) -> str:
    return _mask_base64_bodies(_mask_plain(text, secrets), secrets)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secrets", required=True, type=Path)
    parser.add_argument("--in", dest="src", required=True, type=Path)
    parser.add_argument("--out", dest="dst", required=True, type=Path)
    args = parser.parse_args()

    secrets = [
        line.strip()
        for line in args.secrets.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    masked = mask_text(args.src.read_text(encoding="utf-8"), secrets)
    args.dst.parent.mkdir(parents=True, exist_ok=True)
    args.dst.write_text(masked, encoding="utf-8")
    print(f"masked {args.src} -> {args.dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
