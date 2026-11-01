"""Nuclei 的映像、模板 release、凍結的 HTTP 模板清單與執行設定（T17；docs/DECISIONS.md §23）。

精選、對準 lab 的純 HTTP 模板，涵蓋：
- 通用 web 衛生：安全 header、cookie SameSite、HTTP 方法、目錄列舉、robots/security.txt；
- 暴露：API 規格、git/phpinfo/.DS_Store；
- 技術與技術棧辨識：tech-detect、flask、werkzeug-debugger、angular、express…；
- 少數和 ZAP 重疊的通用主動探測（SQLi、反射 XSS、CRLF、open redirect、CORS），
  作為 M4「同一問題多來源」的候選（可達性依 guard/grant，見 docs/TOOLS.md §2.1）。

協定只收 http、關閉 OAST（-ni）；code/headless/file/fuzz 在 nuclei 預設不載入。
但 -pt http 擋不住「多協定」模板（nuclei 以第一個協定歸類），所以產生 lock 時
另外以 selection.template_violations 讀全文把關，排除含 javascript/flow/code 等
非 http 區塊或 fuzz/OAST tag 的模板（CLAUDE.md §7）。整包有 14,036 個 yaml、
多數是本 lab 用不到的產品模板，故比照 ZAP 白名單、以類別人工審查後精選。

本模組只負責「清單與設定」。lock 檔記錄每個模板的 id、sha256 與路徑，改清單要一併
更新 TEMPLATES_LOCK_SHA256（test_policy.py 核對）。ExecutionPlan 組裝（含凍結速率、
-dut、掛載前逐檔 sha256 驗證）、JSONL parser、引擎註冊與 /scan-profiles 揭露在 T18；
rule group、OWASP 對應與 fingerprint 在 T19。
"""

import hashlib
import json
from collections.abc import Sequence
from functools import cache
from pathlib import Path

from secscan.scanners.domain.nuclei.selection import Template, parse_lock
from secscan.scanners.domain.plan import ImageReference

# T03 鎖定的 nuclei 映像與模板 release（docs/TOOLS.md §1、§2、tests/fixtures/manifest.json）。
NUCLEI_IMAGE = ImageReference.parse(
    "projectdiscovery/nuclei:v3.11.1"
    "@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"
)
NUCLEI_VERSION = "v3.11.1"
TEMPLATE_RELEASE = "v10.5.0"
TEMPLATE_COMMIT = "f8b8b8dcd70d93826c3767e1829ef8243af9f03b"
TEMPLATE_ARCHIVE_SHA256 = "80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41"

# 型別過濾：關閉 OAST（-ni，另排除 OAST 類模板）、關閉更新檢查、協定只收 http。產生/驗證 lock 的
# nuclei -tl 與 T18 的執行共用同一份（LIST_TYPE_FILTER 即是它，避免手抄不一致）。
TYPE_FILTER: tuple[str, ...] = ("-ni", "-duc", "-pt", "http")
LIST_TYPE_FILTER: tuple[str, ...] = TYPE_FILTER
# 凍結的執行設定（T18 的 ExecutionPlan 以此組裝；ARCHITECTURE §5、SOURCES S23）：
# 型別過濾加 JSONL 輸出、只印發現。每個 run 另加 -id（凍結清單）、
# -sf（bearer，domains 完全比對 host:port，S36）、-p（指向 guard）、-o、-u，
# 以及凍結的速率/並行（-rl/-c，T18 依 guard 預算設定）。
FROZEN_FLAGS: tuple[str, ...] = (*TYPE_FILTER, "-jsonl", "-silent")

# 凍結清單允許的 http 類別（lock 檔每個路徑的第二段都必須落在這裡；test_policy.py 核對）。
ALLOWED_CATEGORIES: frozenset[str] = frozenset(
    {"exposures", "miscellaneous", "misconfiguration", "technologies", "vulnerabilities"}
)

# --- 精選的 template id，依類別；理由與 method／guard 相容性見 TOOLS.md §2.1 ---

# 暴露的檔案與 API 規格（對任何 HTTP 應用都適用）。
EXPOSURE_TEMPLATE_IDS: tuple[str, ...] = (
    "openapi",  # 暴露的 OpenAPI 規格
    "swagger-api",  # 暴露的 Swagger UI/規格
    "wadl-api",  # 暴露的 WADL 規格（GET 加 OPTIONS）
    "wsdl-api",  # 暴露的 WSDL 規格
    "git-config",  # 可讀的 .git/config
    "git-exposure",  # 可讀的 .git 目錄
    "phpinfo-files",  # phpinfo() 輸出
    "ds-store-file",  # 外洩的 .DS_Store（目錄結構）
)

# 站台中繼資訊、HTTP 方法與通用資訊外洩偵測。directory-listing 因用 nuclei 的 flow 腳本（非純 http、
# 請求數不定）被內容閘門排除，目錄列舉改由純 http 的 dir-listing 涵蓋。
MISCELLANEOUS_TEMPLATE_IDS: tuple[str, ...] = (
    "http-trace",  # 啟用 TRACE 方法（grant 不接受 TRACE 時為平台阻擋）
    "options-method",  # OPTIONS 回報允許的方法
    "dir-listing",  # 目錄列舉
    "robots-txt",  # robots.txt
    "robots-txt-endpoint",  # robots.txt 揭露的路徑
    "sitemap-detect",  # sitemap.xml
    "security-txt",  # security.txt
    "clientaccesspolicy",  # clientaccesspolicy.xml（跨來源政策）
    "apple-app-site-association",  # apple-app-site-association
    "assetlinks-detect",  # .well-known/assetlinks.json
    "addeventlistener-detect",  # 前端 addEventListener（postMessage 面向）
    "deprecated-feature-policy",  # 已棄用的 Feature-Policy header
    "email-extractor",  # 頁面外洩的 email（T18 遮罩需涵蓋 extracted-results）
    "credit-card-number-detect",  # 頁面外洩的卡號樣式（同上，T18 遮罩）
    "old-copyright",  # 過期的版權年份（可能疏於維護）
)

# 錯誤設定：安全 header 與 cookie SameSite。cookies-without-httponly/secure 用
# nuclei 的 javascript 協定，被內容閘門排除；HttpOnly/Secure 改由 ZAP 被動規則涵蓋。
MISCONFIGURATION_TEMPLATE_IDS: tuple[str, ...] = (
    "http-missing-security-headers",  # negative matcher；T18 須濾掉 guard 的 403
    "missing-cookie-samesite-strict",  # cookie 缺 SameSite
    "xss-deprecated-header",  # 已棄用的 X-XSS-Protection
    "exposed-docker-api",  # 對外暴露的 Docker API
)

# 技術與技術棧辨識：通用指紋，加上對準 lab 靶機的棧（Juice Shop：Angular/Express；VAmPI、fixture：
# Python/Flask/Werkzeug）。
TECHNOLOGY_TEMPLATE_IDS: tuple[str, ...] = (
    "tech-detect",  # Wappalyzer 式通用技術辨識
    "fingerprinthub-web-fingerprints",  # FingerprintHub 指紋
    "favicon-detect",  # favicon hash 辨識
    "waf-detect",  # WAF 辨識（POST / 帶 <script>；需 grant 允許 POST）
    "flask-detect",  # Flask（VAmPI、fixture）
    "werkzeug-debugger-detect",  # Werkzeug 互動式 debugger（只偵測）
    "angular-detect",  # Angular（Juice Shop）
    "express-default-page",  # Express 預設頁（Juice Shop 的 Node 棧）
    "graphql-detect",  # GraphQL（POST introspection 到多個 path；需 grant 允許 POST）
)

# 通用主動探測：和 ZAP 的 active scan 刻意重疊，作為 M4「同一問題多來源」的候選。送探測性 payload、
# 和 ZAP 主動規則同一類、受同一套 guard/grant 限制，只對已核准的 lab 靶機執行。host-header-injection
# 不收（改 Host，guard 一律 ORIGIN_MISMATCH，和 ZAP 排除「會改 Host 的規則」一致，永遠無訊號）；
# strict-1 下帶 % 的 path 探測多半被 PATH_AMBIGUOUS 擋（平台阻擋，T33 後才可達）。
GENERIC_VULNERABILITY_TEMPLATE_IDS: tuple[str, ...] = (
    "cors-misconfig",  # CORS 設定錯誤
    "crlf-injection-generic",  # CRLF 注入（候選疊 ZAP 40003）
    "error-based-sql-injection",  # 錯誤型 SQLi（候選疊 ZAP 40018、fixture FX-01/03）
    "xss-uri-reflected",  # 反射型 XSS（候選疊 ZAP 40012；strict-1 多被平台阻擋）
    "open-redirect-generic",  # 開放轉址（候選疊 ZAP 20019；strict-1 多被平台阻擋）
    "generic-env",  # 外洩的 .env 檔
)

# 凍結清單的 template id（白名單；之外一律不執行）。順序不重要，載入與雜湊都會排序。
INCLUDE_TEMPLATE_IDS: tuple[str, ...] = (
    *EXPOSURE_TEMPLATE_IDS,
    *MISCELLANEOUS_TEMPLATE_IDS,
    *MISCONFIGURATION_TEMPLATE_IDS,
    *TECHNOLOGY_TEMPLATE_IDS,
    *GENERIC_VULNERABILITY_TEMPLATE_IDS,
)

# 會送探測性 payload 或 crafted POST 的模板（非單純 GET 偵測）：和 ZAP active scan
# 同類，需 grant 允許對應 method。供 T18 區分、日後組被動子集 profile；
# test_policy.py 核對是 INCLUDE 子集。
ACTIVE_PROBE_TEMPLATE_IDS: tuple[str, ...] = (
    *GENERIC_VULNERABILITY_TEMPLATE_IDS,
    "graphql-detect",  # POST introspection
    "waf-detect",  # POST / 帶 <script>
)

_LOCK_PATH = Path(__file__).with_name("templates.lock.txt")
# 凍結守衛：lock 檔內容的 sha256。改清單時由 tools/freeze_nuclei_templates.py 重新產生並更新這裡，
# test_policy.py 核對兩者一致。T18 另在掛載模板前逐檔驗證 sha256（執行期 fail-closed）。
TEMPLATES_LOCK_SHA256 = "1d97a25695a25bd5130a37beb5fb1e78988eed541456ed4be702171f1ecefc81"


@cache
def load_templates() -> tuple[Template, ...]:
    """載入凍結清單（templates.lock.txt）。格式錯誤會由 parse_lock 拋 ValueError。"""
    return parse_lock(lock_text())


def lock_text() -> str:
    """lock 檔的原始內容（供雜湊與測試使用）。"""
    return _LOCK_PATH.read_text(encoding="ascii")


def definition_sha256_for(templates: Sequence[Template]) -> str:
    """算一組模板的定義 sha256（含每檔 sha256，內容或路徑一改就變）。

    含每檔 sha256，所以任一模板內容或路徑改動都會改變這個值（不只 id 集合）。產生器以剛建好的模板
    呼叫它（避免 load_templates 的快取），nuclei_definition_sha256() 則以已提交的 lock 呼叫。
    """
    definition = {
        "commit": TEMPLATE_COMMIT,
        "flags": list(FROZEN_FLAGS),
        "release": TEMPLATE_RELEASE,
        "templates": sorted([t.id, t.sha256, t.path] for t in templates),
    }
    canonical = json.dumps(definition, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def nuclei_definition_sha256() -> str:
    """已提交凍結清單的定義 sha256（報告以它揭露模板定義；比照 ZAP 的 zap_definition_sha256）。"""
    return definition_sha256_for(load_templates())
