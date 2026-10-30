"""ZAP 的映像、版本、必要的 add-on 與 active scan 的規則白名單（docs/DECISIONS.md §18.4、§18.8）。

鎖定映像的 53 條 active scan 規則逐條以類別審查，紀錄在 docs/TOOLS.md §7。白名單之外的規則
一律關閉（defaultThreshold: off）：映像更新帶進來的新規則不會自動啟用。排除的類別：OAST 與
OUT_OF_BAND、HTTPS 與非 HTTP 的協定、DoS 類、需要瀏覽器的、會改 Host 的、script 規則、SOAP、
alpha 的規則、雜訊（User Agent Fuzzer）、時間型的注入（耗掉時間預算；T16 再評估）。
web 與 api 各一份（ARCHITECTURE §5：兩種 profile 不等價）；api 以 ZAP 的 API-Minimal policy 為基準。
"""

from collections.abc import Mapping
from types import MappingProxyType

from secscan.core.json_types import JsonObject
from secscan.scanners.domain.plan import ImageReference
from secscan.scans.domain.catalog import ScanProfile

# T03 鎖定的映像（docs/TOOLS.md §1；2026-10-16 發布，早於兩週）。
ZAP_IMAGE = ImageReference.parse(
    "zaproxy/zap-stable:20261016"
    "@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6"
)
ZAP_VERSION = "2.17.0"
# plan 用到的 add-on 與審查過的版本（/zap/plugin 的檔名；同一個 add-on 有多個檔案時 ZAP 載入最大的
# 版本）。probe 確認鎖定映像中的版本相同。
REQUIRED_ADDONS: Mapping[str, str] = MappingProxyType(
    {
        "ascanrules": "84",
        "automation": "0.61.0",
        "commonlib": "1.44.0",
        "network": "0.31.0",
        "openapi": "58",
        "pscan": "0.6.0",
        "pscanrules": "76",
        "reports": "0.46.0",
        "spider": "0.20.0",
    }
)

WEB_RULES: tuple[int, ...] = (
    0,  # Directory Browsing
    6,  # Path Traversal
    7,  # Remote File Inclusion
    10045,  # Source Code Disclosure - /WEB-INF Folder
    10048,  # Remote Code Execution - Shell Shock
    10058,  # GET for POST（web 一定允許 GET）
    20017,  # Source Code Disclosure - CVE-2012-1823
    20018,  # Remote Code Execution - CVE-2012-1823
    20019,  # External Redirect
    40003,  # CRLF Injection
    40008,  # Parameter Tampering
    40009,  # Server Side Include
    40012,  # Cross Site Scripting (Reflected)
    40014,  # Cross Site Scripting (Persistent)
    40016,  # Cross Site Scripting (Persistent) - Prime
    40017,  # Cross Site Scripting (Persistent) - Spider
    40018,  # SQL Injection
    40028,  # ELMAH Information Leak
    40029,  # Trace.axd Information Leak
    40032,  # .htaccess Information Leak
    40034,  # .env Information Leak
    40035,  # Hidden File Finder
    40042,  # Spring Actuator Information Leak
    40045,  # Spring4Shell
    40048,  # Remote Code Execution (React2Shell)
    90017,  # XSLT Injection
    90019,  # Server Side Code Injection
    90020,  # Remote OS Command Injection
    90021,  # XPath Injection
    90024,  # Generic Padding Oracle
    90035,  # Server Side Template Injection
)
API_RULES: tuple[int, ...] = (
    0,  # Directory Browsing
    7,  # Remote File Inclusion
    20019,  # External Redirect
    40003,  # CRLF Injection
    40008,  # Parameter Tampering
    40009,  # Server Side Include
    40018,  # SQL Injection
    40042,  # Spring Actuator Information Leak
    90017,  # XSLT Injection
    90019,  # Server Side Code Injection
    90020,  # Remote OS Command Injection
    90021,  # XPath Injection
    90035,  # Server Side Template Injection
)
ACTIVE_SCAN_RULES: Mapping[ScanProfile, tuple[int, ...]] = MappingProxyType(
    {ScanProfile.WEB_ACTIVE_LAB: WEB_RULES, ScanProfile.API_ACTIVE_LAB: API_RULES}
)
POLICY_NAMES: Mapping[ScanProfile, str] = MappingProxyType(
    {ScanProfile.WEB_ACTIVE_LAB: "secscan-web", ScanProfile.API_ACTIVE_LAB: "secscan-api"}
)
# 起始值（T16 依量測調整）：低強度讓更多規則在預算內跑得完。
DEFAULT_STRENGTH = "low"
RULE_THRESHOLD = "medium"


def policy_definition(profile: ScanProfile) -> JsonObject:
    """activeScan 與 activeScan-policy 共用的 policyDefinition：白名單以外一律關閉。"""
    return {
        "defaultStrength": DEFAULT_STRENGTH,
        "defaultThreshold": "off",
        "rules": [{"id": rule, "threshold": RULE_THRESHOLD} for rule in ACTIVE_SCAN_RULES[profile]],
    }
