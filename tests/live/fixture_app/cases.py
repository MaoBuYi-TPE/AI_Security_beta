"""T30 ground truth 案例登錄表：fixture app 的事實來源（docs/SECURITY_AND_TESTING.md §5.1）。

每個 Case 描述一個端點在弱點版（insecure，正例）與修補版（secure，負例）的預期行為、
類別、OWASP 對應、ZAP 能否偵測、人工確認方式與修補差異。案例表（§4.4）、單元測試與
OpenAPI 規格都從這裡導出，三者不各寫一份。

strict-1 的 guard 只擋 path 中的百分比編碼：所以多數正例放在 query／form／body／header／
cookie，guard 可達；`platform_blocked=True` 的案例（path 參數注入）在 strict-1 下被 guard 以
PATH_AMBIGUOUS 擋下，另記為「平台阻擋」，不計入掃描器漏報（DECISIONS.md §21.5），T33 的
encoded-params-1 放寬後自然可達。
"""

from __future__ import annotations

from dataclasses import dataclass

from .routes import HANDLER_KEYS

ANONYMOUS = "anonymous"
STANDARD_USER = "standard_user"


@dataclass(frozen=True)
class Case:
    case_id: str  # 例如 T30-FX-01
    handler: str  # routes.py 的 handler key
    method: str
    path: str  # 路由樣板（含 {id}）
    surface: str  # web / api
    auth_role: str
    kind: str  # security / contract
    category: str  # 弱點/檢查類別
    owasp: str  # OWASP 對應（official/curated；沒有時留空）
    detection: str  # ZAP 能否偵測
    vulnerable_behavior: str  # insecure 模式的預期（正例）
    patched_behavior: str  # secure 模式的修補（負例），即修補差異
    verification: str  # 人工確認方式
    platform_blocked: bool = False  # strict-1 下 guard 擋下
    holdout: bool = False  # 保留作 holdout（§5.2）


SECURITY_CASES: tuple[Case, ...] = (
    Case(
        "T30-FX-01",
        "search",
        "GET",
        "/search",
        "web",
        ANONYMOUS,
        "security",
        "SQL 注入（query 參數 q）",
        "A03:2025 Injection",
        "主動（40018）",
        "q 以字串拼接進 SQL；單引號造成 sqlite 語法錯誤回 500 並洩漏訊息",
        "以參數化查詢執行，q 當資料處理，壞值回正常空結果",
        "q=apple' 回 500（sqlite OperationalError）；對照合法 q 回 200",
    ),
    Case(
        "T30-FX-02",
        "greet",
        "GET",
        "/greet",
        "web",
        ANONYMOUS,
        "security",
        "反射型 XSS（query 參數 name）",
        "A03:2025 Injection",
        "主動（40012/40014）",
        "name 未轉義直接寫進 HTML，標籤被反射",
        "以 html.escape 轉義後才輸出",
        "name=<b>x</b> 在回應中原樣出現（未轉義）",
    ),
    Case(
        "T30-FX-03",
        "login",
        "POST",
        "/login",
        "web",
        ANONYMOUS,
        "security",
        "SQL 注入（表單 body user/pass）",
        "A03:2025 Injection",
        "主動（40018）",
        "表單欄位拼接進登入 SQL，單引號回 500；永真條件可繞過登入",
        "參數化查詢比對帳密，壞值回 401",
        "user=admin'-- 之類造成 500 或非預期登入；對照正常登入回 200",
    ),
    Case(
        "T30-FX-04",
        "search",
        "GET",
        "/search",
        "web",
        ANONYMOUS,
        "security",
        "錯誤訊息／堆疊洩漏",
        "A05:2025 Security Misconfiguration",
        "被動（90022）/人工",
        "SQL 錯誤時回應 body 含 sqlite 的例外訊息與內部細節",
        "錯誤只回一般訊息，不含內部細節",
        "q=apple' 的 500 回應 body 含 OperationalError 字樣",
        holdout=True,
    ),
    Case(
        "T30-FX-05",
        "home",
        "GET",
        "/",
        "web",
        ANONYMOUS,
        "security",
        "缺少安全 header（含 CSP）",
        "A05:2025 Security Misconfiguration",
        "被動（10038 CSP、10021 XCTO）",
        "回應缺 Content-Security-Policy、X-Content-Type-Options 等",
        "每個回應附上 SECURITY_HEADERS",
        "任一頁回應的 header 缺 CSP 與 X-Content-Type-Options",
    ),
    Case(
        "T30-FX-06",
        "users_list",
        "GET",
        "/api/users",
        "api",
        ANONYMOUS,
        "security",
        "CORS 萬用字元反射",
        "A05:2025 Security Misconfiguration",
        "被動（10098）",
        "回應帶 Access-Control-Allow-Origin: * 並反射 Origin",
        "不輸出萬用 CORS header",
        "回應含 Access-Control-Allow-Origin: *",
    ),
    Case(
        "T30-FX-07",
        "login",
        "POST",
        "/login",
        "web",
        ANONYMOUS,
        "security",
        "Cookie 缺 HttpOnly/Secure",
        "A05:2025 Security Misconfiguration",
        "被動（10010 HttpOnly、10011 Secure）",
        "登入成功的 Set-Cookie 沒有 HttpOnly、Secure、SameSite",
        "Set-Cookie 附上 HttpOnly; Secure; SameSite=Strict",
        "登入回應的 Set-Cookie 缺 HttpOnly 與 Secure",
    ),
    Case(
        "T30-FX-08",
        "go",
        "GET",
        "/go",
        "web",
        ANONYMOUS,
        "security",
        "開放轉址（query 參數 next）",
        "A01:2025 Broken Access Control",
        "主動（40011）/人工",
        "next 任意外部 URL 都 302 轉出去",
        "next 只允許白名單內的相對路徑，否則回 400",
        "next=http://lab-canary:8080/ 回 302 Location 指向外部",
    ),
    Case(
        "T30-FX-09",
        "backup",
        "GET",
        "/backup.sql",
        "web",
        ANONYMOUS,
        "security",
        "敏感檔案暴露",
        "A05:2025 Security Misconfiguration",
        "主動/人工",
        "/backup.sql 回 200 並吐出含帳密的傾印內容",
        "/backup.sql 回 404",
        "GET /backup.sql 回 200、body 含使用者資料",
        holdout=True,
    ),
    Case(
        "T30-FX-10",
        "order_get",
        "GET",
        "/api/orders/{id}",
        "api",
        STANDARD_USER,
        "security",
        "BOLA／IDOR（物件層級授權）",
        "API1:2023 BOLA",
        "不在 ZAP 能力範圍（人工）",
        "任何帶 token 者都能讀任一 order，不檢查擁有者",
        "只允許讀自己（token 對應使用者）的 order，否則回 404",
        "以 alice 的 token 讀 bob 的 order（1002）仍回 200",
    ),
    Case(
        "T30-FX-11",
        "users_create",
        "POST",
        "/api/users",
        "api",
        ANONYMOUS,
        "security",
        "Mass assignment（JSON body 的 is_admin）",
        "API3:2023 BOPLA / A04:2025",
        "不在 ZAP 能力範圍（人工）",
        "註冊時 body 的 is_admin 直接寫入，可自封管理員",
        "只接受白名單欄位，is_admin 一律 0",
        "註冊帶 is_admin=true 後該使用者的 is_admin 為真",
    ),
    Case(
        "T30-FX-12",
        "users_list",
        "GET",
        "/api/users",
        "api",
        ANONYMOUS,
        "security",
        "過度資料暴露",
        "API3:2023 BOPLA",
        "不在 ZAP 能力範圍（人工）",
        "使用者清單回傳 password 與 secret_note 等敏感欄位",
        "只回傳 id、username、email 的安全投影",
        "GET /api/users 的回應含 password／secret_note",
        holdout=True,
    ),
)

CONTRACT_CASES: tuple[Case, ...] = (
    Case(
        "T30-FX-C1",
        "order_get",
        "GET",
        "/api/orders/{id}",
        "api",
        STANDARD_USER,
        "contract",
        "壞輸入的狀態碼（非整數 id）",
        "",
        "人工/被動（90022）",
        "非整數 id 造成未處理例外、回 500",
        "非整數 id 回 400",
        "GET /api/orders/abc 回 500（弱點版）對 400（修補版）",
    ),
    Case(
        "T30-FX-C2",
        "users_create",
        "POST",
        "/api/users",
        "api",
        ANONYMOUS,
        "contract",
        "缺必填欄位的狀態碼",
        "",
        "人工",
        "缺 username 造成未處理例外、回 500",
        "缺必填欄位回 400",
        "POST /api/users 不帶 username 回 500 對 400",
    ),
    Case(
        "T30-FX-C3",
        "user_get",
        "GET",
        "/api/users/{id}",
        "api",
        ANONYMOUS,
        "contract",
        "回應不符宣告的 schema",
        "",
        "人工（對照 OpenAPI）",
        "回應多出未宣告欄位、型別與 OpenAPI 不符",
        "回應符合 OpenAPI 宣告的 schema",
        "GET /api/users/1 的回應欄位與型別對照規格",
        holdout=True,
    ),
    Case(
        "T30-FX-C4",
        "users_create",
        "POST",
        "/api/users",
        "api",
        ANONYMOUS,
        "contract",
        "型別混淆（body 是陣列）",
        "",
        "人工",
        "body 是 JSON 陣列時造成未處理例外、回 500",
        "非物件 body 回 400",
        "POST /api/users body 為 [] 回 500 對 400",
    ),
    Case(
        "T30-FX-C5",
        "order_put",
        "PUT",
        "/api/orders/{id}",
        "api",
        STANDARD_USER,
        "contract",
        "未文件化 method 的狀態碼",
        "",
        "人工",
        "OpenAPI 未宣告的 PUT 造成未處理例外、回 500",
        "未支援的 method 回 405",
        "PUT /api/orders/1001 回 500 對 405",
    ),
    Case(
        "T30-FX-C6",
        "users_create",
        "POST",
        "/api/users",
        "api",
        ANONYMOUS,
        "contract",
        "格式錯誤的 JSON body",
        "",
        "人工",
        "body 不是合法 JSON 時造成未處理例外、回 500",
        "非法 JSON 回 400",
        "POST /api/users body 為壞 JSON 回 500 對 400",
        holdout=True,
    ),
)

PLATFORM_BLOCKED_CASES: tuple[Case, ...] = (
    Case(
        "T30-FX-PB-01",
        "user_by_name",
        "GET",
        "/users/{username}",
        "api",
        ANONYMOUS,
        "security",
        "SQL 注入（path 參數 username）",
        "A03:2025 Injection",
        "主動（40018），strict-1 平台阻擋",
        "username 拼接進 SQL；但探測需 path 中的 %27，strict-1 下 guard 以 PATH_AMBIGUOUS 擋下",
        "參數化查詢；T33 encoded-params-1 放寬後此案例才可達",
        "對照實驗（不經 guard）name1' 回 500；經 guard 被 PATH_AMBIGUOUS 擋下",
        platform_blocked=True,
    ),
)

ALL_CASES: tuple[Case, ...] = SECURITY_CASES + CONTRACT_CASES + PLATFORM_BLOCKED_CASES


def cases_by_handler(handler: str) -> tuple[Case, ...]:
    return tuple(case for case in ALL_CASES if case.handler == handler)


def _validate() -> None:
    """載入時檢查案例登錄表與路由一致，並符合 §5.1 的數量。"""
    unknown = {case.handler for case in ALL_CASES} - HANDLER_KEYS
    if unknown:
        raise ValueError(f"案例指向未知的 handler：{sorted(unknown)}")
    ids = [case.case_id for case in ALL_CASES]
    if len(ids) != len(set(ids)):
        raise ValueError("case_id 重複")
    security = [case for case in SECURITY_CASES if not case.platform_blocked]
    if len(security) != 12:
        raise ValueError(f"安全正例應為 12 個，實際 {len(security)}")
    if len(CONTRACT_CASES) != 6:
        raise ValueError(f"contract 正例應為 6 個，實際 {len(CONTRACT_CASES)}")


_validate()
