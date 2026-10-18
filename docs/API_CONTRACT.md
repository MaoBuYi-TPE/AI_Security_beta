# REST API 設計契約

本文件是預計實作的 API，不是已上線端點或已驗證 OpenAPI。M1 起由 Pydantic/router 產生實際 OpenAPI，並透過 contract test 檢查與此設計一致。

## 1. 共通約定

Prefix：`/api/v1`。平台使用 `Authorization: Bearer <platform_api_key>`。這個 key 只授權使用檢測平台，**不可轉送到被測網站**；被測網站的 secret 由 auth_profile_id 關聯。

角色：platform_admin 為全域管理員；operator 與 viewer 綁定一個 project。無公開註冊、密碼登入、OAuth 或 session cookie。起始管理 key 由受控本機 CLI 建立並只展示一次，後續可撤銷/輪替；不在這個規劃包提供真實 key。

UUID 為物件 ID，時間為 UTC ISO 8601。跨專案查詢一律加 project 授權過濾。不存在或無權存取的物件通常回 404，避免洩漏存在性；角色不足的已知操作回 403。無效 key 回 401。

T05 已實作上述驗證與權限：key 格式、有效期、驗證失敗的回應、權限矩陣與端點範例見 §13。

所有回應都使用統一的 envelope：

```json
{
  "success": true,
  "data": {},
  "error": null,
  "meta": {"page": 1, "limit": 25, "total": 0}
}
```

- `meta` 只出現在清單回應。
- 失敗時 `success=false`、`data=null`，`error` 的格式見 §12。
- 以下各節的 JSON 範例，除非特別標示，都是 `data` 欄位的內容。

分頁：

- 清單採 page/limit 分頁，預設 limit=25、上限 100；`meta` 回傳 page、limit、total。
- `/scans/{id}/events` 是例外，以 `after_sequence` cursor 輪詢。

日誌包含 request_id，但不包含憑證、完整 body 或 raw command。

## 2. 端點總表

| 方法 | 路徑 | 權限 | 回應與要點 |
|---|---|---|---|
| GET | /health/live | 可僅本機公開 | 200；僅程序存活，不含敏感依賴資訊 |
| GET | /health/ready | 管理網 | 200/503；DB、runner heartbeat、必要配置可用。T04 已實作 DB 可連線且 schema 在目前的 migration 版本，不符時回 503 `DEPENDENCY_UNAVAILABLE`；runner heartbeat 在 M2 加入 |
| POST | /api/v1/projects | platform_admin | 201 建立專案（T05 已實作） |
| GET | /api/v1/projects | 已授權 key | 200，只列可存取專案（T05 已實作） |
| GET | /api/v1/projects/{project_id} | 同專案 | 200；其他 project 與不存在的一樣回 404（T05 新增並實作） |
| POST | /api/v1/projects/{project_id}/keys | platform_admin | 201，建立 operator/viewer key，僅回傳一次完整值（T05 已實作） |
| DELETE | /api/v1/keys/{key_id} | platform_admin | 204，撤銷而非刪除 audit；重複撤銷也回 204（T05 已實作） |
| POST | /api/v1/projects/{project_id}/targets | operator/admin | 201 建立靶場目標，尚不可掃 |
| GET | /api/v1/projects/{project_id}/targets | viewer/operator/admin | 200 |
| GET | /api/v1/targets/{target_id} | 同專案 | 200 |
| PATCH | /api/v1/targets/{target_id} | operator/admin | 200；origin 變更需新 target 或重新授權 |
| POST | /api/v1/targets/{target_id}/scope-grants | operator/admin | 201 建立 pending 授權申請 |
| POST | /api/v1/scope-grants/{grant_id}/approve | platform_admin | 200；核對靶場/授權證據後核准 |
| POST | /api/v1/scope-grants/{grant_id}/revoke | platform_admin | 200；使有效執行停止新流量 |
| POST | /api/v1/targets/{target_id}/api-specs | operator/admin | 201；multipart 規格上傳，P0 不接受遠端 URL |
| GET | /api/v1/api-specs/{spec_id}/operations | 同專案 | 200；method/path、是否納入 scope |
| POST | /api/v1/targets/{target_id}/auth-profiles | operator/admin | 201；secret 只寫不讀 |
| PATCH | /api/v1/auth-profiles/{profile_id} | operator/admin | 200；產生新版本，舊 scan 快照不修改 |
| GET | /api/v1/scan-profiles | 同專案 | 200；只列當前 Runner 已驗證支援的 profile |
| GET | /api/v1/scanners | 已授權 key | 200；各引擎的版本、映像 digest、可用 profile 與 capability probe 結果 |
| POST | /api/v1/scans | operator/admin | 202 + scan_id；必須 Idempotency-Key |
| GET | /api/v1/scans | 同專案 | 200；target/status/time filter |
| GET | /api/v1/scans/{scan_id} | 同專案 | 200；引擎狀態、進度、coverage、停止理由 |
| GET | /api/v1/scans/{scan_id}/events | 同專案 | 200；以 after_sequence 輪詢，不先做 WebSocket |
| POST | /api/v1/scans/{scan_id}/cancel | operator/admin | 202/200；取消中/已終止，不代表已撤銷外部操作 |
| GET | /api/v1/scans/{scan_id}/findings | 同專案 | 200；kind/severity/tool/triage filter |
| GET | /api/v1/findings/{finding_id} | 同專案 | 200；來源 observations、遮罩證據與歷史 |
| PATCH | /api/v1/findings/{finding_id}/triage | operator/admin | 200；需 reason；敏感變更留 audit |
| POST | /api/v1/scan-comparisons | 同專案 | 200；只比較有權限且相同 target 的 scans |
| POST | /api/v1/scans/{scan_id}/reports | operator/admin | 201；建立 JSON/Markdown 遮罩報告 artifact（P1 加 SARIF） |
| GET | /api/v1/artifacts/{artifact_id}/download | 同專案 | 200；P0 僅遮罩報告/證據；不提供 raw secret artifact |
| GET | /api/v1/projects/{project_id}/audit-events | platform_admin | 200；遮罩且分頁，由新到舊（T05 已實作） |

`/health` 不在 `/api/v1`，便於部署探針；其他業務路由統一版本前綴。API 文件端點僅管理/開發環境開啟，不視為自行開發前端。

## 3. 建立 Target

```json
{
  "name": "API 教學靶場",
  "kind": "api",
  "base_url": "http://api-lab:8000",
  "environment": "lab"
}
```

`kind` 為 web/api/hybrid；P0 `environment` 僅 lab。URL 僅接 origin 與受限 seed path，禁止 userinfo/fragment/其他 scheme；實際解析與可達性由授權流程決定，不在 public API 隨意 fetch。

回應 target_id、canonical_origin、enabled、authorization_status=pending。Target 存在不代表允許掃描。

## 4. ScopeGrant

```json
{
  "allowed_origins": ["http://api-lab:8000"],
  "allowed_ips": ["10.77.0.20"],
  "allowed_paths": ["/api/search", "/api/items/{id}", "/api/me"],
  "allowed_methods": ["GET", "HEAD", "OPTIONS"],
  "excluded_paths": ["/api/logout", "/api/admin", "/api/delete"],
  "budget": {"requests_per_second": 2, "max_requests": 5000, "max_duration_seconds": 1500},
  "authorization_reference": "LAB-ASSET-RECORD-001",
  "valid_from": "2026-10-15T00:00:00Z",
  "valid_until": "2026-10-22T00:00:00Z"
}
```

日期、IP 與編號為示例，不代表真實授權或可用環境；實作時使用實際已核准資產。P0 不接受任意 regex；path 模式只允許完整 literal path 或由可信 OpenAPI 解析出的 route 佔位，禁止從字串前綴直接推論安全範圍。

核准需管理員驗證文件/靶場資產、origin 到 IP 的對應、隔離網路與副作用可接受性。若需 POST 等狀態改變方法，建立明確的實驗 scope，不擅自放寬原本只讀 grant。新 grant 版本不得偷偷改變執行中 scan。

## 5. 上傳 API 規格

P0 支援 OpenAPI 3.0 JSON/YAML，單檔上限 5 MiB（規劃值），使用安全 YAML loader，限制巢狀深度與解析資源。僅同文件內部 `$ref`；拒絕 file、network、absolute path refs 與任意 callback/webhook。

伺服器將 `servers` 固定對應至 target/grant，並產生受 scope 限制的 operation inventory。外部 import、GraphQL、Postman collection 是後續擴充，不先假設有做。

Operation 回應示例：

```json
[
  {"operation_id": "getItem", "method": "GET", "path": "/api/items/{id}", "eligible": true},
  {"operation_id": "deleteItem", "method": "DELETE", "path": "/api/items/{id}", "eligible": false, "reason": "METHOD_NOT_AUTHORIZED"}
]
```

分頁資訊放在 envelope 的 `meta`。

被排除的操作不能刪到完全看不見；報告需顯示哪些操作未測及理由。

## 6. 認證設定

```json
{
  "name": "測試一般使用者",
  "type": "bearer",
  "role_label": "standard_user",
  "secret": "<ONE_TIME_INPUT_NOT_RETURNED>",
  "preflight": {
    "method": "GET",
    "path": "/api/me",
    "expected_status": 200,
    "expected_json": {"role": "user", "username": "lab-user"}
  }
}
```

`<...>` 是示意 placeholder，不是可用 key。回應只包含 profile_id、version、type、role_label、secret_configured=true。API key header 類型允許受限 header name，拒絕 CR/LF 與覆蓋 Host/Connection 等危險 header；Cookie 同樣禁止換行。

preflight 必須在同 scope、相同 proxy 與 auth 注入機制下執行並計入 budget。JSON 比對僅支援固定簡單 equality，不允許使用者傳任意程式/script。200 且回登入頁不能算認證成功。

## 7. 建立 Scan

Header：`Idempotency-Key: <client-generated-random-key>`。

```json
{
  "target_id": "11111111-1111-4111-8111-111111111111",
  "scope_grant_id": "22222222-2222-4222-8222-222222222222",
  "api_spec_id": "33333333-3333-4333-8333-333333333333",
  "auth_profile_id": "44444444-4444-4444-8444-444444444444",
  "profile": "api_active_lab",
  "engines": ["zap", "nuclei"],
  "budget": {"requests_per_second": 2, "max_requests": 5000, "max_duration_seconds": 1500}
}
```

所有 ID 必須存在、屬於相同 target/project 且版本有效；示例 UUID 不是既有資源。無 spec 的 Web 掃描可以將 api_spec_id 設 null；未認證 profile 的 auth_profile_id 可為 null，但明確標記 anonymous，不得沿用認證覆蓋稱呼。

Engine/profile 只能從伺服器已驗證 allowlist 選擇。Budget 不可超過 grant 或平台上限。API 不接受 arbitrary URL list、raw headers、shell、template content、container image、host mounts 或 CLI flags。

首次回 202：

```json
{
  "scan_id": "55555555-5555-4555-8555-555555555555",
  "status": "queued",
  "status_url": "/api/v1/scans/55555555-5555-4555-8555-555555555555"
}
```

同 key 同內容再送，返回相同 scan_id 和當前狀態，不新增 scan；仍未完成可 202，已終止可 200。同 key 不同內容回 409 `IDEMPOTENCY_CONFLICT`。若該 target 已有另一個活躍 scan，初版回 409 `TARGET_BUSY`。

## 8. 狀態查詢

```json
{
  "scan_id": "55555555-5555-4555-8555-555555555555",
  "status": "partially_completed",
  "engines": [
    {"engine": "zap", "status": "succeeded", "observation_count": 3},
    {"engine": "nuclei", "status": "timed_out", "observation_count": 1, "error_code": "ENGINE_TIMEOUT"}
  ],
  "coverage": {
    "eligible_operations": 12,
    "observed_operations": 9,
    "authenticated_operations": 7,
    "coverage_measured": true,
    "limitations": ["ONE_ENGINE_INCOMPLETE"]
  },
  "budget_usage": {"requests_sent": 1840, "traffic_duration_seconds": 824},
  "results_complete": false
}
```

以上是資料格式示意，數字不是實驗結果。`budget_usage` 以 egress guard 的實際計數為準，不採用工具自報的數字。`observed_operations` 代表有實際 request 流量對應到該 operation，**不代表所有漏洞種類已測試**。`authenticated_operations` 需該身分已驗證與適用證據，不靠單一 status code 推論。

如缺少可信 OpenAPI 或流量對應，coverage 欄位可 null、coverage_measured=false 並附 reason，不填 100%。coverage_measured 只表示有量測依據，並非安全覆蓋完整或系統安全的判定。

不要顯示假精準進度百分比。工具沒有可靠百分比時，呈現目前 phase、完成引擎數、已用預算。

## 9. Finding 回應

```json
{
  "finding_id": "66666666-6666-4666-8666-666666666666",
  "kind": "security",
  "title": "待人工確認的 SQL 注入告警",
  "normalized_severity": "high",
  "cwe_ids": ["CWE-89"],
  "cve_ids": [],
  "cvss": null,
  "location": {"method": "GET", "path": "/api/search", "parameter_location": "query", "parameter_name": "q"},
  "auth_role": "standard_user",
  "triage_state": "unreviewed",
  "lifecycle_state": "open",
  "observations": [
    {"engine": "zap", "source_rule_id": "<FROM_REAL_OUTPUT>", "evidence_artifact_id": "77777777-7777-4777-8777-777777777777"}
  ],
  "verification": {"status": "not_performed", "notes": "工具告警尚未經人工確認"}
}
```

這不是聲稱某個實際靶場存在弱點。API 資料需由真實輸出產生；title/分類/mapping 有版本，缺乏 CWE 時可空陣列，不從文字硬猜。

## 10. Triage 與複掃比較

Triage request：

```json
{
  "triage_state": "confirmed",
  "lifecycle_state": "open",
  "reason": "於授權靶場人工核對重現證據",
  "evidence_artifact_ids": ["77777777-7777-4777-8777-777777777777"]
}
```

將 lifecycle_state 設為 resolved 時必須提供驗證理由；accepted_risk 不等於已修補。所有變更保留舊值與 actor。

Compare request：baseline_scan_id、current_scan_id。回傳 comparability、差異理由、new/persistent/not_observed/inconclusive 及每個 finding 的覆蓋證據。不同 target 直接 422；工具版本、scope 或 auth role 差異回 not_comparable/inconclusive，不捏造修復率。

## 11. 報告

`POST /scans/{id}/reports` request：`{"format":"markdown"}` 或 `json`；P1 起支援 `sarif`。已有可用結果即可產生報告，但必須標記部分/未完成。報告有版本、hash、生成時間與掃描時間；生成報告的時間不是漏洞發現時間。

Artifact download 必須再做 project/object 授權，不接受 `path=`。P0 不提供 raw artifact 公開下載端點。下載使用安全 Content-Disposition 檔名、正確 media type，不執行檔案內指令、不自動載入外部資源。

## 12. 穩定錯誤格式

完整的失敗回應（含 envelope）：

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "SCOPE_NOT_APPROVED",
    "message": "此目標尚無有效的掃描範圍授權。",
    "request_id": "<server-generated-id>"
  },
  "meta": null
}
```

| HTTP | 常見 code |
|---|---|
| 401 | UNAUTHENTICATED、API_KEY_EXPIRED |
| 403 | ROLE_NOT_ALLOWED、SCOPE_NOT_APPROVED、SCOPE_EXPIRED |
| 404 | RESOURCE_NOT_FOUND |
| 405 | METHOD_NOT_ALLOWED |
| 409 | IDEMPOTENCY_CONFLICT、TARGET_BUSY、INVALID_STATE_TRANSITION、PROJECT_NAME_CONFLICT |
| 413 | SPEC_TOO_LARGE、ARTIFACT_TOO_LARGE |
| 422 | INVALID_REQUEST、INVALID_TARGET、UNSUPPORTED_SCHEMA、EXTERNAL_REF_FORBIDDEN、ENGINE_UNSUPPORTED、PROFILE_INCOMPATIBLE |
| 429 | API_RATE_LIMITED |
| 500 | INTERNAL_ERROR |
| 503 | RUNNER_UNAVAILABLE、DEPENDENCY_UNAVAILABLE |

執行時錯誤如 AUTH_FAILED、AUTH_EXPIRED、ENGINE_TIMEOUT、OUTPUT_INVALID、POLICY_BLOCKED、BUDGET_EXHAUSTED 記於 scan/run，不全部變成 API 的 500。未知例外回通用訊息與 request_id，不洩漏 stack trace/Token。

T04 已實作的部分（`src/secscan/core/errors.py`）：

- 所有錯誤回應都是 envelope，並帶伺服器產生的 request_id（回應 header `X-Request-ID`；client 送來的值不採用）。
- 由框架產生的錯誤：
  - 路徑不存在：404 `RESOURCE_NOT_FOUND`。
  - 方法不符：405 `METHOD_NOT_ALLOWED`，保留 `Allow` header。
  - 其他 HTTP 狀態：`HTTP_ERROR`。
  - 這三種都不回傳框架的 detail 原文。
- 請求驗證失敗：422 `INVALID_REQUEST`。訊息只列出欄位位置（例如 `query.page`），最多 5 個，不回顯輸入值。
- 未處理的例外：500 `INTERNAL_ERROR`，回固定訊息與 request_id。伺服器端只記 request_id 與例外類別，不記例外訊息。
- 寫入違反 DB 約束時，repository 拋出帶約束名稱的 `ConstraintViolationError`，由 service 對應成上表的穩定錯誤碼（T05 起）。約束名稱本身不回給 client。

T05 加入的部分：

- 401、403、404 的判斷規則見 §13.2；`AppError` 可以帶回應 header（例如 401 的 `WWW-Authenticate: Bearer`）。
- 物件層級的 404 與「路徑不存在」的 404 完全相同（相同的 code 與訊息）。
- 約束對應：`uq_projects_name` → 409 `PROJECT_NAME_CONFLICT`；`fk_api_keys_project_id_projects` → 404；`ck_api_keys_expires_after_created` → 422 `INVALID_REQUEST`；不認得的約束 → 500 `INTERNAL_ERROR`（通用訊息）。

## 13. 平台 API key 與專案（T05 已實作）

理由見 `DECISIONS.md` §9。

### 13.1 key 的格式、有效期與驗證

- **格式**：`secscan_<prefix>_<secret>`。prefix 是 16 個小寫 hex（公開的識別碼），secret 是 64 個小寫 hex（256-bit 亂數）。
- **保存**：DB 只存 prefix 與完整 key 的 SHA-256；完整的 key 只在建立時出現一次，之後無法再取得，也不出現在 audit 與 log。
- **有效期**：所有 key 都會過期。`expires_at` 必須帶時區，晚於現在且不超過 365 天後；沒指定時為 90 天後。回應中的時間一律是 UTC。沒有到期時間的 key（只可能經由直接寫 DB 產生）一律視為過期。
- **撤銷**：撤銷後立即失效；資料列保留（audit 仍可追溯）。
- **使用方式**：`Authorization: Bearer <key>`。這把 key 只授權使用本平台，不可送往被測網站。

驗證失敗的回應：

| 情況 | HTTP | code |
|---|---|---|
| 沒帶 key、scheme 不是 Bearer、格式不符、key 不存在、secret 錯誤、已撤銷 | 401 | `UNAUTHENTICATED`：回應完全相同，都含 `WWW-Authenticate: Bearer` |
| secret 正確但已過期 | 401 | `API_KEY_EXPIRED` |

- 先比對 secret，再判斷撤銷與到期：只知道 prefix 的人看不出 key 是否已過期。
- `/api/v1` 的所有路由都要 key，驗證在欄位驗證之前：沒有 key 時，body 欄位不符不會先得到 422。但 FastAPI 會在驗證 key 之前先讀取並解析 JSON body，所以語法錯誤的 JSON 會得到 422 `INVALID_REQUEST`（只列出位置），非法的 UTF-8 等會得到 400；路徑不存在（404）與方法不符（405）也與 key 無關。
- 目前沒有請求大小上限，也沒有速率限制（429 `API_RATE_LIMITED`）；在驗證前先擋下的 middleware 列入 T07 與 T23（`DECISIONS.md` §9.5）。
- 伺服器日誌記下失敗原因（missing、malformed、unknown_key、hash_mismatch、revoked、expired）與 request_id，不記 client 送來的值。

### 13.2 權限

| 角色 | 全域管理<br>（建立 project、撤銷 key） | 自己 project：讀 | 自己 project：寫<br>（T06 起的資源） | 自己 project：管理<br>（建立 key、看稽核） | 其他 project |
|---|---|---|---|---|---|
| platform_admin | 允許 | 允許 | 允許 | 允許 | 允許（不存在才 404） |
| operator | 403 | 允許 | 允許 | 403 | 404 |
| viewer | 403 | 允許 | 403 | 403 | 404 |

先判斷 project，再判斷角色：不是自己的 project 一律回 404（與不存在相同），是自己的 project 但角色不足才回 403 `ROLE_NOT_ALLOWED`。被拒絕的存取會記在伺服器日誌（decision、key_id、角色、權限、project_id、request_id），不記 body。

### 13.3 端點

建立專案（`POST /api/v1/projects`，201）：

```json
{"name": "API 教學靶場"}
```

```json
{"id": "<uuid>", "name": "API 教學靶場", "created_at": "2026-10-19T08:00:00Z"}
```

- 名稱 1–100 個字元，不可全是空白（含全形空白）或含 NUL；不接受其他欄位。
- 名稱重複回 409 `PROJECT_NAME_CONFLICT`。

清單（`GET /api/v1/projects?page=1&limit=25`）：platform_admin 看到全部，其他角色只看到自己的 project；依建立時間由舊到新，`meta` 帶 page、limit、total。

建立 key（`POST /api/v1/projects/{project_id}/keys`，201，回應帶 `Cache-Control: no-store`）：

```json
{"name": "ci-reader", "role": "viewer", "expires_at": "2027-01-17T00:00:00Z"}
```

```json
{
  "id": "<uuid>",
  "project_id": "<uuid>",
  "role": "viewer",
  "name": "ci-reader",
  "prefix": "<16 個 hex>",
  "created_at": "2026-10-19T08:00:00Z",
  "expires_at": "2027-01-17T00:00:00Z",
  "key": "secscan_<16 個 hex>_<64 個 hex>"
}
```

- `role` 只接受 `operator` 或 `viewer`；platform_admin key 只能由本機 CLI 建立（§13.4）。
- `expires_at` 可省略；不接受其他欄位（例如 `key_hash`）。
- project 不存在時回 404。

撤銷 key（`DELETE /api/v1/keys/{key_id}`，204，沒有 body）：重複撤銷也回 204，但 audit 只記第一次；key 不存在時回 404。

稽核事件（`GET /api/v1/projects/{project_id}/audit-events`）：由新到舊、分頁。每筆含 `id`、`created_at`、`action`、`object_type`、`object_id`、`actor_key_id`、`request_id` 與 `changes`。

- `changes` 寫入前已遮罩（authorization、cookie、password、secret、token、key hash 等欄位，以及文字中的平台 key、Bearer 值與 JWT），讀出時再遮罩一次，也有大小上限。
- T05 會寫入的事件：`project.create`、`api_key.create`、`api_key.revoke`。
- 沒有所屬 project 的事件（CLI 建立 admin key、撤銷 admin key）目前只能直接查 DB；查詢 API 留給 T21。

### 13.4 本機 CLI

```bash
uv run secscan-admin create-admin-key --name "本機管理員" [--expires-in-days 90] [--output PATH]
```

- DB 連線設定與 API 相同（`DB_*` 環境變數或 `.env`）。DB 無法連線或 schema 不是最新版時，提示 `make db-up` 或 `make migrate`，exit 1；參數錯誤時 exit 2。
- 有效天數 1–365，預設 90。
- 完整的 key 只在 commit 成功之後寫出一次：預設寫到 stdout；`--output` 寫進新建、權限 600 的檔案（已存在就拒絕，不覆寫）。說明、key id 與 prefix 寫到 stderr。
- 沒有建立 key（設定錯誤、DB 不可用、commit 失敗）時 exit 1，不寫出任何東西，也不留下空檔；DB 錯誤只回報例外類別。
- key 已建立但寫不出去（例如 stdout 已關閉）時 exit 1，只回報 key id；沒有人拿得到它的值，所以無法使用。
- 寫一筆 `api_key.create` audit，actor 為空、`changes.source` 為 `cli`。
