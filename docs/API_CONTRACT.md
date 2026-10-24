# REST API 設計契約

本文件是預計實作的 API，不是已上線端點或已驗證 OpenAPI。M1 起由 Pydantic/router 產生實際 OpenAPI，並透過 contract test 檢查與此設計一致。

## 1. 共通約定

Prefix：`/api/v1`。平台使用 `Authorization: Bearer <platform_api_key>`。這個 key 只授權使用檢測平台，**不可轉送到被測網站**；被測網站的 secret 由 auth_profile_id 關聯。

角色：platform_admin 為全域管理員；operator 與 viewer 綁定一個 project。無公開註冊、密碼登入、OAuth 或 session cookie。起始管理 key 由受控本機 CLI 建立並只展示一次，後續可撤銷/輪替；不在這個規劃包提供真實 key。

UUID 為物件 ID，時間為 UTC ISO 8601。跨專案查詢一律加 project 授權過濾。不存在或無權存取的物件通常回 404，避免洩漏存在性；角色不足的已知操作回 403。無效 key 回 401。

T05 已實作上述驗證與權限：key 格式、有效期、驗證失敗的回應、權限矩陣與端點範例見 §13。T06 的 target 與 scope grant 見 §14，T07 的 API 規格見 §15。

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
| POST | /api/v1/projects/{project_id}/targets | operator/admin | 201 建立靶場目標，尚不可掃（T06 已實作） |
| GET | /api/v1/projects/{project_id}/targets | viewer/operator/admin | 200（T06 已實作） |
| GET | /api/v1/targets/{target_id} | 同專案 | 200（T06 已實作） |
| PATCH | /api/v1/targets/{target_id} | operator/admin | 200；只能改名稱與啟用狀態，origin 要改就建立新的 target（T06 已實作） |
| POST | /api/v1/targets/{target_id}/scope-grants | operator/admin | 201 建立 pending 授權申請（T06 已實作） |
| GET | /api/v1/targets/{target_id}/scope-grants | 同專案 | 200；target 的所有版本，新版本在前（T06 新增並實作） |
| GET | /api/v1/scope-grants/{grant_id} | 同專案 | 200（T06 新增並實作） |
| POST | /api/v1/scope-grants/{grant_id}/approve | platform_admin | 200；核對靶場/授權證據後核准（T06 已實作） |
| POST | /api/v1/scope-grants/{grant_id}/revoke | platform_admin | 200；之後不能再用它建立 scan。停止執行中的 scan 由 T09、T13 處理（T06 已實作撤銷本身） |
| POST | /api/v1/targets/{target_id}/api-specs | operator/admin | 201；raw body 上傳 OpenAPI 3.0（JSON 或 YAML），P0 不接受遠端 URL；servers 改綁到 target 的 origin（T07 已實作；原規劃的 multipart 改掉，理由見 `DECISIONS.md` §11.1） |
| GET | /api/v1/targets/{target_id}/api-specs | 同專案 | 200；target 的所有版本，新版本在前（T07 新增並實作） |
| GET | /api/v1/api-specs/{spec_id} | 同專案 | 200；不含文件內容（T07 新增並實作） |
| GET | /api/v1/api-specs/{spec_id}/operations | 同專案 | 200；method/path，帶 `scope_grant_id` 時附上是否在範圍內與原因（T07 已實作） |
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

`kind` 為 web/api/hybrid；P0 `environment` 僅 lab。實際解析與可達性由授權流程決定，不在 public API 隨意 fetch。

T06 的實際規則（理由見 `DECISIONS.md` §10.2，完整說明見 §14.1）：

- `base_url` 只能是 origin：`http://主機[:port]`，結尾可以有一個 `/`。原規劃的「受限 seed path」延到 M3（ZAP web profile 需要時）。
- P0 只接受 http；userinfo、反斜線、percent-encoding、path、query、fragment、非 ASCII、IPv6、`localhost`、數字形式模糊的 host 都拒絕。
- 回應中沒有 `authorization_status`：target 本身沒有授權狀態，能不能掃描看 scope grant（§4）。Target 存在不代表允許掃描。

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

T06 的實際規則（理由見 `DECISIONS.md` §10.3、§10.4，完整說明見 §14.2–§14.4）：

- 要允許全部 path，必須明確設定 `"allow_all_paths": true`（此時 `allowed_paths` 必須是空的）；空的 `allowed_paths` 不代表全部。
- `budget` 可省略，省略的項目使用上限（2 req/s、5,000 次、1,500 秒）。
- `LAB_ONLY` 時，`allowed_ips` 的每個 IP 都必須是 `LAB_CIDR` 內的主機位址。
- 建立後範圍不能修改；要改範圍就申請新版本（`version` 遞增）。

## 5. 上傳 API 規格

P0 支援 OpenAPI 3.0 JSON/YAML，使用安全 YAML loader，限制巢狀深度與解析資源。僅同文件內部 `$ref`；拒絕 file、network、absolute path refs 與任意 callback/webhook。

伺服器將 `servers` 固定對應至 target/grant，並產生受 scope 限制的 operation inventory。外部 import、GraphQL、Postman collection 是後續擴充，不先假設有做。

T07 的實際規則（理由見 `DECISIONS.md` §11，完整說明見 §15）：

- 以 raw body 上傳（不是 multipart），`Content-Type` 只接受 `application/json` 與 `application/yaml`。
- 單檔上限 1 MiB（原規劃 5 MiB），正規化後最多 2 MiB；巢狀 64 層、10 萬個節點、1,000 個 operation。
- `servers` 一律改綁成 target 的 origin 加 base path；path、operation、link 層級的 server 拒絕。

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
| 400 | INVALID_REQUEST（Content-Length 不合法、上傳途中斷線） |
| 401 | UNAUTHENTICATED、API_KEY_EXPIRED |
| 403 | ROLE_NOT_ALLOWED、SCOPE_NOT_APPROVED、SCOPE_EXPIRED |
| 404 | RESOURCE_NOT_FOUND |
| 405 | METHOD_NOT_ALLOWED |
| 408 | REQUEST_TIMEOUT |
| 409 | IDEMPOTENCY_CONFLICT、TARGET_BUSY、INVALID_STATE_TRANSITION、PROJECT_NAME_CONFLICT、TARGET_ORIGIN_CONFLICT、TARGET_DISABLED、QUOTA_EXCEEDED |
| 413 | SPEC_TOO_LARGE、REQUEST_TOO_LARGE、ARTIFACT_TOO_LARGE |
| 415 | UNSUPPORTED_MEDIA_TYPE |
| 422 | INVALID_REQUEST、INVALID_TARGET、SCOPE_OUTSIDE_LAB、INVALID_SPEC、UNSUPPORTED_SCHEMA、EXTERNAL_REF_FORBIDDEN、ENGINE_UNSUPPORTED、PROFILE_INCOMPATIBLE |
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

T06 加入的部分（§14）：

- 422 `INVALID_TARGET`：URL 不是可接受的 origin；422 `SCOPE_OUTSIDE_LAB`：IP 不是 `LAB_CIDR` 內的主機位址。
- 範圍、預算與期限不合規則：422 `INVALID_REQUEST`，訊息說明欄位、位置與原因（例如「allowed_paths 第 2 個：path 不可有 . 或 .. 段落。」），但不回顯輸入的值（URL 可能帶帳密）。
- 409：`TARGET_ORIGIN_CONFLICT`（同一個 project 已有相同 origin 的 target）、`INVALID_STATE_TRANSITION`（目前的狀態不允許核准或撤銷）、`TARGET_DISABLED`（掃描 gate）、`QUOTA_EXCEEDED`（target 或待核准申請的數量已達上限，§14.1、§14.2）。
- 名稱、授權文件編號、核准與撤銷的說明都不接受控制字元與不可見的格式字元（例如換行、tab、零寬空白、bidi 控制字元），T05 的 project 與 key 名稱也一樣（`DECISIONS.md` §10.10）。
- 403 `SCOPE_NOT_APPROVED`、`SCOPE_EXPIRED`：由掃描 gate 回傳（§14.5），T09 建立 scan 時使用。
- 約束對應：`uq_targets_project_id_canonical_origin` → 409 `TARGET_ORIGIN_CONFLICT`；其他 T06 的約束在 domain 層就已擋下，萬一 DB 回報則是 500（代表程式有錯）。

T07 加入的部分（§15）：

- 413：`REQUEST_TOO_LARGE`（任何請求超過 2 MiB，在路由之前由 middleware 回應）、`SPEC_TOO_LARGE`（規格超過 1 MiB，或正規化後超過 2 MiB）。
- 415 `UNSUPPORTED_MEDIA_TYPE`：上傳的 Content-Type 不是 `application/json` 或 `application/yaml`，或 charset 不是 UTF-8。
- 422：`INVALID_SPEC`（壞掉的文件、超過上限、缺少必要欄位、懸空的參照…）、`UNSUPPORTED_SCHEMA`（P0 不支援的功能）、`EXTERNAL_REF_FORBIDDEN`（參照指向文件以外）。訊息說明原因與位置（行與欄，或只由 key 與陣列索引組成的 JSON Pointer），不含任何值。
- 408 `REQUEST_TIMEOUT`：上傳的規格沒有在 10 秒內讀完。
- 400 `INVALID_REQUEST`：Content-Length 不是十進位整數，或上傳途中斷線。

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
- `/api/v1` 的所有路由都要 key，驗證在欄位驗證之前（T07 起，`DECISIONS.md` §11.1）：
  - 沒有 Bearer，或 key 的格式不符：middleware 在路由之前就回上表的 401，一個 byte 的 body 都不讀。所以沒有 key 時，`/api/v1` 下不存在的路徑與不符的 method 也回 401（有 key 時才是 404、405）。
  - 格式正確的 key 要查 DB 才知道是否有效：FastAPI 在那之前仍會先讀取並解析 JSON body，語法錯誤的 JSON 得到 422 `INVALID_REQUEST`（只列出位置），非法的 UTF-8 等得到 400。
- 請求大小上限（T07）：任何請求超過 2 MiB 回 413 `REQUEST_TOO_LARGE`；有 Content-Length 時不讀 body，chunked 時讀到超過就停。順序在 key 的檢查之後：沒有 key 的大請求回 401。
- 以 `--root-path` 部署時，middleware 判斷是否在 `/api/v1` 底下之前，先去掉 `root_path`（與路由的判斷相同）。
- 目前沒有速率限制（429 `API_RATE_LIMITED`），列入 T23（`DECISIONS.md` §9.5）。
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

## 14. Target 與 ScopeGrant（T06 已實作）

理由見 `DECISIONS.md` §10。T06 不對使用者給的 URL 發出任何流量：不解析 DNS，也不連線。以下的名稱、IP 與日期都是示例。

### 14.1 Target

建立（`POST /api/v1/projects/{project_id}/targets`，201）：

```json
{"name": "VAmPI", "kind": "api", "base_url": "http://vampi-vuln:5000"}
```

```json
{
  "id": "<uuid>",
  "project_id": "<uuid>",
  "name": "VAmPI",
  "kind": "api",
  "canonical_origin": "http://vampi-vuln:5000",
  "environment": "lab",
  "enabled": true,
  "created_at": "2026-10-19T08:00:00Z"
}
```

- `name` 1–100 字元（規則同 project 名稱）；`kind` 為 `web`、`api`、`hybrid`；`environment` 可省略，P0 只有 `lab`。
- `base_url` 最長 256 字元，只能是 `http://主機[:port]`，結尾可以有一個 `/`：
  - canonical 形式：scheme 與主機轉小寫，省略 `:80`。
  - 主機是名稱（英數字與連字號，每段 1–63 字元）或四段十進位的 IPv4。IPv4 必須是 `LAB_CIDR` 內的主機位址，否則 422 `SCOPE_OUTSIDE_LAB`。
  - 其他拒絕的情形見 `DECISIONS.md` §10.2，回 422 `INVALID_TARGET`；訊息說明原因，不回顯輸入。
- 同一個 project 內 canonical origin 不可重複：409 `TARGET_ORIGIN_CONFLICT`。
- 每個 project 最多 100 個 target：409 `QUOTA_EXCEEDED`（`DECISIONS.md` §10.9）。
- 清單（`GET …/targets`）依建立時間由舊到新、分頁。

修改（`PATCH /api/v1/targets/{target_id}`，200）：`{"enabled": false}` 或 `{"name": "…"}`。至少要有一個欄位，不接受 null 與其他欄位；origin 要改就建立新的 target。停用之後，已核准的 grant 就不能再用來建立 scan（§14.5）。operator 也能重新啟用，所以停用不是權威的停止手段；權威的停止是 admin 撤銷 grant。

### 14.2 ScopeGrant

申請（`POST /api/v1/targets/{target_id}/scope-grants`，201）：

```json
{
  "allowed_origins": ["http://vampi-vuln:5000"],
  "allowed_ips": ["10.89.7.20"],
  "allowed_paths": ["/users/v1", "/books/v1/{book_title}"],
  "excluded_paths": ["/users/v1/_debug"],
  "allowed_methods": ["GET", "HEAD", "OPTIONS"],
  "budget": {"requests_per_second": 2, "max_requests": 5000, "max_duration_seconds": 1500},
  "authorization_reference": "LAB-ASSET-RECORD-001",
  "valid_from": "2026-10-19T00:00:00Z",
  "valid_until": "2026-10-26T00:00:00Z"
}
```

回應（查詢時相同）：

```json
{
  "id": "<uuid>",
  "target_id": "<uuid>",
  "project_id": "<uuid>",
  "version": 1,
  "status": "pending",
  "allowed_origins": ["http://vampi-vuln:5000"],
  "allowed_ips": ["10.89.7.20"],
  "allowed_paths": ["/users/v1", "/books/v1/{book_title}"],
  "allow_all_paths": false,
  "excluded_paths": ["/users/v1/_debug"],
  "allowed_methods": ["GET", "HEAD", "OPTIONS"],
  "budget": {"requests_per_second": 2, "max_requests": 5000, "max_duration_seconds": 1500},
  "authorization_reference": "LAB-ASSET-RECORD-001",
  "valid_from": "2026-10-19T00:00:00Z",
  "valid_until": "2026-10-26T00:00:00Z",
  "requested_by_key_id": "<uuid>",
  "created_at": "2026-10-19T08:00:00Z",
  "approved_by_key_id": null,
  "approved_at": null,
  "approval_note": null,
  "revoked_by_key_id": null,
  "revoked_at": null,
  "revocation_reason": null
}
```

| 欄位 | 規則 |
|---|---|
| `allowed_origins` | 1–4 個，規則同 §14.1 的 `base_url`；必須包含 target 的 origin。主機是 IP 的 origin，該 IP 必須列在 `allowed_ips` |
| `allowed_ips` | 1–16 個，四段十進位的 IPv4 主機位址；`LAB_ONLY` 時必須在 `LAB_CIDR` 內，而且不是網段或廣播位址 |
| `allowed_paths` | 最多 256 個：完整的 literal path，或含整段 `{name}` 佔位的 route。不可有 `%`、`\`、`?`、`#`、`;`、`*`、空白、空段落或 `.`、`..` 段落，每個最長 512 字元。清單是空的時，必須設定 `allow_all_paths: true` |
| `allow_all_paths` | 預設 false；true 時 `allowed_paths` 必須是空的 |
| `excluded_paths` | 最多 64 個，語法同上；排除優先於允許，不可與 `allowed_paths` 重複 |
| `allowed_methods` | GET、HEAD、OPTIONS、POST、PUT、PATCH、DELETE 的子集，大小寫必須一致 |
| `budget` | 三個正整數，上限 2、5,000、1,500；可省略，省略的項目用上限 |
| `authorization_reference` | 必填，1–200 字元 |
| `valid_from`、`valid_until` | 必須帶時區；`valid_from` 預設為申請時間。`valid_from < valid_until`、`valid_until` 晚於現在、期間最長 30 天 |

- 任何清單有重複（正規化之後）都拒絕。
- 每個 target 最多 10 個待核准的申請（pending 且未過期）：409 `QUOTA_EXCEEDED`，請先核准或撤銷。
- 時間換算成 UTC 會超出可表示的範圍時（例如 `9999-12-31T23:59:59-05:00`），回 422 `INVALID_REQUEST`。
- `status`、`version` 與核准、撤銷的欄位不能由 client 指定；`version` 是每個 target 各自的流水號。
- 查詢：`GET /api/v1/scope-grants/{grant_id}`，以及 `GET /api/v1/targets/{target_id}/scope-grants`（新版本在前、分頁）。`status` 是讀取當下推導出的狀態。

### 14.3 狀態與轉換

| 狀態 | 意義 |
|---|---|
| `pending` | 已申請，尚未核准 |
| `approved` | 已核准；`valid_from` 之前還不能使用 |
| `revoked` | 已撤銷；優先於 expired |
| `expired` | pending 或 approved，而且已到 `valid_until`。由時間推導，不寫入 DB |

| 目前狀態 | `POST …/approve`（`{"note": "…"}`） | `POST …/revoke`（`{"reason": "…"}`） |
|---|---|---|
| pending | 200 → approved（以目前的 `LAB_CIDR` 重新檢查，不合就 422 `SCOPE_OUTSIDE_LAB`） | 200 → revoked |
| approved | 409 `INVALID_STATE_TRANSITION` | 200 → revoked |
| revoked | 409 | 200，不改變任何東西，也不重記 audit |
| expired | 409（請重新申請新版本） | 409 |

- `note`、`reason` 1–500 字元，不可空白。
- 同時核准與撤銷時，後到的請求等先到的 commit，再以最新的狀態判斷。
- `approved_at` 是核准那個 transaction 開始的時間；`revoked_at` 是撤銷實際寫入的時間，一定不早於 `approved_at`。
- DB 以 trigger 再擋一次非法的轉換與範圍修改（`DECISIONS.md` §10.4）。

### 14.4 權限

| 操作 | platform_admin | operator（自己的 project） | viewer（自己的 project） | 其他 project |
|---|---|---|---|---|
| 建立、修改 target；申請 grant | 允許 | 允許 | 403 | 404 |
| 查詢 target 與 grant | 允許 | 允許 | 允許 | 404 |
| 核准、撤銷 grant | 允許 | 403 | 403 | 404 |

不存在的 project、target 或 grant 也回 404，回應與其他 project 的完全相同。

### 14.5 掃描 gate（給 T09 使用）

T06 還沒有建立 scan 的 API。`ScopeGrantService.require_usable()` 是「這個 grant 現在能不能用來掃描」的唯一判斷，T09 的 `POST /scans` 會在同一個 transaction 中呼叫它：

| 情況 | 回應 |
|---|---|
| target 或 grant 不存在、屬於其他 project | 404 |
| 呼叫者是 viewer | 403 `ROLE_NOT_ALLOWED` |
| grant 屬於同一個 project 的其他 target | 422 `INVALID_REQUEST` |
| target 的 origin 不在 grant 的範圍內（只可能是直接改了 DB） | 422 `INVALID_REQUEST` |
| pending、已撤銷、尚未生效 | 403 `SCOPE_NOT_APPROVED`（訊息不同） |
| 已過期 | 403 `SCOPE_EXPIRED` |
| target 已停用 | 409 `TARGET_DISABLED` |
| IP 不在目前的 `LAB_CIDR` 內 | 422 `SCOPE_OUTSIDE_LAB` |

它以 `FOR SHARE` 鎖住 target 與 grant：撤銷或停用一旦 commit，之後就不會再通過；正在建立 scan 時，撤銷會等它 commit。

### 14.6 Audit

| 事件 | `changes` |
|---|---|
| `target.create` | `name`、`kind`、`origin` |
| `target.update` | 有變動的欄位，例如 `{"enabled": {"from": true, "to": false}}` |
| `scope_grant.create` | `version`、`target_id`、`origins`、`ips`、`methods`、`allow_all_paths`、`path_count`、`excluded_path_count`、`budget`、`valid_from`、`valid_until`、`reference` |
| `scope_grant.approve` | `version`、`note` |
| `scope_grant.revoke` | `version`、`reason`、`previous_state` |

- 完整的 path 清單不寫進 audit：grant 本身不可變。
- 授權文件編號記為 `reference`：欄位名稱含 authorization 會被遮罩規則整個遮掉。

## 15. API 規格（T07 已實作）

理由見 `DECISIONS.md` §11。上傳與解析都不發出任何流量：不抓外部參照、不連 `servers` 指向的位址。以下的名稱與 hash 都是示例。

### 15.1 上傳

`POST /api/v1/targets/{target_id}/api-specs`（201），body 就是規格檔本身：

```bash
curl -s -H @admin.header -H 'Content-Type: application/yaml' \
  --data-binary @openapi3.yml http://127.0.0.1:8000/api/v1/targets/<target_id>/api-specs
```

```json
{
  "id": "<uuid>",
  "target_id": "<uuid>",
  "project_id": "<uuid>",
  "version": 1,
  "openapi_version": "3.0.1",
  "source_format": "yaml",
  "source_size_bytes": 19631,
  "source_sha256": "<64 個 hex：上傳檔的 SHA-256>",
  "document_sha256": "<64 個 hex：正規化文件的 SHA-256>",
  "server_url": "http://vampi-vuln:5000",
  "base_path": "",
  "operation_count": 14,
  "uploaded_by_key_id": "<uuid>",
  "created_at": "2026-10-24T08:00:00Z"
}
```

| 項目 | 規則 |
|---|---|
| Content-Type | `application/json` 或 `application/yaml`；charset 只能是 UTF-8。其他回 415 `UNSUPPORTED_MEDIA_TYPE` |
| 大小 | 最多 1 MiB（1,048,576 bytes），超過回 413 `SPEC_TOO_LARGE`；有 Content-Length 時不讀 body，chunked 時讀到超過就停。任何請求超過 2 MiB 由 middleware 回 413 `REQUEST_TOO_LARGE` |
| 時間 | body 必須在 10 秒內讀完，否則回 408 `REQUEST_TIMEOUT`；途中斷線回 400 `INVALID_REQUEST` |
| 編碼 | 嚴格 UTF-8，不接受 BOM；字串不可有 NUL 或孤立的 surrogate |
| 結構 | 最外層是物件；巢狀最多 64 層、最多 10 萬個節點（key、值與容器各算一個）；key 不可重複 |
| JSON | 不接受 `NaN`、`Infinity` 與溢位成無限大的數字；整數最多 4,300 位 |
| YAML | 單一文件；不接受 directive、anchor、alias、明確的 tag、複合 key、plain 的 `<<`、直接出現的 U+0085／U+2028／U+2029。key 一律是字串，值依 YAML 1.2 core schema 解讀：`yes`、`on`、日期都是字串，`0x1F` 是 31，`.inf`、`.nan` 拒絕 |
| 版本 | `openapi: 3.0.x`（必須是字串，patch 最多 12 位數）；Swagger 2.0 與 3.1 回 422 `UNSUPPORTED_SCHEMA` |
| 頂層 | 只接受 OAS 3.0 的欄位與 `x-` 擴充；`info.title`、`info.version` 必須是字串，`paths` 必須存在 |
| components 的名稱 | schemas、responses、parameters、examples、requestBodies、headers、securitySchemes、links、callbacks 的名稱必須符合 `^[a-zA-Z0-9.\-_]+$`（OAS 3.0 的規定） |
| 參照 | 任何位置的 `$ref`、`operationRef` 只接受 `#/…`、只有 ASCII 可見字元、不含 `%` 的 JSON Pointer，而且必須指得到；不可形成只由參照組成的循環，參照鏈最多 32 層。`discriminator.mapping` 的值只接受 `#/components/schemas/<名稱>`（只寫名稱也不接受）。security scheme、response 與 link 的 `$ref` 只能指向 `#/components/<同一個區段>/<名稱>`。`externalValue` 與 `$id`、`$schema`、`$anchor`、`$dynamicRef` 等一律拒絕 |
| servers | 改綁成 target 的 origin 加 base path（取 URL 的 path、去掉結尾的 `/`）。URL 必須是 `http(s)://主機/…` 或以 `/` 開頭，而且解析得了；不可有變數、query、fragment；所有 server 的 base path 必須相同。原本的 host 不保存，也不出現在回應與錯誤訊息中 |
| path | base path 加上規格的 path 就是完整 path，語法同 grant 的 path（§14.2）：佔位必須占滿一整段；只差在佔位名稱的兩個 route 拒絕；最長 512 字元 |
| operation | 最多 1,000 個；`operationId` 可省略，有的話必須唯一、1–200 字元、不含控制字元 |
| 拒絕的功能 | `callbacks`、`webhooks`、path item 的 `$ref`、path 與 operation 層級的 `servers`、Link 的 `server`、`oauth2` 與 `openIdConnect` 類型的 security scheme |

錯誤的先後：

1. 沒有 key 或格式不符：401（middleware，不讀 body）。
2. 請求超過 2 MiB：413 `REQUEST_TOO_LARGE`（middleware）。
3. key 無效（查 DB）：401。
4. Content-Type：415。
5. 讀取 body：超過 1 MiB 回 413 `SPEC_TOO_LARGE`，超過 10 秒回 408 `REQUEST_TIMEOUT`，途中斷線回 400。
6. target 不存在或屬於其他 project：404；viewer：403。
7. 解析與驗證：422（或正規化後太大的 413）。
8. 每個 target 最多 20 個版本：409 `QUOTA_EXCEEDED`。

解析一定在權限檢查之後，不替沒有權限的呼叫者解析內容。

- 規格建立後不可修改、不可刪除；要改就上傳新版本，`version` 是每個 target 各自的流水號。
- 正規化文件是 key 排序的 canonical JSON，存在 DB；同一份內容以 JSON 或 YAML 上傳，`document_sha256` 相同。目前沒有下載文件的端點（M3 的工具直接從 DB 取）。
- 停用的 target 仍可上傳（上傳不會送出任何流量）。

### 15.2 查詢與 inventory

- `GET /api/v1/targets/{target_id}/api-specs`：新版本在前、分頁。
- `GET /api/v1/api-specs/{spec_id}`：回應同 §15.1。
- `GET /api/v1/api-specs/{spec_id}/operations?scope_grant_id=<uuid>`：依 path（字元碼的順序，所以 `_debug` 在 `{username}` 之前）、method（OAS 的順序：get、put、post、delete…）排序、分頁。

```json
[
  {"method": "GET", "path": "/users/v1/_debug", "operation_id": "api_views.users.debug", "eligible": false, "reason": "PATH_EXCLUDED"},
  {"method": "GET", "path": "/users/v1/{username}", "operation_id": "api_views.users.get_by_username", "eligible": true, "reason": null},
  {"method": "DELETE", "path": "/users/v1/{username}", "operation_id": "api_views.users.delete_user", "eligible": false, "reason": "METHOD_NOT_AUTHORIZED"}
]
```

- 不帶 `scope_grant_id` 時，`eligible` 與 `reason` 都是 null。
- 帶的時候，grant 必須屬於同一個 target（否則 422 `INVALID_REQUEST`）；讀不到的 grant 與不存在的一樣回 404。grant 的任何狀態都可以預覽：`eligible` 只表示 method 與 path 在範圍內，能不能拿來掃描由掃描 gate 判斷（§14.5）。
- 被排除或不在範圍內的 operation 照樣列出（§5）。

判斷的規則與先後：

| 順序 | reason | 條件 |
|---|---|---|
| 1 | `PATH_EXCLUDED` | 被任一 `excluded_paths` 涵蓋：不分大小寫、忽略結尾的斜線 |
| 2 | `METHOD_NOT_AUTHORIZED` | method 不在 `allowed_methods`（TRACE 一定不在） |
| 3 | `PATH_NOT_AUTHORIZED` | 沒有 `allow_all_paths`，也沒有被任一 `allowed_paths` 涵蓋：大小寫與結尾的斜線都要一致 |

「涵蓋」：段數相同；grant 的佔位涵蓋任何一段，literal 只涵蓋相同的 literal，不涵蓋規格中的佔位；不從前綴推論（排除 `/api/admin` 不包含 `/api/admin/{id}`）。

### 15.3 權限

| 操作 | platform_admin | operator（自己的 project） | viewer（自己的 project） | 其他 project |
|---|---|---|---|---|
| 上傳 | 允許 | 允許 | 403 | 404 |
| 查詢規格與 inventory | 允許 | 允許 | 允許 | 404 |

### 15.4 Audit

| 事件 | `changes` |
|---|---|
| `api_spec.create` | `version`、`target_id`、`format`、`size_bytes`、`source_sha256`、`document_sha256`、`operation_count`、`base_path` |

文件本身不寫進 audit：規格不可變，以 hash 對應。被拒絕的上傳不留紀錄。
