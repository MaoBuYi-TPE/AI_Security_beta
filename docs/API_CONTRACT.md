# REST API 設計契約

本文件是預計實作的 API，不是已上線端點或已驗證 OpenAPI。M1 起由 Pydantic/router 產生實際 OpenAPI，並透過 contract test 檢查與此設計一致。

## 1. 共通約定

Prefix：`/api/v1`。平台使用 `Authorization: Bearer <platform_api_key>`。這個 key 只授權使用檢測平台，**不可轉送到被測網站**；被測網站的 secret 由 auth_profile_id 關聯。

角色：platform_admin 為全域管理員；operator 與 viewer 綁定一個 project。無公開註冊、密碼登入、OAuth 或 session cookie。起始管理 key 由受控本機 CLI 建立並只展示一次，後續可撤銷/輪替；不在這個規劃包提供真實 key。

UUID 為物件 ID，時間為 UTC ISO 8601。跨專案查詢一律加 project 授權過濾。不存在或無權存取的物件通常回 404，避免洩漏存在性；角色不足的已知操作回 403。無效 key 回 401。

清單採 cursor pagination，default limit=25、max=100。日誌包含 request_id，但不包含憑證、完整 body 或 raw command。

## 2. 端點總表

| 方法 | 路徑 | 權限 | 回應與要點 |
|---|---|---|---|
| GET | /health/live | 可僅本機公開 | 200；僅程序存活，不含敏感依賴資訊 |
| GET | /health/ready | 管理網 | 200/503；DB/broker/必要配置可用 |
| POST | /api/v1/projects | platform_admin | 201 建立專案 |
| GET | /api/v1/projects | 已授權 key | 200，只列可存取專案 |
| POST | /api/v1/projects/{project_id}/keys | platform_admin | 201，建立 operator/viewer key，僅回傳一次完整值 |
| DELETE | /api/v1/keys/{key_id} | platform_admin | 204，撤銷而非刪除 audit |
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
| POST | /api/v1/scans | operator/admin | 202 + scan_id；必須 Idempotency-Key |
| GET | /api/v1/scans | 同專案 | 200；target/status/time filter |
| GET | /api/v1/scans/{scan_id} | 同專案 | 200；引擎狀態、進度、coverage、停止理由 |
| GET | /api/v1/scans/{scan_id}/events | 同專案 | 200；按 sequence 輪詢，不先做 WebSocket |
| POST | /api/v1/scans/{scan_id}/cancel | operator/admin | 202/200；取消中/已終止，不代表已撤銷外部操作 |
| GET | /api/v1/scans/{scan_id}/findings | 同專案 | 200；kind/severity/tool/triage filter |
| GET | /api/v1/findings/{finding_id} | 同專案 | 200；來源 observations、遮罩證據與歷史 |
| PATCH | /api/v1/findings/{finding_id}/triage | operator/admin | 200；需 reason；敏感變更留 audit |
| POST | /api/v1/scan-comparisons | 同專案 | 200；只比較有權限且相同 target 的 scans |
| POST | /api/v1/scans/{scan_id}/reports | operator/admin | 201；建立 JSON/Markdown 遮罩報告 artifact |
| GET | /api/v1/artifacts/{artifact_id}/download | 同專案 | 200；P0 僅遮罩報告/證據；不提供 raw secret artifact |
| GET | /api/v1/projects/{project_id}/audit-events | platform_admin | 200；遮罩且分頁 |

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
{
  "items": [
    {"operation_id": "getItem", "method": "GET", "path": "/api/items/{id}", "eligible": true},
    {"operation_id": "deleteItem", "method": "DELETE", "path": "/api/items/{id}", "eligible": false, "reason": "METHOD_NOT_AUTHORIZED"}
  ],
  "next_cursor": null
}
```

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

以上是資料格式示意，數字不是實驗結果。`observed_operations` 代表有實際 request 流量對應到該 operation，**不代表所有漏洞種類已測試**。`authenticated_operations` 需該身分已驗證與適用證據，不靠單一 status code 推論。

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

`POST /scans/{id}/reports` request：`{"format":"markdown"}` 或 json。已有可用結果即可產生報告，但必須標記部分/未完成。報告有版本、hash、生成時間與掃描時間；生成報告的時間不是漏洞發現時間。

Artifact download 必須再做 project/object 授權，不接受 `path=`。P0 不提供 raw artifact 公開下載端點。下載使用安全 Content-Disposition 檔名、正確 media type，不執行檔案內指令、不自動載入外部資源。

## 12. 穩定錯誤格式

```json
{
  "error": {
    "code": "SCOPE_NOT_APPROVED",
    "message": "此目標尚無有效的掃描範圍授權。",
    "request_id": "<server-generated-id>"
  }
}
```

| HTTP | 常見 code |
|---|---|
| 401 | UNAUTHENTICATED、API_KEY_EXPIRED |
| 403 | ROLE_NOT_ALLOWED、SCOPE_NOT_APPROVED、SCOPE_EXPIRED |
| 404 | RESOURCE_NOT_FOUND |
| 409 | IDEMPOTENCY_CONFLICT、TARGET_BUSY、INVALID_STATE_TRANSITION |
| 413 | SPEC_TOO_LARGE、ARTIFACT_TOO_LARGE |
| 422 | INVALID_TARGET、UNSUPPORTED_SCHEMA、EXTERNAL_REF_FORBIDDEN、ENGINE_UNSUPPORTED、PROFILE_INCOMPATIBLE |
| 429 | API_RATE_LIMITED |
| 503 | RUNNER_UNAVAILABLE、DEPENDENCY_UNAVAILABLE |

執行時錯誤如 AUTH_FAILED、AUTH_EXPIRED、ENGINE_TIMEOUT、OUTPUT_INVALID、POLICY_BLOCKED、BUDGET_EXHAUSTED 記於 scan/run，不全部變成 API 的 500。未知例外回通用訊息與 request_id，不洩漏 stack trace/Token。
