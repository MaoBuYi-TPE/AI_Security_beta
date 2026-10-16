# 後端架構與資料契約

狀態：待實作設計。選型依據見 `SOURCES.md`，功能範圍見 `PROJECT_PLAN.md`。

## 1. 邏輯架構

```text
HTTP client / 內建 API 文件 / 未來 CI
                 |
                 v
       FastAPI 控制平面
     權限、Scope、認證設定、查詢
                 |
         PostgreSQL transaction
         scans + outbox_events
                 |
          outbox dispatcher
                 v
             Redis queue
                 |
                 v
       Celery worker / 可信 Runner
       (隔離 VM；同一 codebase)
                 |
       固定規格容器啟動 / 回收
                 v
         ZAP -> Nuclei -> [Schemathesis]
                 |
        強制 egress guard + firewall
                 |
          唯一已核准的隔離靶場

受限工作目錄 -> Parser -> Normalizer -> Observation
                        -> 保守合併 -> Finding
                        -> 比較 / JSON、Markdown 報告
```

這是邏輯分工，不代表每一格都是微服務。API、worker、dispatcher/reconciler 可共用 Python 套件與 DB 模型；第一版只有一個可信 Runner。Parser 不應與 Docker 高權限 launcher 混在可任意執行使用者資料的路徑上。

## 2. 部署與信任邊界

控制平面 VM 放 API、PostgreSQL、Redis；資料庫與 broker 不公開。Runner VM 的管理側可以連必要 DB/broker，掃描容器的網路則不能連管理側。Runner 的 Docker 控制權是高權限，若被攻陷可能影響該 VM；獨立、可重建的 VM 是風險隔離措施，不宣稱容器是絕對安全沙箱。[S12]

掃描器只接 `scan_net`，無 Docker socket、無 host network、無 host filesystem。網路只允許它連 egress guard。guard 的上游僅可連本次核准 origin/IP/port；不允許任意 Internet、管理網、宿主 gateway、metadata、校內非靶場設備。

只設 Docker Compose `internal` 並不能取代完整路由、防火牆及宿主介面檢查，需從掃描容器視角做實測。每項規則既檢查應用層，又從接收端確認實際是否有封包。

## 3. Egress guard

可用 mitmproxy 的 addon/event 機制實作本專題 scope、budget 與 telemetry，不自行重寫 proxy/TLS。[S18] 既有工具只是底層，**不會自動提供本專題的授權模型或完備 SSRF 防護**。

### 3.1 每次實際出站必須處理

驗證 HTTP scheme、authority、port、標準化 path、HTTP method、目前有效 scope；拒絕模糊 host/URL 表示。校驗 DNS 回應與允許 IP，將連線綁定允許目的位址，避免驗證後重新解析到其他地址。CONNECT、SNI、Host/HTTP authority 與實際目的位址必須一致。每次 redirect 的下一個請求重新檢查，不能只核對起始 URL。[S13]

P0 不跟隨外部 redirect，不抓外部 $ref，不處理 schema callback。靶場可使用私有位址，但只能逐項允許，不能用「內網都安全」放行。禁用無法檢查/約束的 raw protocol 行為與協定升級。

### 3.2 HTTPS 與限制

要強制 path/method，proxy 必須能檢查解密後的 HTTP；僅放行 CONNECT 到某個主機不能達成此目的。實驗 proxy 的 CA 公開憑證只裝到掃描容器，CA 私鑰不給掃描器。Proxy 對上游仍要驗證憑證，自簽靶場憑證需明確 trust store，不用全域 skip verify。

Mitmproxy 預設可能為取得上游憑證而先建立上游連線。[S19] 在啟動前需確認 lazy connection/關閉不必要 upstream sniffing 等設定，並在任何上游 socket 建立前通過 scope/IP 檢查；不得僅等 request hook 再檢查。

若尚未完成 HTTPS guard/CA 測試，先限定隔離 HTTP 靶場，HTTPS profile 回不支援。禁止透過隱藏關閉驗證來假裝相容。

TLS 代理會影響憑證類檢測。本版不做 TLS/SSL 評等、raw HTTP smuggling、HTTP/2 協定弱點或網路層漏洞；報告需揭露代理對流量的影響。

### 3.3 速率與停止

初始預算為每 target 合計 2 requests/s，burst=1、最多 5,000 次、發流量牆鐘 25 分鐘。是可調規劃值，不是保證無副作用。Budget 從第一次 preflight 發流量開始，包含所有引擎、爬蟲、驗證、認證刷新（未來）、重試。工具本身也設保守上限，但最終由 guard 的共享 budget 限制。

單 Runner 下各引擎串行，預算預先分配而總額不變；不足時明確標記 coverage limited。達上限立即禁止新出站，停止工具，保存已有資料。收集/正規化另設短時間與大小限制，不能無限延長掃描。

取消時 guard 先停止新出站，再通知引擎、stop/kill 對應容器。無法撤銷已送到靶場的操作，靶場資料重置由受控 fixture 程序另外處理。

## 4. 模組與依賴方向

Route 只做輸入/身份驗證與 service 呼叫；Service 負責業務規則；Repository 負責資料。Domain 不依賴 FastAPI/Celery/Docker。Adapter 產生固定 ExecutionPlan 並解析受限 artifact，不能接收任意 command。Runner 負責執行與監督，但不自行決定使用者是否有授權。

建議介面（概念契約，不是已存在程式）：

```python
class ScannerAdapter(Protocol):
    def capabilities(self) -> ScannerCapabilities: ...
    def validate(self, plan: ScanPlan) -> ValidationResult: ...
    def build_execution(self, plan: ScanPlan) -> ExecutionPlan: ...
    def parse(self, bundle: ArtifactBundle) -> ParsedRun: ...

class Runner(Protocol):
    def start(self, execution: ExecutionPlan) -> RunHandle: ...
    def inspect(self, handle: RunHandle) -> RuntimeState: ...
    def cancel(self, handle: RunHandle) -> CancelResult: ...
    def collect(self, handle: RunHandle) -> ArtifactBundle: ...
```

ExecutionPlan 僅包含受控映像 reference、固定 entrypoint/args、授權 input artifact、資源/時間限制、allowlist template IDs、profile hash、run ID。不能含使用者指定 host path、shell、任意映像與網路名稱。

## 5. 工具整合契約

| 項目 | ZAP | Nuclei | Schemathesis（P1） |
|---|---|---|---|
| 主要入口 | Automation Framework、server-generated YAML | 固定 CLI + 審查模板目錄 | 固定 CLI/config + 已驗證 OpenAPI |
| 輸入 | scope context、Web seed 或 API 規格、auth | 核准目標/已核准端點、template allowlist、auth | 受限 spec、operation allowlist、auth、seed |
| 整合輸出 | 固定 JSON report；必要訊息/統計 | JSONL + 執行 manifest | 版本對應 JSON/NDJSON；必要 JUnit/HAR |
| 來源鍵 | plugin/rule ID、alert instance | template ID、matcher、matched-at | check、operation、case/event ID |
| 不能假設 | alert 多表示執行成功；API/Web profile 等價 | 官方模板都無副作用；零 JSONL 等於安全 | check disabled 等於不發請求；500 都是漏洞 |

ZAP 的 packaged scripts 可用於 M0 取得樣本，正式 Adapter 用同一套可版本化配置；不要同時維護數條不相容的掃描路徑。需記錄 engine/add-on 版本、JSON schema 和 exit handling。[S02–S05]

Nuclei templates 採人工審查、固定 commit + allowlist。禁用 code/headless、外部 OAST、cloud upload、任意其他協定、未知 raw template；簽章只是來源證據。[S06]

Schemathesis 依鎖定版本確認報告支援，不捏造通用 `--json` 參數。若用 JUnit，不能只依 free text 猜 parameter/位置；需關聯 NDJSON/HAR，或將缺乏定位資訊的結果保留低精度。[S07] 要禁止某 HTTP method，需限制 generation 和出站，而不是只關閉 corresponding check。[S08]

每個 adapter 都需 capability probe，檢查實際 executable、版本、設定檔、輸出可寫性及 proxy 行為。工具不支援所需能力時，回能力錯誤，而不是偷偷降級。

## 6. 資料模型

| 資料表 | 核心欄位與責任 |
|---|---|
| projects | id、name、created_at；初版可只有一個專案，結構仍保留隔離 |
| api_keys | id、key_hash、prefix、role、project_id、expires_at、revoked_at；admin 可無 project |
| targets | id、project_id、name、kind、canonical_origin、environment、enabled |
| scope_grants | target_id、version、allowed_origins/ips/ports/paths/methods、max_budget、approval、有效期 |
| api_specs | id、target_id、version、content_hash、受控 storage key、operation inventory |
| auth_profiles | id、target_id、version、type、role_label、encrypted_secret、preflight_definition |
| scans | id、project_id、target_id、status、snapshot、idempotency_key/hash、cancel_requested_at、manifest、時間 |
| scanner_runs | id、scan_id、engine、engine_version、status、attempt、lease、container_label、error、coverage |
| findings | id、target_id、fingerprint、kind、normalized_severity、triage/lifecycle、first/last_seen |
| observations | id、finding_id（可先 null）、scan_id、scanner_run_id、source_rule、位置、evidence_ref、raw_severity |
| artifacts | id、run_id、type、hash、storage_key、size、classification、encrypted、retention |
| scan_events | id、scan_id、sequence、event_type、sanitized_payload、時間；可供輪詢 |
| outbox_events | id、scan_id、payload、published_at、attempts；避免 DB 已寫入但工作未派送 |
| audit_events | actor_key_id、project、action、object_ref、redacted_changes、時間 |

### 6.1 約束與索引

所有子資源需可追溯 project；lookup 先限制 project 再取物件，不能只查 UUID。`scans` 對 `(project_id, idempotency_key)` 設唯一約束；相同 key 不同 request hash 回 409。`scanner_runs` 對 scan、engine、attempt 唯一；同 target 初版只允許一個活躍 scan，避免重複改變靶場。

`observations` 對 run + source_event_id 設唯一；不存在 source ID 時用該輸出記錄位置/穩定 hash 產生，防止 Parser 重跑重複寫入。正規化前後都保留 schema/mapping version。`findings` 對 target + fingerprint unique，低可信映射不得強行共用 fingerprint。

JSONB 可用於固定版本 snapshot/來源差異欄位，但不能把所有資料只塞一個 JSON 欄位而失去授權與查詢約束。

## 7. ScanPlan 與執行快照

建立 scan 時凍結以下欄位：target/grant/spec/auth profile IDs 及版本、origin/path/method、engine 集合、template commit/IDs、映像 digest、ZAP add-on、profile/budget、parser/mapping version、程式 commit、靶場 image/data snapshot。secret 本身不存入普通 snapshot。

執行前再次檢查 grant 尚未撤銷/過期、target 未停用、實際網路仍一致。若授權撤回，停止仍在執行的 scan。不能因快照存在就繼續使用失效授權。

## 8. 任務狀態機

```text
queued -> preparing -> running -> collecting -> normalizing
                                            -> completed
                                            -> partially_completed

活躍狀態 -> cancelling -> cancelled
活躍狀態 -> failed / timed_out / interrupted
```

| Scan 狀態 | 定義 |
|---|---|
| queued | 已有持久化 scan 與 outbox，等待執行 |
| preparing | claim、scope/auth/network/capability preflight 中 |
| running | 至少一引擎已開始，可能依序執行多個 |
| collecting | 收集已產出的受限 artifacts |
| normalizing | 驗證輸出、匯入 observation、建立/關聯 finding |
| completed | 所有選定適用引擎執行及解析完成；可為零告警 |
| partially_completed | 至少一引擎有可用結果，其他引擎/覆蓋未完成 |
| failed | 無可用完整結果，已確認工具/設定/解析失敗 |
| timed_out | 全 scan 的時間/請求 budget 用盡；保留部分證據但不宣稱完整 |
| cancelling / cancelled | 停止處理中 / 已確認不再執行與發出新請求 |
| interrupted | Runner 丟失等原因，無法證明已正常完成；需 reconciler 處理 |

每個 scanner_run 另有 queued/preparing/running/collecting/normalizing/succeeded/failed/timed_out/cancelling/cancelled/interrupted，供聚合。即使 scan=completed，也不表示所有授權 API operation 都確實成功測到；coverage 是另一個維度，必須呈現分母和未測理由。

不支援的引擎、缺少必需 spec 或 profile 不相容，在建任務時 422 拒絕，不事後默默跳過。單工具失敗不應刪除另一工具的成功證據。真實檢出安全問題所造成的非零退出，依工具契約分類，不直接當 crash。

## 9. 可靠派送與取消

DB transaction 同時寫 scans/outbox。Dispatcher 將 scan_id（不含 secret/任意 command）發布至 broker，發送成功再標 outbox；中間故障可能重送，所以 worker 必須 claim/lease，先查既有 container label 與 run 狀態，不重複啟動。

心跳規劃每 5 秒一次、lease 30 秒；數值由測試調整。lease 過期不代表舊容器已停止：reconciler 需核對、阻斷舊 run 出站並確認容器終止。不能僅憑 lease 過期就開第二個掃描器。

在尚未發出任何掃描請求前，可重試暫時性啟動/派送問題。開始發流量後若崩潰，預設標 interrupted，由使用者以新 scan 重跑；僅 Parser 可對不可變 artifact 安全重試。這不提供目標外部狀態的 transaction rollback。[S11]

取消驗收目標：控制 API 回應後 10 秒內停止新出站，最長 30 秒回收工具容器；實測有偏差需記錄。API 回 202 時狀態可以是 cancelling，只有確認清理後才變 cancelled。

## 10. 統一發現格式與去重

Observation 包含來源 engine/rule、source severity/confidence、CWE/CVE（可空）、request method、canonical origin、route/path、parameter location/name、auth role、資源辨別資訊、證據索引與時間。HTTP body、敏感 query 與 Token 不直接當索引。

Finding 的 proposed fingerprint：

```text
SHA256(canonical_json({
  target_id,
  kind,
  reviewed_semantic_rule_group,
  http_method,
  verified_route_or_literal_path,
  parameter_location,
  parameter_name,
  stable_auth_role,
  resource_discriminator_when_required
}))
```

`reviewed_semantic_rule_group` 是人工審查的跨工具規則對應，不是只用 CWE 代替。沒有可信映射時加入 scanner/rule ID，保持獨立。API route 只有存在可信 OpenAPI/route map 時才把具體 ID 對應 `{id}`；授權/資源特有問題仍要保留 resource discriminator，防止合併不同物件。

Query 不是全部刪除。像 action/type 等業務語意欄位需依規則保留；secret 值要遮罩，可對必要識別欄位用專案穩定 HMAC。不要過度 decoding path 導致把不同路徑當成相同。

去重不刪 Observation。跨工具只代表多個來源，不自動升高嚴重度或標為 confirmed。severity 依版本化 mapping 處理，衝突/未知保留原值與理由；不可用空 CVSS 補假分數。

## 11. 人工 triage 與複掃

`triage_state`：unreviewed / confirmed / false_positive / accepted_risk。

`lifecycle_state`：open / resolved / reopened。resolved 需人工或明確驗證程序加註原因與證據；不能只因新 scan 沒有告警就自動關閉。

Compare 結果包含 `new / persistent / not_observed / inconclusive / not_comparable`。先比較 target、scope、auth role、spec、profile、engine/template、靶場/版本，再核對執行完成度、認證與操作/規則實際覆蓋。

工具版本或策略變動會影響可比性；顯示差異及信心限制。沒有足夠 rule/operation telemetry 時，未再次命中標 inconclusive，不假設工具有檢查該處。即使可比且 not_observed，仍非自動安全證明。

## 12. Artifact 與報告

每個工作使用不可預測 ID 的固定工作目錄，使用 server-generated storage key；使用者不能指定本機路徑。檔案大小上限、路徑穿越、symlink、壓縮展開限制皆測試；P0 不接受使用者壓縮包。

原始輸出寫入受限暫存，計算 hash，經加密存為受限 evidence；普通查詢使用遮罩後摘要。報告顯示工具/版本、範圍、auth 狀態、operation coverage、引擎錯誤、security/contract/robustness 分類、證據、人工 triage 和未測項目。

不將未經編碼的目標回應放入可執行 HTML。初版輸出 JSON/Markdown 並以 attachment/content-type 正確傳送；亦需處理 Markdown 中的原始 HTML/連結，不自動載入遠端資源。生成報告不需要自訂前端。
