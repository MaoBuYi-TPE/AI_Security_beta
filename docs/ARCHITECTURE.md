# 後端架構與資料契約

狀態：待實作設計。選型依據見 `SOURCES.md`，功能範圍見 `PROJECT_PLAN.md`，取捨理由見 `DECISIONS.md`。

## 1. 邏輯架構

```text
HTTP client / 內建 API 文件（僅開發環境）/ 未來 CI
                 |
                 v
        api（FastAPI 控制平面）
     權限、Scope、認證設定、查詢
                 |
   PostgreSQL（唯一事實來源 + 工作佇列）
   scans 與 scanner_runs 在同一 transaction 建立
          |                          |
   runner 認領 queued run       worker 認領 collected run / pending report
  （SKIP LOCKED + lease）       （解析、正規化、去重、報告）
          |                          ^
   docker-socket-proxy               | 唯讀讀取 runs volume
          |                          |
   單次掃描容器：ZAP -> Nuclei -> [Schemathesis]
          |
   egress guard（scope、共享預算、telemetry）
          |
   已核准的隔離靶場（lab_net）
```

這是邏輯上的分工，不代表每一格都是微服務：

- api、worker、runner 共用同一個 Python 套件與 DB 模型，但以不同程序、不同權限執行。
- egress guard 是同一儲存庫中的 mitmproxy addon。
- 第一版只有一個 runner。
- Parser 只在 worker 中執行，不和有 Docker 權限的 runner 混在同一條路徑上。

## 2. 部署與信任邊界

開發與展示期間，所有元件都在同一台 Mac（OrbStack）上，靠 Docker networks 與權限分離：

| 網路 | 成員 | 說明 |
|---|---|---|
| control_net（internal） | api、worker、runner、PostgreSQL | api 只發布在 127.0.0.1:8000；PostgreSQL 不對外 |
| docker_net（internal） | runner、docker-socket-proxy | 只有 runner 能呼叫 Docker API |
| scan_net（internal） | 單次掃描容器、egress guard | 掃描器唯一能連到的對象是 guard |
| lab_net（internal） | egress guard、靶機、canary | 靶機與 canary 不能連到其他網路 |

**T04 的開發階段**：api 仍在宿主以 `make dev` 執行，PostgreSQL 由 `compose.yaml` 啟動，只綁 127.0.0.1（開發 55432、整合測試 55433），不接 lab_net 或 scan_net。應用程式以非 superuser 的資料庫擁有者角色連線（`DECISIONS.md` §7）。M2 把 api/worker/runner 容器化之後，PostgreSQL 改成只接 control_net。

### 掃描容器

- 只接 scan_net；沒有 Docker socket、沒有 host network、不掛載任何 host 路徑。
- 映像固定 digest，以非 root 執行，設定 `cap_drop: ALL` 與 `no-new-privileges`。
- 唯讀 rootfs（必要的 tmpfs 例外），並限制記憶體、CPU、pids 與執行時間。
- 只掛載該 run 的工作目錄：runs volume 的 subpath，`in/` 唯讀、`out/` 可寫。[S29]

### runner

- 唯一有 Docker API 權限的程序，而且只能經 docker-socket-proxy 存取，只開放容器相關的 API 區段（不開 exec、volumes、networks、build 等）。[S27]
- socket-proxy 只依 API 區段與 HTTP method 過濾，不檢查 request body，所以擋不住 container create 裡的 bind mount。這部分由 runner 的 ExecutionPlan 驗證負責，而 runner 本身不解析任何不可信資料。

### worker

- 負責解析不可信的工具輸出，但沒有 Docker 權限，對 runs volume 只有唯讀權限。

### egress guard

- 在 scan_net 與 lab_net 之間轉送流量，不接 control_net。
- policy 與 telemetry 都透過 volume 交換（§3.1），不經由網路連線。

### 殘餘風險

runner 一旦被攻陷，就能透過 Docker API 影響整台開發機的容器環境。[S12] 目前的緩解措施是 socket-proxy、ExecutionPlan 驗證、只掃 lab。若要掃描 lab 以外的授權目標，runner 與掃描容器必須移到獨立、可重建的 VM。我們不宣稱容器是絕對安全的沙箱。

### 實測要求

只設定 Docker Compose 的 `internal` 並不能取代完整檢查，必須從掃描容器的角度實測：從 scan_net 連 DB、socket-proxy、宿主 gateway、canary，都必須失敗。每一條規則都要同時：

- 在應用層檢查。
- 從接收端確認實際有沒有收到封包。

Docker 文件指出 `internal: true` 仍會配 gateway 位址、容器可連宿主在該位址上的服務[S32]，因此 lab_net/scan_net 另加 `gateway_mode_ipv4: isolated`（不配 gateway）。T03 在 OrbStack 2.2.1 + Engine 29.4.0 上以 isolated + internal 實測：scan_net 容器連外部 IP 為 unreachable、連 `host.docker.internal` 解析不到，被 guard 擋下的請求也以 canary 證明未送達（見 `TOOLS.md` §3；未另做 internal-only 對照組）。M2 仍須以 egress guard 補齊 DNS/IP 綁定與 redirect 重檢，不以網路設定取代應用層檢查，且部署環境需重測。

## 3. Egress guard

guard 以 mitmproxy 的 addon/event 機制實作本專題的 scope、budget 與 telemetry，不自行重寫 proxy 或 TLS。[S18] 既有工具只是底層，**不會自動提供本專題的授權模型或完備的 SSRF 防護**。

### 3.1 辨識 run 與交換 policy

- **辨識 run**：
  - runner 為每次 run 產生專屬的 proxy 帳密，掃描工具以 `http://<run_id>:<token>@guard:8080` 使用 proxy。
  - guard 驗證 `Proxy-Authorization` 後就移除這個 header，不轉送到上游。
  - 無法辨識是哪個 run 的請求，一律拒絕。（實際的 header 處理方式在 M2 實測。）
- **寫入 policy**：runner 在啟動容器前，以原子寫入（寫暫存檔後 rename）把該 run 的 policy 放進 policy volume，內容包括：
  - scope 快照
  - 允許的 IP
  - path/method 規則
  - 預算
  - 狀態
- **讀取 policy**：guard 以唯讀方式掛載 policy volume，每個請求都檢查檔案是否有更新。
- **telemetry**：guard 把每個請求的決策與統計，以 JSONL 寫進 telemetry volume；worker 與 runner 以唯讀方式讀取。

### 3.2 每次實際出站必須處理

每個請求都要驗證：

- HTTP scheme、authority、port
- 標準化後的 path 與 HTTP method
- 目前有效的 scope
- 模糊的 host/URL 表示一律拒絕

連線目的位址的規則：

- 校驗 DNS 回應是否在允許的 IP 內，並把連線綁定到允許的目的位址，避免驗證後重新解析到其他地址。
- CONNECT、SNI、Host/HTTP authority 與實際目的位址必須一致。
- 每次 redirect 的下一個請求都要重新檢查，不能只核對起始 URL。[S13]

P0 的限制：

- 不跟隨外部 redirect、不抓外部 $ref、不處理 schema callback。
- 靶場可以用私有位址，但只能逐項允許，不能用「內網都安全」整片放行。
- 禁用無法檢查/約束的 raw protocol 行為與協定升級。

### 3.3 HTTPS 與限制

**P0 只支援 HTTP 靶場。**

- 要強制 path/method，proxy 必須能檢查解密後的 HTTP；只放行 CONNECT 到某個主機達不到這個目的。
- 實驗用 proxy 的 CA 公開憑證只裝到掃描容器，CA 私鑰不給掃描器。
- proxy 對上游仍要驗證憑證；自簽的靶場憑證需要明確設定 trust store，不用全域 skip verify。
- mitmproxy 預設可能為了取得上游憑證，先建立上游連線。[S19] 啟動前要確認 lazy connection、關閉不必要的 upstream sniffing 等設定，並在建立任何上游 socket 之前通過 scope/IP 檢查；不能只等到 request hook 才檢查。
- HTTPS guard/CA 測試還沒完成時，HTTPS profile 一律回「不支援」。禁止用隱藏關閉驗證的方式假裝相容。

TLS 代理會影響憑證類的檢測。本版不做以下檢測，並在報告中揭露代理對流量的影響：

- TLS/SSL 評等
- raw HTTP smuggling
- HTTP/2 協定弱點
- 網路層漏洞

### 3.4 速率與停止

**預算**：

- 起始預算為每個 target 合計 2 requests/s、burst=1、最多 5,000 次、發流量的牆鐘時間 25 分鐘。這是 M0–M2 的保守起始值，不保證沒有副作用。
- M3 依量測調整 lab profile，並記錄 profile hash。
- 預算從第一次 preflight 發流量開始計算，包含所有引擎、爬蟲、驗證、認證刷新（未來）與重試。
- 工具本身也設保守上限，但最終由 guard 的共享預算限制。

**分配與用盡**：

- 單一 runner 下各引擎依序執行；預算預先分配給各引擎，總額不變。不夠用時明確標記 coverage limited。
- 預算用盡時，立即禁止新的出站請求、停止工具、保存已有資料。
- 收集與正規化另設短時間與大小上限，不能無限延長掃描。

**取消**：

1. runner 先把 policy 狀態改為 blocked，guard 立即拒絕該 run 的所有請求。
2. 再通知引擎，stop/kill 對應的容器。

已經送到靶場的操作無法撤銷；靶場資料的重置由受控的 fixture 程序另外處理。

### 3.5 Telemetry 的用途

- **實際請求數與耗時**：實驗的成本指標，以 guard 的計數為準，不只看 CLI 自報的統計。
- **API operation coverage**：把請求的 method + path 對應到 OpenAPI operation。
- **安全測試證據**：被拒絕的請求與原因，搭配 canary 的收包紀錄。

## 4. 模組與依賴方向

程式依功能分模組（`src/secscan/<feature>/`），每個模組都包含 router、service、schemas、models、repository。各層責任：

| 層/模組 | 責任與限制 |
|---|---|
| Route | 只做輸入驗證、身分驗證與呼叫 service |
| Service | 業務規則 |
| Repository | 存取資料，回傳 frozen domain model |
| Domain 規則（狀態機、scope 比對、fingerprint） | 不依賴 FastAPI、DB session、Docker，以 import-linter 強制 |
| `scanners/` | 只產生 ExecutionPlan 與解析輸出，都是純函式 |
| `runner/` | 唯一 import Docker SDK 的模組；負責執行與監督，但不自行判斷使用者是否有授權 |

T04 起的實作慣例（理由見 `DECISIONS.md` §8、§9）：

- **domain 規則放在固定位置**：`<feature>/domain.py`，或拆成 `<feature>/domain/` 套件。import-linter 只檢查這兩種位置，以及共用的 `security/`。
- **模組之間依呼叫關係分層**：`main | cli → migrations → health | specs | auth_profiles → grants → targets → projects → api_keys → audit → security → core`，上層可以 import 下層（T06–T08 的更新見 `DECISIONS.md` §10.7、§11.7、§12.7）。`security/` 放 API key 的產生與雜湊、遮罩，以及目標 secret 的加密（MultiFernet，T08），和 domain 一樣不得依賴框架、DB 與 Docker。
- **跨功能的 FK 以資料表名稱引用**，不 import 對方的 model。所有 model 登記在 `secscan.migrations.metadata`；API（`main`）、CLI（`cli`）、worker、runner 等每個使用 ORM 的程序入口都必須 import 它。
- **驗證與授權（T05）**：
  - `/api/v1` 在 router 層強制平台 key 驗證（`authenticated_router`），新增的路由不會意外變成公開端點。
  - service 先呼叫 `authorize(principal, permission, project_id)`；規則是 `api_keys/domain.py` 的純函式 `decide()`，其他 project 回 404、角色不足回 403，被拒絕時記下日誌（含 request_id）。
  - 清單查詢收明確的 `ProjectScope`（`AllProjects` 或 `OneProject`），由 `Principal.project_scope` 決定；不用 `None` 代表全部。T06 起的 target、grant、scan 等資源沿用同樣的做法。
- **request transaction（T05）**：
  - 路由以 `DbSession` 取得 session：每個請求一個 transaction，回應送出之前 commit，有例外時 rollback。
  - 業務變更與 audit 在同一個 transaction；可能撞到唯一約束而需要重試的寫入，放在 `begin_nested()` savepoint 內。
- **audit（T05）**：一律經 `AuditTrail.record` 寫入，changes 先以 `security.redaction` 遮罩；`NewAuditEvent` 再檢查是否已遮罩，並限制在 8 KiB 以內。
- **掃描範圍（T06，`DECISIONS.md` §10）**：
  - `LAB_CIDR` 由 `create_app` 依設定放在 `app.state.lab`，路由以 `CurrentLab` 依賴取得，再傳給 service。
  - origin 的嚴格解析與 `LabNetwork` 在 `targets/domain.py`；grant 的範圍、預算、期限、狀態與掃描 gate 在 `grants/domain/`。都不依賴框架與 DB。
  - 鎖的順序固定為 target 先、grant 後：申請 grant 以 `FOR UPDATE` 鎖 target；核准、撤銷以 `FOR UPDATE` 鎖 grant；掃描 gate 以 `FOR SHARE` 依序鎖兩者。上鎖時都用 `populate_existing` 讀 DB 的最新值。
- **驗證之前的關卡（T07，`DECISIONS.md` §11.1）**：兩個 pure-ASGI middleware，順序是 request_id → key 格式（`api_keys/middleware.py`）→ 大小上限（`core/body_limit.py`）。`/api/v1` 沒有 Bearer 或 key 格式不符就直接回 401、不讀 body；任何請求超過 2 MiB 回 413。key 格式的判斷與 `current_principal` 共用同一組函式。
- **API 規格（T07，`DECISIONS.md` §11）**：
  - 上傳是 raw body，由 async 依賴（`specs/dependencies.py`）逐塊讀取，限制在 1 MiB 與 10 秒（身分驗證已取得 DB 連線，慢速上傳不能一直佔住連線）；解析是 CPU 工作，在 service（threadpool）中進行。
  - 解析與正規化都在 `specs/domain/`，是不做 I/O 的純函式：`documents`（JSON、YAML 的子集與上限；YAML 只用 PyYAML 純 Python 的事件 API，由迭代式 composer 組成資料）、`references`（參照）、`openapi`（servers 改綁、inventory、canonical 文件）。
  - path 與 method 的比對在 `grants/domain/matching.py`（`covers()`、`ScopeRules`），M2 的 guard 也用它比對實際的請求。
  - 上傳先檢查權限、再解析，解析完才以 `FOR UPDATE` 鎖 target 取 version，不拖長鎖住 target 的時間。
- **認證設定與 secret（T08，`DECISIONS.md` §12）**：
  - `SecretCipher`（`security/secret_cipher.py`，MultiFernet）由 `create_app` 依 `SECRET_ENCRYPTION_KEYS` 建立，放在 `app.state.secret_cipher`，只有建立與 PATCH 的路由以 `CurrentCipher` 取得（查詢的路由沒有它）；沒有金鑰或格式不合時 API 不會啟動。只有 `security.secret_cipher` 可以 import `cryptography`（import-linter）。
  - 加密的內容綁定 `auth_profile:<id>:<type>:<header_name 或 ->`（context）。API 只加密、不解密：新版本沿用 secret 時直接複製密文；以 AST 測試確認 src 中沒有任何模組呼叫 `reveal`（M2 的 runner 會是唯一的呼叫者）。
  - 認證類型、secret 的格式、preflight 與 PATCH 的規則都在 `auth_profiles/domain/`，不依賴框架與 DB。schema 只限制型別與長度，規則在權限檢查之後驗證。
  - 鎖的順序：建立以 `FOR UPDATE` 鎖 target（數量上限）；PATCH 以 `FOR UPDATE` 先鎖 profile，再鎖目前的版本列才讀密文。金鑰換版（`secscan-admin rotate-secret-keys`，只有 CLI 呼叫）同樣先鎖 profile（依 id 的順序、`FOR SHARE`），再鎖版本列：順序相同，所以不會死結，而且兩個方向都互斥（PATCH 等換版，換版也等還沒 commit 的 PATCH）。

建議介面（概念契約，不是已存在的程式）：

```python
class ScannerAdapter(Protocol):
    def capabilities(self) -> ScannerCapabilities: ...              # 版本、支援的 profile、需要的輸入
    def validate(self, plan: ScanPlan) -> ValidationResult: ...      # 純函式
    def build_execution(self, plan: ScanPlan) -> ExecutionPlan: ...  # 純函式；秘密只用參照
    def parse(self, bundle: ArtifactBundle) -> ParsedRun: ...        # 純函式；輸出一律視為不可信

class Runner(Protocol):
    def start(self, execution: ExecutionPlan) -> RunHandle: ...
    def inspect(self, handle: RunHandle) -> RuntimeState: ...
    def cancel(self, handle: RunHandle) -> CancelResult: ...       # 先封鎖 guard，再停容器
    def collect(self, handle: RunHandle) -> ArtifactBundle: ...    # 只收集與計算 hash，不解析
```

ExecutionPlan 只能包含：

- 受控映像的 reference（digest）
- 固定的 entrypoint 與 args
- 已授權的 input artifact
- 資源與時間限制
- template ID 的 allowlist
- proxy 設定
- profile hash
- run ID

不能包含使用者指定的 host path、shell、任意映像或網路名稱。

## 5. 工具整合契約

| 項目 | ZAP | Nuclei | Schemathesis（P1） |
|---|---|---|---|
| 映像 | `zaproxy/zap-stable`（日期 tag + digest）[S04] | `projectdiscovery/nuclei`（digest） | `schemathesis/schemathesis`（digest）[S24] |
| 主要入口 | `zap.sh -cmd -autorun /zap/wrk/plan.yaml`，plan 由伺服器產生 [S02][S04] | 固定參數陣列、唯讀模板目錄、凍結 ID 清單（`-id`）[S23] | `st run <spec> --url … --seed …`，搭配固定 config [S07] |
| 輸入 | scope context、Web seed 或 API 規格 | 核准的目標/端點、template ID 清單 | 已驗證的 OpenAPI、operation allowlist、seed |
| 目標認證 | `ZAP_AUTH_HEADER*` 環境變數（啟動時讀取，每個容器各自獨立）[S21]；T03 已驗證 `_SITE` 以 host 子字串比對 | `-sf` secret 檔：`static: - type: bearertoken` + `domains` 完全比對 host:port（T03 驗證）[S23] | `schemathesis.toml` 以 `${ENV}` 帶入 `[auth.openapi.<scheme>] bearer`（T03 驗證）[S09] |
| 出站 | upstream proxy 設定鍵 `network.connection.httpProxy.*`，以 `-configfile`（0400）注入、不洩漏密碼（T03 驗證） | `-p <檔案>` 指向 guard；經 proxy 不需本機 DNS（T03 驗證）[S23] | `proxy` 指向 guard（T03 驗證）[S07] |
| 整合輸出 | report job 產生的 JSON；必要的訊息/統計 | `-jsonl -o` + 執行 manifest | `--report json,ndjson`；必要時加 junit [S07] |
| 必須關閉 | `-silent`（不主動對外請求、不檢查更新）[S20]；OAST | `-ni`（關閉 interactsh/OAST）、`-duc`、`-pt http` 以外的協定、code/headless/dos 模板、雲端上傳 [S23] | 未授權的 method（grant + guard 雙重限制）；自動建立帳號等行為（若該版本有） |
| 來源鍵 | plugin/rule ID、alert instance | template ID、matcher、matched-at | check、operation、case/event ID |
| 不能假設 | alert 很多就表示執行成功；API/Web profile 等價 | 官方模板都沒有副作用；JSONL 是空的就等於安全 | check 停用就等於不發請求；500 都是漏洞 |

- **ZAP**：M0 可以用 packaged scripts 取得樣本，但正式的 Adapter 使用同一套可版本化的設定，不同時維護好幾條不相容的掃描路徑。需記錄 engine/add-on 版本、JSON schema 和 exit handling。[S02–S05]
- **Nuclei 模板清單**：
  - 從鎖定的 nuclei-templates release，依 tag/類型產生固定的 ID 清單，並記錄 release、hash 與 ID。
  - 以類別為單位人工審查，並抽查高風險模板。
  - 禁用 code/headless、外部 OAST、cloud upload、HTTP 以外的協定與未知的 raw template；模板簽章只是來源證據。
  - 新增或移除模板都要留紀錄，實驗前凍結。[S06][S23]
- **Schemathesis**：
  - 依鎖定版本確認報告支援的格式，不捏造參數。
  - 用 JUnit 時，不能只靠 free text 猜 parameter 或位置；要關聯 NDJSON，或把缺乏定位資訊的結果標為低精度。[S07]
  - 要禁止某個 HTTP method，必須同時限制 generation 與出站，而不是只關掉對應的 check。[S08]
- **capability probe**：每個 adapter 都要檢查實際的 executable、版本、設定檔、輸出能否寫入，以及 proxy 行為。工具不支援所需能力時，回傳能力錯誤，不偷偷降級。

## 6. 資料模型

| 資料表 | 核心欄位與責任 |
|---|---|
| projects | id、name、created_at；初版可以只有一個專案，但結構仍保留隔離 |
| api_keys | id、key_hash、prefix、role、project_id、expires_at、revoked_at；admin 可以不屬於任何 project |
| targets | id、project_id、name、kind、canonical_origin、environment、enabled（T06 已建立） |
| scope_grants | target_id、version、status（pending/approved/revoked；expired 由期限推導）、allowed_origins/ips/paths/methods、excluded_paths、allow_all_paths、預算、authorization_reference、有效期、申請與核准、撤銷的 key 與時間；`LAB_ONLY` 時 allowed_ips 必須在 `LAB_CIDR` 內（T06 已建立；port 由 origin 決定，不另存） |
| api_specs | id、target_id、version、上傳檔的格式、大小與 sha256、正規化文件（bytea）與它的 sha256、openapi_version、base_path、operation_count、上傳者（T07 已建立；原規劃的受控 storage key 改成存在 DB，理由見 `DECISIONS.md` §11.5） |
| api_spec_operations | spec_id、ordinal、method、path（含 base path）、operation_id；inventory 的每一列（T07 已建立） |
| auth_profiles | id、target_id、name、role_label（同一個 target 內唯一）、建立的 key 與時間；建立後不可變（T08 已建立） |
| auth_profile_versions | profile_id、version、type、header_name、preflight（method、path、expected_status、expected_json）、encrypted_secret（Fernet token，被取代就清除）、secret_erased_at、建立的 key 與時間（T08 已建立；原規劃的單一資料表改成兩張，理由見 `DECISIONS.md` §12.3） |
| scans | id、project_id、target_id、status、snapshot、idempotency_key/hash、cancel_requested_at、manifest、時間 |
| scanner_runs | id、scan_id、engine、engine_version、sequence（執行順序）、status、attempt、lease_owner、lease_expires_at、heartbeat_at、container_label、proxy_credential_hash、error、coverage；同時是 runner 與 worker 的工作佇列 |
| findings | id、target_id、fingerprint、kind、normalized_severity、owasp_2025、owasp_api_2023、mapping_source、mapping_version、triage/lifecycle、first/last_seen |
| observations | id、finding_id（可以先為 null）、scan_id、scanner_run_id、source_rule、rule_group、位置、auth_role、evidence_ref、raw_severity、raw_confidence、parser_version |
| artifacts | id、run_id、type、hash、storage_key、size、classification、encrypted、retention |
| reports | id、scan_id、format（json/markdown；P1 加 sarif）、status、artifact_id、lease 欄位、error；同時是 worker 的工作佇列 |
| scan_events | id、scan_id、sequence、event_type、sanitized_payload、時間；供輪詢使用 |
| audit_events | actor_key_id、project、action、object_ref、redacted_changes、時間 |

### 6.1 約束與索引

- **project 隔離**：
  - 所有子資源都要能追溯到 project。
  - 查詢時先限制 project 再取物件，不能只用 UUID 查。
- **scans**：
  - `(project_id, idempotency_key)` 設唯一約束；相同 key 但 request hash 不同時，回 409。
  - 同一個 target 初版只允許一個進行中的 scan，避免重複改變靶場狀態。
- **scanner_runs**：
  - `(scan, engine, attempt)` 唯一。
  - 用部分索引加速工作認領，例如 `scanner_runs(status, sequence) WHERE status IN ('queued', 'collected')`。
- **observations**：
  - `(run, source_event_id)` 設唯一約束。
  - 沒有 source ID 時，用輸出記錄的位置或穩定 hash 產生，避免 Parser 重跑時重複寫入。
- **mapping 版本**：正規化前後都保留 parser、rule_groups 與 mapping 的版本。
- **findings**：`(target, fingerprint)` 唯一；低可信度的映射不得強行共用 fingerprint。

JSONB 可以用來存固定版本的 snapshot 或各來源的差異欄位，但不能把所有資料都塞進單一 JSON 欄位，導致失去授權與查詢約束。

### 6.2 實作狀態

- **T04（migration `0001`）已建立 projects、api_keys、audit_events**：
  - 約束與索引依固定命名慣例產生（例如 `uq_api_keys_prefix`、`fk_api_keys_project_id_projects`），service 可以依約束名稱對應錯誤碼。
  - api_keys：platform_admin 一律 `project_id IS NULL`，operator/viewer 必須屬於一個 project（CHECK）；key_hash 固定 32 bytes 且唯一；撤銷只設 `revoked_at`，不刪除資料列。
  - audit_events：trigger 拒絕 UPDATE、DELETE 與 TRUNCATE（append-only）。FK 一律 `ON DELETE RESTRICT`，被稽核紀錄引用的 project 與 key 不能刪除。
  - 時間欄位是 timestamptz，以 `UtcDateTime` 型別存取：拒絕沒有時區的 datetime（否則會被當成 UTC，靜默差 8 小時），讀出時一律轉成 UTC。連線也固定以 UTC 解讀。
  - id 是 UUIDv4，ORM 與 DB 兩邊都有預設值。
  - engine 設定 `hide_parameters`：SQL 參數不出現在例外與日誌中。repository 把約束錯誤轉成 `ConstraintViolationError`，帶約束名稱與 SQLSTATE，但不接上原始例外，因為原始例外含 DB 回傳的資料值。
  - domain 的 `New*` 物件在送進 DB 前先驗證長度、空白（含全形空白）與 NUL；DB 的 CHECK 是最後一道防線。
- **T05 沒有新增 migration**：key 的 prefix、hash、撤銷與到期欄位在 `0001` 已建立。T05 新增的是 API、權限規則、request transaction 與本機 CLI（`API_CONTRACT.md` §13）。
- **T06（migration `0002`）建立 targets 與 scope_grants**：
  - targets：`(project_id, canonical_origin)` 唯一；CHECK 限定 kind、`environment = 'lab'`，並以 regex 檢查 canonical origin 的形式。
  - scope_grants：`(target_id, version)` 唯一；allowed_ips 是 `inet[]`。CHECK 涵蓋狀態與核准、撤銷欄位的一致性、時間先後（核准必須在到期之前）、清單筆數、method 白名單、`allow_all_paths` 與 path 清單的搭配、預算大於 0。預算上限與 `LAB_CIDR` 是政策或設定，放在 domain。
  - trigger `scope_grants_guard`：UPDATE 只允許 pending→approved、pending→revoked、approved→revoked，而且只能改狀態與核准、撤銷欄位；DELETE 與 TRUNCATE 一律拒絕。
  - FK 一律 `ON DELETE RESTRICT`；grant 所屬的 project 由 target 取得，不重複存放。
- **T07（migration `0003`）建立 api_specs 與 api_spec_operations**：
  - api_specs：`(target_id, version)` 唯一；CHECK 涵蓋格式、上傳檔大小（1 MiB）、文件大小（2 MiB）、hash 長度、`document_sha256 = sha256(document)`、openapi_version 為 3.0.x、base path 的形式、operation 數量。文件欄位以 deferred 載入，一般查詢不讀它。
  - api_spec_operations：主鍵 `(spec_id, ordinal)`；`(spec_id, method, path)` 與 `(spec_id, operation_id)` 唯一（NULL 不相等，沒有 operationId 的可以有很多個）；CHECK 涵蓋 method 白名單（含 TRACE）、path 以 `/` 開頭、operationId 不空白、ordinal 範圍。
  - trigger `api_specs_guard`：兩張表的 UPDATE、DELETE、TRUNCATE 一律拒絕（只防程式錯誤造成的誤改，同 `DECISIONS.md` §7）。
  - FK 一律 `ON DELETE RESTRICT`；規格所屬的 project 與 origin 由 target 取得。
- **T08（migration `0004`）建立 auth_profiles 與 auth_profile_versions**：
  - auth_profiles：`(target_id, role_label)` 唯一；CHECK 涵蓋名稱不空白、role_label 的形式（不可是 `anonymous`）。trigger 擋下 UPDATE、DELETE 與 TRUNCATE。
  - auth_profile_versions：主鍵 `(profile_id, version)`；部分唯一索引 `uq_auth_profile_versions_live_secret`（`WHERE encrypted_secret IS NOT NULL`）保證每個 profile 最多一份密文。CHECK 涵蓋 type 白名單、header_name 與 type 成對、preflight 的 method、path（沒有佔位）、status 與 expected_json（非空的物件、大小上限）、密文與清除時間成對、密文是 Fernet token（`gAAAAA` 開頭）且有長度上限。
  - trigger `auth_profile_versions_guard`：INSERT 必須帶密文；UPDATE 只允許清除密文與重新加密，其他欄位都不能改；DELETE、TRUNCATE 一律拒絕。和其他 trigger 一樣只防程式錯誤造成的誤改。
  - 密文欄位以 deferred 載入；FK 一律 `ON DELETE RESTRICT`，所屬的 project 由 target 取得。
- **其餘資料表由各功能任務以自己的 migration 加入**：scans、scanner_runs、scan_events（T09）。findings、observations、artifacts、reports 在 M3 之後加入。

## 7. ScanPlan 與執行快照

建立 scan 時凍結以下欄位，但 secret 本身不存進一般的 snapshot（auth profile 只記 id 與版本；被取代的版本已清除密文，排隊中、綁定被取代版本的 scan 在 runner 啟動前就失敗，`DECISIONS.md` §12.3）：

- **目標與授權**：target、grant、spec、auth profile 的 ID 與版本；origin、path、method
- **引擎與模板**：engine 集合、template commit 與 ID、映像 digest、ZAP add-on 版本
- **設定與版本**：profile/budget、guard policy hash、parser/rule_groups/mapping 版本、程式 commit
- **靶場**：image 與 data snapshot

執行前要再次檢查：grant 尚未撤銷或過期、target 沒有停用、實際網路仍然一致。授權被撤回時，停止仍在執行的 scan。不能因為快照存在，就繼續使用已失效的授權。

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
| queued | scan 與 scanner_runs 已持久化，等待 runner 認領 |
| preparing | 認領、scope/auth/network/capability preflight 中 |
| running | 至少一個引擎已開始；多個引擎依序執行 |
| collecting | 收集已產出的受限 artifacts |
| normalizing | 驗證輸出、匯入 observation、建立或關聯 finding |
| completed | 所有選定且適用的引擎都執行並解析完成；可以是零告警 |
| partially_completed | 至少一個引擎有可用結果，其他引擎或覆蓋未完成 |
| failed | 沒有可用的完整結果，且已確認是工具、設定或解析失敗 |
| timed_out | 全 scan 的時間或請求預算用盡；保留部分證據，但不宣稱完整 |
| cancelling / cancelled | 停止處理中 / 已確認不再執行，也不再發出新請求 |
| interrupted | 因 runner 遺失等原因，無法證明已正常完成；需由 reconciler 處理 |

**scanner_run 的狀態**：queued / preparing / running / collecting / collected / normalizing / succeeded / failed / timed_out / cancelling / cancelled / interrupted，並彙總成 scan 的狀態。

- `queued` 由 runner 認領；runner 收集完畢後標為 `collected`，再由 worker 認領解析。
- 即使 scan 是 completed，也不代表所有授權的 API operation 都確實測到了。coverage 是另一個維度，必須呈現分母和未測的理由。

**例外處理**：

- 不支援的引擎、缺少必需的 spec，或 profile 不相容，在建立任務時就回 422 拒絕，不事後默默跳過。
- 單一工具失敗，不應刪除另一個工具的成功證據。
- 因為真的檢出安全問題而造成的非零退出，依工具契約分類，不直接當成 crash。

## 9. 可靠派送與取消

**建立與認領**：

- 建立 scan 時，在同一個 transaction 裡寫入 scans，以及每個引擎的 scanner_runs（queued）。commit 之後工作就已經存在，不需要另外派送訊息，所以不會出現「DB 已寫入但工作沒派出去」的情況。
- runner 以 `SELECT … FOR UPDATE SKIP LOCKED` 認領下一個可執行的 run [S28]，同一個 scan 依 sequence 依序執行。
- 認領時寫入 lease_owner 與 lease_expires_at，並先查既有的 container label 與 run 狀態，不重複啟動。
- worker 用同樣的方式認領 collected 的 run 與 pending 的 report。
- 初版以 1–2 秒輪詢，需要時再加 LISTEN/NOTIFY。

**心跳與對帳**：

- 規劃每 5 秒送一次心跳、lease 30 秒；實際數值由測試調整。
- lease 過期不代表舊容器已經停止。runner 內的 reconciler 必須：
  1. 核對 container label；
  2. 把舊 run 的 guard policy 設為 blocked；
  3. 確認容器已終止。
- 不能只因 lease 過期就啟動第二個掃描器。

**重試原則**：

- 還沒發出任何掃描請求前，可以重試暫時性的啟動問題。
- 開始發流量後若崩潰，預設標為 interrupted，由使用者以新的 scan 重跑。
- 只有 Parser 可以對不可變的 artifact 安全重試。
- 這套機制不提供目標外部狀態的 transaction rollback。

**取消的驗收目標**：

- 控制 API 回應後，10 秒內停止新的出站請求，最長 30 秒內回收工具容器；實測有偏差需記錄。
- API 回 202 時，狀態可以是 cancelling；只有確認清理完成後才變成 cancelled。

## 10. 統一發現格式與去重

**Observation 包含**：

- 來源 engine/rule、source severity/confidence
- CWE/CVE（可為空）
- request method、canonical origin、route/path
- parameter 的位置與名稱
- auth role、資源辨別資訊
- 證據索引與時間

HTTP body、敏感的 query 與 Token 不直接當作索引。

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

**語意規則群組**：

- `reviewed_semantic_rule_group` 來自 `findings/taxonomy/rule_groups.yaml`。這份表經過人工審查並有版本號，把 (scanner, rule_id) 對到語意群組；不是用 CWE 代替。
- 對不到群組的規則，以 `scanner:rule_id` 作為群組，保持獨立，不跨工具合併。

**路徑與參數**：

- 只有存在可信的 OpenAPI 或 route map 時，才把 API 路徑中的具體 ID 對應成 `{id}`。
- 與授權或特定資源有關的問題，仍要保留 resource discriminator，避免把不同物件合併在一起。
- Query 不全部刪除。像 action/type 這類有業務語意的欄位，要依規則保留。
- secret 值要遮罩；必要的識別欄位可以用專案穩定的 HMAC。
- 不要過度 decode path，導致把不同的路徑當成相同。

**標準對應**：

- 對應掛在語意規則群組上。
- OWASP Top 10:2025 依官方 CWE 清單（`mapping_source=official`）[S25]。
- API Security Top 10:2023 用自訂表（`curated`）[S15]。
- 沒有可靠的對應時標為 `none`。
- API6 與 API10 無法用 DAST 偵測，列為限制。

**severity 正規化**：

- 保留原值，以有版本號的對照表轉成 critical / high / medium / low / info。
- ZAP 的 riskcode 3/2/1/0 對到 high/medium/low/info。
- Nuclei 的 severity 一對一對應；unknown 轉成 info，並標記 needs_review。
- Schemathesis 依 kind 與安全影響對應，5xx 預設為 robustness。

**合併原則**：

- 去重不刪除 Observation。
- 跨工具命中只代表有多個來源，不自動提高 severity，也不標為 confirmed。
- severity 的衝突或未知時，保留原值與理由；不可以用空的 CVSS 補一個假分數。

## 11. 人工 triage 與複掃

`triage_state`：unreviewed / confirmed / false_positive / accepted_risk。

`lifecycle_state`：open / resolved / reopened。

- resolved 需要人工或明確的驗證程序加註原因與證據；不能只因為新的 scan 沒有告警就自動關閉。

Compare 的結果分成 `new / persistent / not_observed / inconclusive / not_comparable`。比較的順序：

1. 先比較 target、scope、auth role、spec、profile、engine/template、靶場與版本。
2. 再核對執行完成度、認證狀態，以及操作/規則的實際覆蓋。

可比性的限制：

- 工具版本或策略的變動會影響可比性，必須顯示差異與信心上的限制。
- 沒有足夠的 rule/operation telemetry 時，「這次沒再命中」標為 inconclusive，不假設工具有檢查到該處。
- 即使可比且是 not_observed，也不能自動當成安全的證明。

## 12. Artifact 與報告

**工作目錄與檔案限制**：

- 每次 run 的工作目錄是 runs volume 的一個子目錄，以伺服器產生、不可預測的 ID 命名。
- 掃描容器以 subpath 掛載：`in/` 唯讀、`out/` 可寫。
- runner 收集完後計算 hash，worker 以唯讀方式解析。
- 使用者不能指定本機路徑。
- 檔案大小上限、路徑穿越、symlink、壓縮檔展開上限都要測試；P0 不接受使用者上傳的壓縮檔。

**證據保存**：

- 原始輸出寫入受限的暫存區並計算 hash，再加密存成受限的 evidence。
- 一般查詢只回傳遮罩後的摘要。

**報告內容**：

- 工具與版本、範圍、auth 狀態
- operation coverage、guard 計數的實際請求數
- 引擎錯誤
- security / contract / robustness 分類
- 證據、人工 triage、未測項目

**報告安全**：

- 不把未經編碼的目標回應放進可執行的 HTML。
- 初版輸出 JSON/Markdown（P1 加 SARIF），並以 attachment 與正確的 content-type 傳送。
- 需要處理 Markdown 中的原始 HTML 與連結，不自動載入遠端資源。
- 產生報告不需要自訂前端。
