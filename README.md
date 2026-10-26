# Web 與 API 多引擎動態安全檢測後端｜畢業專題規劃包

- 文件日期：2026-10-16（整合版）
- 專題代號：`webapi-security-backend`（暫名；Python 套件名暫定 `secscan`）
- 文件狀態：**設計與開發規格，不是已完成或已實測的後端程式。**
- 已確認的條件：
  - 範圍：Web 應用與 API 安全檢測，整合 3 個動態工具，只做後端。
  - 人力與時程：1 人開發，2026/10/16 – 2027/06/30（約 37 週）。

## 建議題目

**Web 與 API 多引擎動態安全檢測暨結果整合後端系統之設計與實作**

P0 先完成 ZAP + Nuclei。兩引擎通過 P0 Gate 後，M6 再接第三引擎 Schemathesis。專題貢獻聚焦於授權範圍控管、強制出站邊界、可靠的掃描編排、證據保留、保守去重、覆蓋率與複掃比較，而不是宣稱自行發明弱點掃描器。

## 規劃來源

本包整合了兩份規劃：

- **ChatGPT 版原稿**：本儲存庫第一個 commit，可用 `git show 86d7b2b` 查看。
- **Claude 版**：在 Claude Code 規劃模式中產出。

逐項比較與取捨理由見 `docs/DECISIONS.md`。

## 文件索引

| 檔案 | 用途 |
|---|---|
| `CLAUDE.md` | 放在專案根目錄的 Claude Code 開發規則 |
| `docs/REQUIREMENTS.md` | 已凍結的需求摘要：題目、相對於手動使用工具的增益、P0/P1/不做、研究問題與待驗證假設 |
| `docs/TOOLS.md` | T03 工具 spike 結果：映像相容性表、digest、授權、網路隔離與各引擎 proxy/auth/output 的實測 |
| `docs/PROJECT_PLAN.md` | 背景、需求、工具選型、功能範圍、時程與交付成果 |
| `docs/ARCHITECTURE.md` | 元件、信任邊界、egress guard、資料模型、Adapter/Runner 與狀態機 |
| `docs/API_CONTRACT.md` | REST API、權限、資料格式與錯誤語意；§13 是 T05 已實作的 key、專案與權限，§14 是 T06 已實作的 target 與 scope grant，§15 是 T07 已實作的 API 規格，§16 是 T08 已實作的認證設定 |
| `docs/SECURITY_AND_TESTING.md` | 平台自身的安全要求、測試矩陣與實驗設計 |
| `docs/TASKS.md` | 依里程碑排列的工作、依賴、驗收條件與降階方案 |
| `docs/START_HERE.md` | 開發順序，以及給 Claude Code 的第一段任務提示 |
| `docs/DECISIONS.md` | 兩份規劃的比較與設計取捨，可作為報告素材 |
| `docs/SOURCES.md` | 已查核的一手技術文件與引用對照 |

## 使用方式

先閱讀 `docs/START_HERE.md`，再依 `docs/TASKS.md` 的順序開發。根目錄使用大寫檔名 **`CLAUDE.md`**。[S01]

目前完成 M0 與 M1（T02–T09）：
- **M0**：FastAPI 骨架與品質命令（T02）；隔離 lab（`compose.lab.yaml` + `make lab-up`）與三個掃描器經 proxy 的工具 spike（T03，結果見 `docs/TOOLS.md`）。
- **T04**：PostgreSQL 資料層（`compose.yaml`、Alembic migration、repository），第一批資料表 projects、api_keys、audit_events，以及 `GET /health/ready`。
- **T05**：平台 API key（DB 只存 hash、一定會過期、可撤銷）、project 與 object-level 權限、`/api/v1` 的 projects、keys 與稽核查詢端點，以及建立初始管理 key 的本機 CLI `secscan-admin`（見下方「平台 API key」與 `docs/API_CONTRACT.md` §13）。
- **T06**：掃描目標（target）與管理員核准的掃描範圍（scope grant）：origin 的嚴格解析、`LAB_ONLY`／`LAB_CIDR`、pending／approved／revoked／expired 的轉換，以及建立 scan 前要通過的檢查（見下方「掃描目標與授權」與 `docs/API_CONTRACT.md` §14）。
- **T07**：上傳 OpenAPI 3.0 規格（JSON 或 YAML），嚴格解析、拒絕外部參照，`servers` 一律改綁到 target 的 origin；產生 operation inventory，並依 grant 判斷每個 operation 是否在範圍內。另外在 `/api/v1` 前加上驗證之前的 key 格式檢查與請求大小上限（見下方「API 規格」與 `docs/API_CONTRACT.md` §15）。

- **T08**：被測目標的認證設定（auth profile）：bearer、API key header、Cookie 三種，secret 以 MultiFernet 加密、只寫不讀；PATCH 產生新版本並清除上一版的密文；preflight 的定義與驗證；加密金鑰換版的 CLI `secscan-admin rotate-secret-keys`（見下方「認證設定」與 `docs/API_CONTRACT.md` §16）。
- **T09**：建立 scan（Idempotency-Key、不可變的快照、一個 target 同時只有一個進行中的 scan）、以 PostgreSQL `SKIP LOCKED` 認領的工作佇列（lease、心跳、對帳）、run 與 scan 的狀態機、事件輪詢與取消，以及測試用的 fake 引擎與 `secscan-admin fake-runner`；DB 連線加上逾時（見下方「建立 scan」與 `docs/API_CONTRACT.md` §17）。

還沒有 runner 或正式的 Adapter／egress guard（M2 起）：T09 的 scan 只能用 `fake` 引擎，它不連任何位址，結果在回應中標為 `fixture: true`，不是真的掃描。其他文件中的指令與 API 仍是**待實作的契約**；`tests/fixtures/` 的真實輸出是給未來 Parser 開發用的樣本，不代表平台已能端到端掃描，也不能把 Mock 當成真實掃描成功的證明。

### 開發環境

需要 Homebrew、uv 與 OrbStack；專案固定使用 Python 3.12（見 `.python-version`）。

```bash
brew install uv   # 依賴管理工具
make bootstrap    # 依 uv.lock 安裝依賴，並啟用 pre-commit hook
orb start         # 啟動 OrbStack（PostgreSQL 與 lab 都跑在容器裡）
make db-up        # 啟動開發用 PostgreSQL（第一次會自動產生 .env 裡的本機密碼）
make migrate      # 把開發資料庫升級到最新 schema，最後印出目前版本
make test         # 先啟動 db-test，再跑 unit/contract/integration 測試與 coverage 門檻 80%
make lint         # ruff 與 import-linter
make typecheck    # mypy strict
make dev          # 只綁 127.0.0.1:8000；/docs 只在 dev 開啟
```

`make dev` 啟動後：

- `curl http://127.0.0.1:8000/health/live` 回傳 `{"success": true, "data": {"status": "ok"}, "error": null, "meta": null}`。
- `curl http://127.0.0.1:8000/health/ready` 在 DB 可連線且已 migrate 時回 200；否則回 503（`DEPENDENCY_UNAVAILABLE`）。

TDD 時可以只跑單一測試檔：`uv run pytest tests/unit/core/test_config.py`，這樣不會檢查 coverage 門檻；提交前仍以 `make test` 為準。不需要 DB 的測試可用 `uv run pytest -m "not integration"`。

#### PostgreSQL（T04）

`compose.yaml` 有兩個只綁 127.0.0.1 的 PostgreSQL 18：

| 服務 | port | 用途 | 資料 |
|---|---|---|---|
| `db` | 55432 | 開發（`make dev`、`make migrate`） | 保存在 volume `secscan_db_data` |
| `db-test` | 55433 | 整合測試 | tmpfs，停掉就清空 |

- **密碼**：都在 `.env`（權限 600，不進 git）。`make env` 只會補上缺少的隨機值，不會覆寫既有的值；`dev`、`db-up`、`test-db-up`、`test` 會自動呼叫它。
- **加密金鑰**：`make env` 也會在 `.env` 產生 `SECRET_ENCRYPTION_KEYS`（加密認證設定的 secret；API 沒有它就不會啟動）。**請備份這一行**：遺失之後，已保存的 secret 都解不開，只能重新設定。換版的做法見下方「認證設定」。
- **連線角色**：應用程式與 migration 用非 superuser 的 `secscan_app`。superuser 只給容器初始化與手動維運。
- **整合測試**：每次 session 都在 db-test 建立專屬角色與全新資料庫，結束時刪除。只接受 `cluster_name=secscan-test` 的伺服器，不會碰到開發資料庫。
- **停止**：`make db-down` 停止兩者，但保留開發資料。
- **不要分享的輸出**：`docker-compose config` 與 `docker inspect` 會顯示 `.env` 裡的明文密碼，不要貼到 issue、報告或聊天中。pre-commit 會擋下 `.env` 檔（即使用 `git add -f`）。
- **改了 `.env` 的 `DB_PASSWORD` 之後**：要讓新密碼生效，得重建開發資料庫。這會**刪除所有開發資料**：`make db-down && docker volume rm secscan_db_data && make db-up && make migrate`。

新增 schema 變更時：先寫會失敗的測試，再改 model，最後產生 migration。例如：`uv run alembic revision --autogenerate --rev-id 0002 -m "<說明>"`。產生後補上升降級說明並檢查內容；`tests/integration/test_migrations.py` 會檢查 model 與 migration 沒有漂移。

#### 平台 API key（T05）

`/api/v1` 的每個請求都要帶 `Authorization: Bearer <key>`。第一把管理 key 由本機 CLI 建立，完整的 key 只會出現這一次；DB 只存 hash，遺失時只能重新建立。

```bash
make db-up && make migrate
umask 077 && mkdir -p ~/.config/secscan
uv run secscan-admin create-admin-key --name "本機管理員" --output ~/.config/secscan/admin.key
printf 'Authorization: Bearer %s\n' "$(cat ~/.config/secscan/admin.key)" > ~/.config/secscan/admin.header
make dev   # 另開一個終端機
curl -H @"$HOME/.config/secscan/admin.header" http://127.0.0.1:8000/api/v1/projects
```

- **key 只寫出一次**：`--output` 把 key 寫進新建、權限 600 的檔案；檔案已存在時拒絕，不會覆寫舊的 key。不加 `--output` 則寫到 stdout。
- **不要把 key 放在命令列參數**：其他程序可以從 `ps` 看到命令列，shell 歷史也會留下紀錄。上面的做法讓 curl 從權限 600 的檔案讀 header。
- **有效期**：所有 key 都會過期，預設 90 天、最多 365 天（CLI 用 `--expires-in-days` 調整）。過期後重新建立即可。
- **專案成員的 key**：admin 以 `POST /api/v1/projects/{project_id}/keys` 建立 operator 或 viewer key，回應中的 `key` 同樣只出現這一次，請立即存起來。
- **撤銷**：`DELETE /api/v1/keys/{key_id}`；撤銷後立即失效。
- **dev 的 API 文件**：`/docs` 會從 CDN 載入 Swagger UI。要在 Authorize 填 key 時，只用權限最小的 viewer key，不要貼 admin key。
- 權限規則、錯誤碼與範例見 `docs/API_CONTRACT.md` §13，設計理由見 `docs/DECISIONS.md` §9。

#### 掃描目標與授權（T06）

target 只是登記要掃描的靶場；要掃描，還需要管理員核准的 scope grant（允許的 origin、IP、path、method、預算與期限）。以下假設 `operator.header`、`admin.header` 是用上一節的方式做成、權限 600 的 header 檔，`<…>` 換成實際的 id。

```bash
cd ~/.config/secscan
# operator（或 admin）建立 target：只接受 http 的 origin
curl -H @operator.header -H 'Content-Type: application/json' \
  -d '{"name": "VAmPI", "kind": "api", "base_url": "http://vampi-vuln:5000"}' \
  http://127.0.0.1:8000/api/v1/projects/<project_id>/targets
# 申請 scope grant（狀態是 pending），內容範例見 docs/API_CONTRACT.md §14.2
curl -H @operator.header -H 'Content-Type: application/json' -d @grant.json \
  http://127.0.0.1:8000/api/v1/targets/<target_id>/scope-grants
# admin 核對之後核准，note 寫下核對了什麼
curl -H @admin.header -H 'Content-Type: application/json' \
  -d '{"note": "已核對 lab 資產紀錄與 vampi-vuln 的 IP，網路為 internal"}' \
  http://127.0.0.1:8000/api/v1/scope-grants/<grant_id>/approve
```

- **`LAB_ONLY` 與 `LAB_CIDR`**：P0 只掃 lab，`LAB_ONLY` 不能關閉（設成 false 時啟動就失敗）。`LAB_CIDR` 預設是 `compose.lab.yaml` 的 lab_net（`10.89.7.0/24`）；grant 的每個 IP，以及 IP 形式的 target 主機，都必須是這個網段內的主機位址。
- **核准前要核對**：靶場資產紀錄（`authorization_reference`）、origin 與 IP 的對應、網路是否隔離，以及允許的 method 有沒有副作用。API 不會替你解析 DNS 或連線。查容器的 IP 時只取需要的欄位，例如 `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <container>`；完整的 `docker inspect` 會印出環境變數。
- **改範圍就申請新版本**：grant 建立後不能修改；核准新版本不會自動撤銷舊版本，不用的版本請撤銷。
- **停止**：admin 以 `POST /api/v1/scope-grants/<grant_id>/revoke`（附 `reason`）撤銷；operator 可以用 `PATCH /api/v1/targets/<target_id>` 送 `{"enabled": false}` 停用 target。兩者都讓之後不能再用它建立 scan。operator 也能重新啟用 target，所以權威的停止是撤銷 grant。
- **上限**：每個 project 最多 100 個 target；每個 target 最多 10 個待核准的申請（`409 QUOTA_EXCEEDED`）。
- **期限**：grant 最長 30 天，到期後狀態自動顯示為 `expired`，要重新申請。
- 建立 scan 見下方「建立 scan」；規則、錯誤碼與範例見 `docs/API_CONTRACT.md` §14，設計理由見 `docs/DECISIONS.md` §10。

#### API 規格（T07）

上傳的規格只是保存與檢查：平台不會去抓規格中的外部參照，也不會連 `servers` 指向的位址。body 就是規格檔本身（不是 multipart）：

```bash
cd ~/.config/secscan
# operator（或 admin）上傳；YAML 用 application/yaml，JSON 用 application/json
curl -H @operator.header -H 'Content-Type: application/yaml' --data-binary @openapi3.yml \
  http://127.0.0.1:8000/api/v1/targets/<target_id>/api-specs
# 預覽 inventory：帶 scope_grant_id 時，每個 operation 附上是否在範圍內與原因
curl -H @operator.header \
  'http://127.0.0.1:8000/api/v1/api-specs/<spec_id>/operations?limit=100&scope_grant_id=<grant_id>'
```

- **servers 會被改綁**：例如 VAmPI 規格中的 `http://localhost:5000` 會變成 target 的 `http://vampi-vuln:5000`；原本的 host 不保存。回應的 `server_url` 是改綁後的位址。
- **限制**：最多 1 MiB、10 秒內上傳完成、OpenAPI 3.0.x；只接受同一份文件中的 `$ref`（`#/…`），discriminator 的 mapping 要寫成 `#/components/schemas/<名稱>`。YAML 不接受 anchor、alias 與 tag，`yes`、`on`、日期一律當成字串（YAML 1.2）；被拒絕時，錯誤訊息會指出行、欄或 JSON Pointer 位置。完整規則見 `docs/API_CONTRACT.md` §15.1。
- **範圍判斷**：排除的 path 不分大小寫、忽略結尾的斜線；允許的 path 必須完全一致；都不從前綴推論，要排除 `/api/admin` 底下的 route 必須另外列出（例如 `/api/admin/{id}`）。
- **版本**：規格不能修改或刪除，要改就重新上傳（每個 target 最多 20 個版本）；同一份內容以 JSON 或 YAML 上傳，`document_sha256` 相同。
- **驗證之前的關卡**：`/api/v1` 沒有 key 或 key 格式不符時直接回 401，不讀 body；任何請求超過 2 MiB 回 413。

#### 認證設定（T08）

被測網站的憑證（不是平台的 API key）以認證設定保存。secret 只寫入、不會出現在任何回應、日誌或 audit；T08 只保存與檢查，不會送出任何請求（preflight 在 T12 才執行）。請求 body 含 secret，先寫進權限 600 的檔案再送：

```bash
cd ~/.config/secscan
umask 077
cat > profile.json <<'JSON'
{"name": "VAmPI 一般使用者", "role_label": "standard_user", "type": "bearer",
 "secret": "<從 VAmPI 登入取得的 token>",
 "preflight": {"method": "GET", "path": "/me", "expected_status": 200,
               "expected_json": {"/status": "success", "/data/username": "name1"}}}
JSON
curl -H @operator.header -H 'Content-Type: application/json' --data-binary @profile.json \
  http://127.0.0.1:8000/api/v1/targets/<target_id>/auth-profiles
# 換 token：產生新版本，上一版的密文清除（body 一樣先寫進檔案）
curl -X PATCH -H @operator.header -H 'Content-Type: application/json' --data-binary @new-token.json \
  http://127.0.0.1:8000/api/v1/auth-profiles/<profile_id>
rm profile.json new-token.json
```

- **三種類型**：`bearer`（只填 token 本身，不要加 `Bearer `）、`api_key_header`（另外指定 `header_name`，不可以是 Host、Proxy-*、X-HTTP-Method-Override 這類 header）、`cookie`（`name=value; name2=value2`）。secret 不可含平台的 API key。
- **preflight**：只有 GET、path 不可有佔位、status 200–299；`expected_json` 至少要比對一項回應內容（key 是 JSON Pointer，例如 `/data/username`），只看狀態碼分不出登入頁。
- **版本**：PATCH 沒給的欄位沿用目前的版本；換 `type` 或 `header_name` 時要附上新的 secret。歷史見 `GET /api/v1/auth-profiles/<profile_id>/versions`（只有目前的版本還有 secret）。每個 target 最多 10 個認證設定、每個 100 個版本。
- **加密金鑰換版**：
  1. 以 `openssl rand -base64 32 | tr '+/' '-_'` 產生新金鑰，放在 `.env` 的 `SECRET_ENCRYPTION_KEYS` 最前面（逗號分隔，例如 `新,舊`），重啟 API。
  2. 執行 `uv run secscan-admin rotate-secret-keys`：以新金鑰重新加密所有的 secret；有任何一份解不開就全部回滾。
  3. 移除舊金鑰、重啟 API，再執行一次 `rotate-secret-keys`，確認全部解得開。

  第 3 步確認之前，另外保留舊金鑰的備份：萬一有一份沒換到，還能放回舊金鑰再做一次。
- **清除只是邏輯上的**：被取代版本的密文從資料表中清除，但 DB 的舊資料列、WAL 與備份中仍有（受金鑰保護）。secret 外洩時，要到目標系統讓它失效（lab 重新登入換 token）。
- 完整規則見 `docs/API_CONTRACT.md` §16，設計理由見 `docs/DECISIONS.md` §12。

#### 建立 scan（T09）

T09 只開放 `fake` 引擎：它不連任何位址、不啟動容器，結果由 `secscan-admin fake-runner` 產生（`fixture: true`）。`zap`、`nuclei` 在 M3、M4 整合之前回 422 `ENGINE_UNSUPPORTED`。

```bash
cd ~/.config/secscan
umask 077
cat > scan.json <<'JSON'
{"target_id": "<target_id>", "scope_grant_id": "<grant_id>", "api_spec_id": "<spec_id>",
 "auth_profile_id": "<profile_id>", "profile": "api_active_lab", "engines": ["fake"]}
JSON
# Idempotency-Key 必填：每個新的 scan 用一個新的隨機值；網路中斷時以同一個 key 重送，不會建立第二個
curl -H @operator.header -H "Idempotency-Key: $(uuidgen)" -H 'Content-Type: application/json' \
  --data-binary @scan.json http://127.0.0.1:8000/api/v1/scans
# 處理排隊中的 fake run（另一個終端機；DB 設定同 API）
uv run secscan-admin fake-runner
# 查詢狀態與輪詢事件（以最後一個事件的 sequence 當作下一次的 after_sequence）
curl -H @operator.header http://127.0.0.1:8000/api/v1/scans/<scan_id>
curl -H @operator.header 'http://127.0.0.1:8000/api/v1/scans/<scan_id>/events?after_sequence=0'
# 取消：排隊中回 200（cancelled）；執行中回 202（cancelling），runner 確認之後才是 cancelled
curl -X POST -H @operator.header http://127.0.0.1:8000/api/v1/scans/<scan_id>/cancel
```

- **profile**：`api_active_lab` 要有規格（target 是 api 或 hybrid，至少一個 operation 在 grant 的範圍內）；`web_active_lab` 不帶規格（target 是 web 或 hybrid）。省略 `auth_profile_id` 就是未認證的 scan（`auth_role` 是 `anonymous`）。
- **快照**：綁定 grant、規格與 auth profile 目前的版本，並凍結 target 的 origin 與每個 operation 的判斷。之後撤銷 grant、停用 target 或 PATCH profile，排隊中的 scan 在 runner 啟動前就會失敗（例如 `SCOPE_REVOKED`、`AUTH_PROFILE_SUPERSEDED`），不會改用新的設定。
- **Idempotency-Key**：同一個 key、同樣的內容回原本的 scan（未結束 202、已結束 200）；內容不同回 409。範圍是 project，永久保存。
- **上限**：一個 target 同時只有一個進行中的 scan（409 `TARGET_BUSY`）；每個 target 在 24 小時內最多 50 個。
- **fake-runner**：`--outcome fail` 產生失敗的結果、`--hold-seconds 30` 讓它停在 running 30 秒（期間可以試取消）、`--once` 只處理一個。被強制終止（Ctrl-C）時 scan 會停在 running，lease 30 秒過期之後，下一次執行 fake-runner 會把它標成 `interrupted`。
- **coverage**：`eligible_operations` 是建立時在範圍內的 operation 數；`coverage_measured` 一律 false（T12 才量測實際的流量）。
- **DB 逾時**：每個連線有 `DB_STATEMENT_TIMEOUT_SECONDS`（30）、`DB_LOCK_TIMEOUT_SECONDS`（5）、`DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS`（60）；等鎖或查詢逾時回 503 `DEPENDENCY_UNAVAILABLE` 加 `Retry-After`，稍後重試即可。
- 完整規則見 `docs/API_CONTRACT.md` §17，設計理由見 `docs/DECISIONS.md` §13。

#### 隔離 lab 靶場（T03）

需要先啟動 OrbStack（`orb start`）。lab 只接 internal network、不發布任何 port：

```bash
make lab-up                     # 啟動 Juice Shop 與 VAmPI（vulnerable/secure）
make lab-up LAB_PROFILES=vampi  # 只啟動部分（profile：juice-shop、vampi）
make lab-down                   # 停止並移除（若 spike 仍接在 lab_net 上，需先停 spike）
```

工具 spike 的腳本與重現步驟見 `spikes/t03/README.md`，結論見 `docs/TOOLS.md`。只掃 lab，不對外。

#### venv

`make bootstrap` 建立的 `.venv` 是標準的 Python venv，也可以用一般的 venv 方式操作：

```bash
source .venv/bin/activate   # 啟用後可直接執行 python、pytest、mypy
deactivate                  # 離開
```

依賴一律以 `uv add`／`uv remove` 修改，`uv.lock` 會同步更新。`.venv` 裡沒有 pip，請不要用 pip 直接安裝套件，否則環境會和 `uv.lock` 不一致。VS Code 請選用 `.venv/bin/python` 作為直譯器。

## 範圍界線

- **掃描對象**：僅限自有或已獲明確授權的隔離靶場。預設 `LAB_ONLY`，不能因為輸入了一個 URL 或勾選聲明，就取得掃描該網站的授權。
- **展示方式**：沒有前端開發工作，使用 REST API、內建 API 文件、HTTP client 與 JSON/Markdown 報告展示。
- **不列入第一版**：AI 判讀、RAG、白箱原始碼分析、行動 App、全網資產發現、多租戶商用 SaaS、任意工具/模板上傳、自動修補、正式站台掃描。

## 法律提醒

未經授權掃描他人系統，可能觸犯刑法第 36 章妨害電腦使用罪（§358–363）[S30]。

- 只掃描 lab 靶機，或已取得書面授權的目標。
- 不要掃描校園或第三方的系統。
- 不確定時，先請指導教授確認。

## 來源

本文的 `[Sxx]` 對照見 `docs/SOURCES.md`。所有硬體、工期、資料量與驗收門檻都是規劃值，不是已量測結果。
