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

目前完成 M0、M1（T02–T09）與 M2（T10–T13）：
- **M0**：FastAPI 骨架與品質命令（T02）；隔離 lab（`compose.lab.yaml` + `make lab-up`）與三個掃描器經 proxy 的工具 spike（T03，結果見 `docs/TOOLS.md`）。
- **T04**：PostgreSQL 資料層（`compose.yaml`、Alembic migration、repository），第一批資料表 projects、api_keys、audit_events，以及 `GET /health/ready`。
- **T05**：平台 API key（DB 只存 hash、一定會過期、可撤銷）、project 與 object-level 權限、`/api/v1` 的 projects、keys 與稽核查詢端點，以及建立初始管理 key 的本機 CLI `secscan-admin`（見下方「平台 API key」與 `docs/API_CONTRACT.md` §13）。
- **T06**：掃描目標（target）與管理員核准的掃描範圍（scope grant）：origin 的嚴格解析、`LAB_ONLY`／`LAB_CIDR`、pending／approved／revoked／expired 的轉換，以及建立 scan 前要通過的檢查（見下方「掃描目標與授權」與 `docs/API_CONTRACT.md` §14）。
- **T07**：上傳 OpenAPI 3.0 規格（JSON 或 YAML），嚴格解析、拒絕外部參照，`servers` 一律改綁到 target 的 origin；產生 operation inventory，並依 grant 判斷每個 operation 是否在範圍內。另外在 `/api/v1` 前加上驗證之前的 key 格式檢查與請求大小上限（見下方「API 規格」與 `docs/API_CONTRACT.md` §15）。

- **T08**：被測目標的認證設定（auth profile）：bearer、API key header、Cookie 三種，secret 以 MultiFernet 加密、只寫不讀；PATCH 產生新版本並清除上一版的密文；preflight 的定義與驗證；加密金鑰換版的 CLI `secscan-admin rotate-secret-keys`（見下方「認證設定」與 `docs/API_CONTRACT.md` §16）。
- **T09**：建立 scan（Idempotency-Key、不可變的快照、一個 target 同時只有一個進行中的 scan）、以 PostgreSQL `SKIP LOCKED` 認領的工作佇列（lease、心跳、對帳）、run 與 scan 的狀態機、事件輪詢與取消，以及測試用的 fake 引擎與 `secscan-admin fake-runner`；DB 連線加上逾時（見下方「建立 scan」與 `docs/API_CONTRACT.md` §17）。

- **T10**：容器版的 runner 與 worker（`secscan-admin runner`／`worker`）、經 wollomatic socket-proxy 存取 Docker（只放行掃描容器需要的 API）、ExecutionPlan 的驗證與強化的單次容器、target secret 以 0400 檔注入、`GET /api/v1/scanners`，以及 api、runner、worker 的容器化（`make up`）與測試程序連不到 Docker 的隔離（見下方「app stack 與 runner」與 `docs/API_CONTRACT.md` §18）。

- **T11**：egress guard（官方 mitmproxy 映像加上我們的 addon）：每個 run 一組 proxy 帳密與 policy，逐請求檢查 origin、DNS／IP、path、method 與 redirect 之後的請求，拒絕時不建立上游連線；runner 在 guard 不可用時不認領、每條停止的路徑都先封鎖 guard；lab_net 與 scan_net 改由 Makefile 建立（見下方「egress guard」與 `docs/DECISIONS.md` §15）。
- **T12**：scan 共用的預算：guard 強制請求數與速率（超過速率就等待，最多 5 秒）並記錄 telemetry，runner 分配剩下的預算、用盡時停止容器、寫回實際用量；綁定 auth profile 的 scan 先跑 preflight（busybox 經 guard 送出帶認證與匿名的請求，worker 依 `docs/DECISIONS.md` §12.5 判斷）；API 的 `budget_usage`、`auth.preflight` 與 coverage 的量測（見下方「共享預算與 preflight」與 §16）。
- **T13**：runner 中斷之後的收尾：runner 內的 reconciler 依 DB 記下的容器名稱，先封鎖 guard、再刪除孤兒容器，確認之後才把 run 標成 `interrupted`（不永遠停在 running）；啟動時只清理已結算的 run 留下的 policy 與 secret；grant 撤銷或到期、target 停用、建立者的 key 撤銷時停止執行中的 scan；解析重試最多 3 次（見下方「中斷與撤回授權」與 `docs/DECISIONS.md` §17）。

還沒有正式的 Adapter（M3 起）：scan 只能用 `fake` 引擎，它的容器不連任何位址，結果在回應中標為 `fixture: true`，不是真的掃描。其他文件中的指令與 API 仍是**待實作的契約**；`tests/fixtures/` 的真實輸出是給未來 Parser 開發用的樣本，不代表平台已能端到端掃描，也不能把 Mock 當成真實掃描成功的證明。

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
- **加密金鑰**：`make env` 也會在 `.env` 產生三組平台金鑰，各自只交給需要的容器：`SECRET_ENCRYPTION_KEYS`（認證設定的 secret；api、runner）、`EVIDENCE_ENCRYPTION_KEYS`（runs volume 的原始證據；只有 runner）、`CONTENT_ENCRYPTION_KEYS`（報告內容與人工複測摘錄；api、worker）。缺少自己的那一組時程序不會啟動。`make env` 只補上缺少的那一行，不改、不重設、不輪替既有的值，也不在終端顯示金鑰（T23a 之前建立的 `.env` 要再執行一次 `make env` 補上兩組新金鑰）。**請備份這三行**：遺失之後，已保存的 secret、尚未清除的原始證據、報告與摘錄都解不開。換版的做法見下方「認證設定」與「資料保護」。
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

T09 只開放 `fake` 引擎：它不連任何位址、不啟動容器，結果由 `secscan-admin fake-runner` 產生（`fixture: true`）。`zap`（M3、T15）、`nuclei`（M4、T18）已整合；`schemathesis` 在 M6 整合之前回 422 `ENGINE_UNSUPPORTED`。

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
- **快照**：綁定 grant、規格與 auth profile 目前的版本，並凍結 target 的 origin 與每個 operation 的判斷。之後撤銷 grant、停用 target 或 PATCH profile，排隊中的 scan 在 runner 啟動前就會失敗（例如 `SCOPE_REVOKED`、`AUTH_PROFILE_SUPERSEDED`），不會改用新的設定。建立 scan 的平台 key 被撤銷時，它排隊中的 scan 也會失敗（`CREATOR_KEY_REVOKED`）。
- **Idempotency-Key**：同一個 key、同樣的內容回原本的 scan（未結束 202、已結束 200）；內容不同回 409。範圍是 project，永久保存。
- **上限**：一個 target 同時只有一個進行中的 scan（409 `TARGET_BUSY`）；每個 target 在 24 小時內最多 50 個。
- **fake-runner**：`--outcome fail` 產生失敗的結果、`--hold-seconds 30` 讓它停在 running 30 秒（期間可以試取消）、`--once` 只處理一個。被強制終止（Ctrl-C）時 scan 會停在 running，lease 30 秒過期之後，下一次執行 fake-runner 會把它標成 `interrupted`。已經要求取消、runner 卻在確認之前被終止時也是 `interrupted`：沒有確認停止，就不會是 `cancelled`。
- **coverage**：`eligible_operations` 是建立時在範圍內的 operation 數；`coverage_measured` 一律 false（T12 才量測實際的流量）。
- **DB 逾時**：每個連線有 `DB_STATEMENT_TIMEOUT_SECONDS`（30）、`DB_LOCK_TIMEOUT_SECONDS`（5）、`DB_IDLE_IN_TRANSACTION_TIMEOUT_SECONDS`（60）；等鎖或查詢逾時回 503 `DEPENDENCY_UNAVAILABLE` 加 `Retry-After`，稍後重試即可。
- 完整規則見 `docs/API_CONTRACT.md` §17，設計理由見 `docs/DECISIONS.md` §13。

#### app stack 與 runner（T10）

`make up` 以同一個映像啟動 api、runner、worker 與 socket-proxy（compose 的 `app` profile），並建立掃描容器用的 `secscan_scan_net`（internal＋gateway isolated）：

```bash
make migrate                       # db 的 schema（make up 不會自動 migrate）
API_PORT=8765 make up              # 127.0.0.1:8000 被其他服務占用時改用別的 port
docker exec secscan-runner-1 secscan-admin create-admin-key --name 本機管理員   # 或 uv run secscan-admin …
curl -H @admin.header http://127.0.0.1:8765/api/v1/scanners   # fake 是否可用、runner 與 worker 是否存活
make down                          # 停止 app stack 與 db（資料保留在 volume）
```

- **權限分離**：只有 socket-proxy 掛 docker.sock（唯讀），只接 internal 的 docker_net、只接受 runner 連線；api、runner、worker 都非 root、唯讀 rootfs、`cap_drop: ALL`、`no-new-privileges`。`make dev` 仍可在宿主執行 API（開發用，不具這樣的隔離）。
- **掃描容器**：每個 run 一個 `secscan-run-<run_id>`：核准的映像（digest 鎖定，runner 不 pull，`make images` 事先 pull）、uid 10001、唯讀、只接 scan_net、只掛該 run 的 volume subpath；有 auth profile 時 secret 是 `/scan/secret/target-auth`（0400，容器刪除後就刪除）。
- **fake 的腳本**：`RUNNER_FAKE_OUTCOME=fail`、`RUNNER_FAKE_HOLD_SECONDS=30 make up`（容器停留 30 秒，可以試取消：5–6 秒內刪除容器）。
- **in-process 的 fake-runner** 仍可在宿主使用（不需要 Docker）；它和容器版的 runner 都會認領 fake，擇一執行。
- **live 測試**：`ENABLE_LIVE_LAB_TESTS=1 make test-live-runner` 在獨立的 compose 專案（自己的 DB、網路與 volume，API 綁 127.0.0.1:8765）中建立、測試、一律拆除；T11 起在 live 自己的 lab 網路（10.89.10.0/24）上啟動接收端，不啟動 Juice Shop、VAmPI。需要 OrbStack。
- `secscan_scan_net` 與 T03 spike 的網路同名：執行 spike 前先 `make down`，並刪除這個網路。
- 完整規則見 `docs/API_CONTRACT.md` §18，設計理由見 `docs/DECISIONS.md` §14。

#### egress guard（T11）

`make up` 一併啟動 guard（`secscan-guard:dev`，`make build` 建立），它只接 `secscan_scan_net` 與 `secscan_lab_net`，固定在兩個網段的最後一個位址（10.89.8.254、10.89.7.254），只在 scan 那一側的 8080 聽。

- **掃描容器**：拿到 `/scan/secret/proxy-url`（0400，`http://<run_id>:<token>@10.89.8.254:8080`），只能經 guard 連到 grant 核准的 target origin；被擋下的請求回 403（`X-Secscan-Guard: <原因>`）或 407（帳密）。ZAP 以 0400 的 `zap.properties`（`-configfile`）使用同一組帳密（T14）；Nuclei 以 `-p /scan/secret/proxy-url` 從同一個檔案讀 proxy（T18，不上命令列）。
- **guard 不可用時**：`GET /api/v1/scanners` 顯示 `GUARD_UNAVAILABLE`，runner 不認領；執行中斷掉的 run 標成 `interrupted`。`docker logs secscan-guard-1` 是每個請求的決定（不含 header 的值、query 與 token）。
- **保留的位址**：`LAB_CIDR` 的最後一個主機位址（預設 10.89.7.254）保留給 guard，target 與 grant 都不能用。
- **telemetry**：guard 在 `secscan_guard_telemetry`（tmpfs）為每個 run 寫 summary 與每個轉送請求一行的 jsonl（不含 query 與 header 的值），runner 與 worker 唯讀；6 小時後刪除。

#### 共享預算與 preflight（T12）

- **預算**：scan 的 `max_requests`、`max_duration_seconds` 與速率由所有 run 共用（preflight 也算）。用盡時 guard 回 403（`BUDGET_EXHAUSTED`），runner 停止容器，run 是 `timed_out`；還沒開始就用完是 `failed`。`GET /api/v1/scans/{id}` 的 `budget_usage` 是 guard 實際的計數。
- **preflight**：綁定 auth profile 的 scan，第一個 run 是 `preflight`（不能在請求中指定）。結果在 `auth.preflight`：`passed` 才把以認證取得的回應算進 `coverage.authenticated_operations`；`inconclusive` 代表匿名的請求也符合（或沒有對照），證明不了認證有效。in-process 的 `secscan-admin fake-runner` 不送流量，結果一律 `not_executed`。
- **重建 T10 以前建立的網路**：舊的 `secscan_scan_net`、`secscan_lab_net` 沒有 `--ip-range`，`make scan-net`／`make lab-net` 會失敗並提示。先停掉使用它們的服務，再刪除重建：

  ```bash
  make down && make lab-down
  docker network rm secscan_scan_net secscan_lab_net
  make scan-net lab-net
  ```

- 完整規則見 `docs/API_CONTRACT.md` §18，設計與實測見 `docs/DECISIONS.md` §15。

#### 中斷與撤回授權（T13）

- **runner 中斷**：runner 被 kill 時，guard 最晚在 lease 到期（30 秒）時拒絕孤兒容器的請求。runner 重啟之後（以及每 10 秒）對帳：先把 policy 改成 blocked、刪除容器，確認之後 run 與 scan 才是 `interrupted`（`LEASE_EXPIRED`），同一個 target 就能再建立 scan。這個 run 的用量不明，同一個 scan 之後的引擎以 `BUDGET_EXHAUSTED` 失敗（保守）。Docker 不可用時 run 保持 running，等 Docker 恢復。
- **撤回授權**：撤銷 grant、停用 target 或撤銷建立 scan 的平台 key，執行中的 scan 在下一次心跳停止（通常 5 到 7 秒內），run 是 `failed`（`SCOPE_REVOKED`、`TARGET_DISABLED`、`CREATOR_KEY_REVOKED`）。
- **`GET /health/ready`**：只檢查 DB 與 schema；runner、worker、guard 的狀態看 `GET /api/v1/scanners`。
- 設計見 `docs/DECISIONS.md` §17；錯誤碼見 `docs/API_CONTRACT.md` §17.2。

#### ZAP 的執行（T14、T15）

`POST /api/v1/scans` 指定 `zap` 時（T15 開放），runner 以強化的單次容器執行 ZAP，worker 解析輸出、結果入庫，以 `GET /api/v1/scans/{id}/observations` 查詢。

- **映像**：`make images` 以 digest pull `zaproxy/zap-stable` 2.17.0（約 1.2 GB）。
- **capability probe**：runner 啟動之後以和掃描相同的設定實際執行一次 ZAP（約 15 秒，不送任何請求），確認版本、必要的 add-on 與規則白名單；`GET /api/v1/scanners` 的 zap 顯示 `version`。probe 期間 fake 照常處理。
- **plan**：由伺服器產生，ZAP 以 `-silent` 執行。`web_active_lab` 從 `/` 開始 spider（grant 必須允許 `GET /`），`api_active_lab` 只匯入 grant 範圍內的 operation；active scan 只跑審查過的規則（`docs/TOOLS.md` §7），grant 不允許 POST 時，會把請求改成 POST 的規則也不執行。
- **認證**：以 `ZAP_AUTH_HEADER*` 環境變數交給 ZAP（bearer、`api_key_header`、cookie 都是一個 header），值不在 plan、Docker 的設定或 log 中；沒有 auth profile 的 scan 是 anonymous。
- **輸出**：`runs/<run_id>/out/` 的 `zap-report.json` 與 `zap.log`（已遮罩這個 run 的 secret 與 proxy 的 token）；manifest 記下 ZAP 的退出碼、輸入的 hash 與遮罩的次數。
- **結果（T15）**：
  - 退出碼不等於結果：`GET /api/v1/scans/{id}` 的 `engines[].status`、`error_code` 與 `result` 分得出成功（0 個觀察就是乾淨的結果）、ZAP 回報錯誤（`ENGINE_REPORTED_ERRORS`，部分結果保留）、未掃到端點（`NO_TARGET_TRAFFIC`）、輸出不能用（`OUTPUT_INVALID`）與時間到（`ENGINE_TIMEOUT`，觀察保留）。
  - 不是目標的回應（guard 的拒絕、proxy 的錯誤頁）與不在範圍內的告警不會入庫，只計數在 `result.excluded`。
  - 觀察是工具的單次回報，等級是工具的原始值；T19 起 worker 在解析之後把觀察連結到 finding（見下方「Finding（T19）」）。
  - `GET /api/v1/scan-profiles` 列出現在可以用的 profile 與規則定義的 hash。
- **版本與流量（T16）**：每個引擎的 `plan_hash`（實際執行的 plan 的 sha256）與 `profile_definition_sha256`（zap 的規則定義）在 runner 建立容器之前寫入，不收集的 run 也有；`result.guard_traffic` 保存 guard 的轉送數、各原因的拒絕數與帶認證的請求被接受／拒絕的數量（guard 的 telemetry 6 小時後刪除，這裡留著）。
- **憑證失效（T16）**：掃描中途 token 過期時（同一個 operation 先接受、最後被拒絕，或 auth profile 的 preflight 端點被拒絕），coverage 的 `limitations` 有 `AUTHENTICATION_LOST`；平台不重新登入。
- **live 測試**：`ENABLE_LIVE_LAB_TESTS=1 make test-live-zap`（約 13 分鐘；只掃 live lab 網路上的小型網站）；`ENABLE_LIVE_LAB_TESTS=1 make test-live-lab`（約 27 分鐘；Juice Shop 與 VAmPI，結果見 `docs/TOOLS.md` §7.7）；`ENABLE_LIVE_LAB_TESTS=1 make test-live-fixture`（自製的 fixture app 弱點版與修補版，量測 ground truth，結果見 `docs/TOOLS.md` §7.8）；`ENABLE_LIVE_LAB_TESTS=1 make test-live-fixture-nuclei`（同一個 fixture app，改以真的 nuclei 掃，約 8 分鐘）。
- 設計見 `docs/DECISIONS.md` §18、§19、§20；量測與規則的審查見 `docs/TOOLS.md` §7。

#### Nuclei 模板凍結與整合（T17、T18）

M4 的第一步 T17 只凍結「清單與執行設定」；**T18 已把 Nuclei 整合進引擎管線（Adapter、JSONL parser、真實 e2e）**，`nuclei` 現可受理（`schemathesis` 仍回 422）。

- **凍結清單**：`src/secscan/scanners/domain/nuclei/templates.lock.txt`（42 個精選、對準 lab 的純 HTTP 模板，每行 `id sha256 path`；多協定／會改 Host 的模板由內容閘門排除）；policy 與執行旗標在同目錄的 `policy.py`。
- **產生**：`make nuclei-templates`（需要 OrbStack）驗證鎖定 archive 的 sha256、在鎖定映像裡**離線**（`--network none`）跑 `nuclei -tl` 列舉、算每檔 sha256，寫出 lock。**不連任何目標、不出網**。`make nuclei-templates-check` 逐位元組重現驗證。
- 選取方式、逐類別審查與高風險抽查見 `docs/TOOLS.md` §2.1、`docs/DECISIONS.md` §23。
- **T18 整合**：`scanners/domain/nuclei/{plan,results}.py`（匿名掃描、proxy 從 `/scan/secret/proxy-url` 讀、`-dut`、42 模板以 InputFile 掛載並逐檔 sha256 驗證）、`worker/nuclei.py`、引擎註冊與 migration v0012；parser 以 `X-Secscan-Guard` 濾掉 guard 的合成 403、兩層遮罩輸出。真實 e2e 見上（弱點版 `cors-misconfig` 命中、修補版不命中）。設計見 `docs/DECISIONS.md` §24。

#### Finding（T19、T20）

observation 是不可變的單次觀察；finding 是 target 層級、跨掃描的議題（`src/secscan/findings/`）。worker 解析入庫之後，在一個 transaction 中把觀察連結到 finding（冪等，中斷之後重試只補上沒有連結的）。

- **語意規則群組**：`src/secscan/findings/taxonomy/rule_groups.yaml`（人工審查、有版本、sha256 執行期釘選；2026-11-04 使用者簽核後是 v2）。一個群組只有一個引擎；跨引擎只有 CSP、X-Content-Type-Options、anti-clickjacking 三個 header 群組：以 ZAP 的條件為準，nuclei 在同一次 scan、同一個位置有 ZAP 的觀察時才併入。CORS 兩個工具偵測的行為不同，只標示相關。對不到的觀察是單一引擎的 `engine:rule[:variant]`、`unclassified`、標 `needs_review`。審查紀錄見 `docs/TOOLS.md` §8。
- **分類**：security 分 vulnerability 與 misconfiguration，informational 分 technology、detection、hardening；人工 triage 之前都不是已驗證的漏洞。技術識別以 `群組/技術名` 各自一個 finding，和 security 分開統計。
- **fingerprint**（v2）：target、kind、群組、method、route（有規格時剛好一個最具體的 operation 才用樣板）、參數位置與名稱、auth role 與身分是否驗證過；route 是樣板時，沒有審查過的規則另外以字面 path 區分物件。標題、證據、等級、query、工具的 CWE 都不影響。去重的反例（同 CWE 不同參數、同 route 不同身分或物件、不同的弱點）與合併的對照組在 `tests/unit/findings/test_dedup_counterexamples.py` 與真實錄製的契約測試。
- **等級**：各來源正規化之後的最高值，來源數本身不加分；來源不一致時 `severity_conflict`。兩個工具同時命中不是人工確認。
- **OWASP**：Top 10:2025 依官方的 CWE 清單（`make owasp-top10` 從鎖定 commit 的官方分類頁凍結成 `findings/taxonomy/owasp_top10_2025.json`，`make owasp-top10-check` 逐位元組重現；不連網）；API Security Top 10:2023 是 curated。每個 finding 記下對應的來源與版本。
- **API**：`GET /api/v1/scans/{scan_id}/findings`（分頁，可依 kind、category、severity、engine、triage_state、lifecycle_state、needs_review 篩選；sources 只有這個 scan 的來源；另給原始 CWE、未對應的原因與相關的 finding）。triage 見下方 T21。
- **來源追溯**（T20）：`GET /api/v1/findings/{id}`（有上限的摘要與近期 5 次 scan）、`/findings/{id}/scans`（完整的歷史，每個 scan 列出所有 run）、`/findings/{id}/observations`（連結當時的值 → 遮罩後的觀察 → 報告 artifact 的 metadata → run 的映像、plan_hash 與版本；不輸出 storage_key）。連結有 DB 指定的序號，帶回 `as_of` 翻頁時集合固定；DB 另外檢查觀察、finding 與 first／last seen 的 scan 屬於同一個 target（migration v0015）。
- **live 測試**：`ENABLE_LIVE_LAB_TESTS=1 make test-live-fixture-findings`（同一個 scan 跑 ZAP 與 Nuclei，掃 fixture app 的弱點版與修補版，並以追溯 API 驗證每個觀察的來源；另跑小時間預算的部分失敗情境，約 25 分鐘）。
- 設計見 `docs/DECISIONS.md` §25、§26；API 見 `docs/API_CONTRACT.md` §9、§17.9、§17.10。

#### 複掃比較（T22）

- `POST /api/v1/scan-comparisons`：operator/admin 提交 `baseline_scan_id`、`current_scan_id`。兩次 scan 必須屬於同一 target、已終止且依建立序號排列；新快照回 201，重複建立回 200。兩側都做 project 授權。
- `GET /api/v1/scan-comparisons/{comparison_id}`：摘要、差異理由、分類數量、人工確認提示；同專案 viewer 可讀。
- `GET /api/v1/scan-comparisons/{comparison_id}/findings`：不可變逐 finding 證據摘要，支援 `classification`、`page`、`limit`；後續 scan 不改變舊比較。
- **not_observed 不等於已修補**，比較不修改生命週期。位置有回應、規則完整執行、身分／參數可比缺一不可；目前實測尚無足夠的規則完成證據，因此真正的單側未命中維持 inconclusive 或 not_comparable，而非假稱驗證修補；也因此這一版不計算「自動驗證修補成功率」。
- 新位置表只保存 path 的 SHA-256 相等性索引，不是加密；不保存參數名稱或值，比較 API 不輸出 path/digest 或 raw evidence。原始輸出的加密與保留期限見下方「資料保護（T23a）」；觀察保留遮罩過的證據、不加密。
- `X-ZAP-Scan-ID` 是內部保留 header，不接受新的目標認證設定；舊 profile 可讀取、換金鑰及修復，但不能用來掃描。Nuclei matcher error 會標示引擎失敗，不把零告警當成完整成功。
- `ENABLE_LIVE_LAB_TESTS=1 make test-live-fixture-rescan LIVE_PYTEST_ENV="SECSCAN_RECORD_DIR=$PWD/recordings/fixture-rescan/run-name"`：同一隔離 target 的弱點→弱點、弱點→修補、小預算複掃。每次把 `run-name` 換成尚未存在的目錄；既有目錄或檔案會被拒絕，不覆寫歷史量測。不與其他 live 指令同時執行。結果在 gitignore 的 `recordings/fixture-rescan/`。三次有效校準與最終執行都通過（每次約 32 分鐘）：弱點→弱點、弱點→修補皆 comparable，小預算需人工確認；new／not_observed 一律為 0；已自動對應的 6 個修補案例（20 個 finding）都是 inconclusive，另 6 個案例沒有自動對應、未逐一驗證。細節見 `DECISIONS.md` §27.14。
- v0016 升級保留既有 run 的未知 provenance，不回填；downgrade 會刪除新快照／位置／版本資料，僅供已備份的開發測試 DB。
- 契約見 `docs/API_CONTRACT.md` §17.11，決策與實測見 `docs/DECISIONS.md` §27，反例見 `docs/SECURITY_AND_TESTING.md` §4.3 的 RESCAN 表。

#### 人工 triage、audit 與報告（T21）

- **resolved 一律是人工判定，平台不提供自動修補驗證。** `PATCH /api/v1/findings/{id}/triage` 一次改一個欄位，必帶 `expected_version` 與 `reason`；resolve 必須引用同一個 target 的比較快照：
  - `basis: rescan_not_observed`：該列是 not_observed。比較演算法 v1 不會產生 not_observed，**現行版本不可用**。
  - `basis: manual_retest`：該列是 inconclusive、平台證據都成立，另附人工複測聲明（`attestation`）。平台只做一致性檢查（route、Host、參數、狀態列、身分、時間），**不驗證摘錄的真實性**；不要貼上憑證。
  - 比較快照不會被修改；resolve 之後較新的 scan 以相同的 fingerprint 與 mapping 又觀察到時自動重開。
  - 「人工判定」指的是以 operator/admin 的 API key 送出的 PATCH：平台分不出送出者是人還是自動化的 client，問責的對象是 key 與它的持有者（事件與 audit 記下 key 與 request_id）。
- `GET /api/v1/findings/{id}/triage-events`：不可修改的事件；摘錄內容只給 operator/admin。
- 報告：`POST /api/v1/scans/{id}/reports`（必帶 `Idempotency-Key`、scan 必須已終止，回 202）→ worker 產生 → `GET /api/v1/reports/{id}/download`（只能以 report id 下載平台產生的報告；JSON 或 Markdown，≤ 8 MiB，超過時截斷並標示）。工具的原始輸出不提供下載。
- 管理檢視（platform_admin）：`GET /api/v1/audit-events`、`GET /api/v1/scope-grants/pending`；`POST /api/v1/auth-profiles/{id}/disable` 停用認證設定（終止狀態）。
- 資料保護：T23a 起報告內容與人工複測摘錄在 DB 中加密、30 天後清除（見下方「資料保護（T23a）」）。
- Gate D（去重、複掃與報告的驗收）2026-11-08 通過，採用有文件記錄的替代證據：partially_completed 與 timed_out 的報告由兩次 Live 複掃驗證；completed 的報告由 DB 整合測試驗證（真實的 API、worker、渲染與下載，合成的觀察），**沒有 completed 的 Live 端到端驗證**。Gate D 通過不代表 M5 或資料保護已完成（`docs/DECISIONS.md` §28.17）。
- migration v0017–v0019；契約見 `docs/API_CONTRACT.md` §19，決策見 `docs/DECISIONS.md` §28，反例見 `docs/SECURITY_AND_TESTING.md` §4.3 的 TRIAGE／REPORT 表。

#### benchmark harness 與引擎子預算（T31，進行中）

- **引擎子預算**：多引擎的 scan 可以在建立時選填 `engine_budgets`，凍結每個引擎的 `max_requests`、`max_duration_seconds`。每個 run 取「scan 剩下的」與「這個引擎的上限」的較小值，沒用完的份額作廢、不轉給後面的引擎；只會讓配額變小，總額與 guard 的強制不變。省略時行為和之前相同。`engines[].budget` 列出上限，`engines[].usage` 列出每個 run 分到的配額與 guard 計數（被 runner 停止、沒有收集的 run 也有）。migration v0020。
- **harness**（`benchmarks/`，不進 wheel）：只吃平台 API 的 JSON。實驗規格（`benchmarks/experiments/*.yaml`）只能指定 fixture、juice_shop、vampi 三種靶場，所有組別共用同一份總預算；排程由種子決定；`evaluate.py` 是純函式（recall 以案例、precision 以議題計，分母為 0 或還有未裁定的 finding 是 N/A）。
- `make bench-check BENCH_SPEC=… BENCH_NAME=…`：離線檢查規格與結果目錄的名稱。
- `ENABLE_LIVE_LAB_TESTS=1 make bench BENCH_SPEC=benchmarks/experiments/t31-smoke.yaml BENCH_NAME=<新名稱>`：先做上面的檢查，再以 `test-live-runner` 的同一個隔離 stack 與清理範圍經 API 跑完排程，結果寫到 gitignore 的 `benchmarks/results/<新名稱>/`（0700／0600、不覆寫、寫入前檢查秘密；T23a 起以本機的 bench 金鑰加密，見下方「資料保護（T23a）」）。不自動重試；環境故障整批作廢、換新名稱重跑。**T31 的 Live smoke 尚未執行（需要另外授權）**，Juice Shop、VAmPI 的路徑要到 T28 才第一次執行。
- `make bench-evaluate BENCH_NAME=… BENCH_TRUTH=<ground truth>`：離線、只讀結果目錄，評估以 JSON 寫到 stdout（另有選填的 `BENCH_ADJUDICATIONS`、`BENCH_PAIR_LABELS`、`BENCH_INCLUDE_HOLDOUT`）。正式的 ground truth 比對檔與預算由 T27 凍結；smoke 的數字不是實驗結果。
- 決策見 `docs/DECISIONS.md` §29，契約見 `docs/API_CONTRACT.md` §17.1，測試見 `docs/SECURITY_AND_TESTING.md` §4.3 的 BUDGET／BENCH 表。

#### 資料保護（T23a）

T23a 已完成（2026-11-12）：兩項 Live 與 worker 的掛載檢查都通過，見 `docs/DECISIONS.md` §30.13 的「Live 驗收」與 §30.14。**SEC-14 仍未完成**，P0 的完成條件見 §30.14。設計見 `docs/DECISIONS.md` §30，測試見 `docs/SECURITY_AND_TESTING.md` §4.3 的 KEY／SEAL／EVID／CONT／RET／ROT／BSEAL 表，剩餘風險見同一份文件的 §8。

- **原始證據（runs volume）是 run 結束之後才加密，不是全程靜態加密**：掃描、收集與等待解析期間是明文。run 結束（解析完成、失敗或逾期）、容器確認刪除之後，runner 的背景執行緒在約 10–20 秒內把目錄加密成 `sealed/`、驗證之後才刪除明文，7 天後刪除整個目錄。worker 停擺時，等待解析超過 60 分鐘的 run 以 `PARSE_DEADLINE_EXCEEDED` 結束並加密。加密失敗時明文保留、API 顯示 `pending`，runner 不認領新的 run（`GET /api/v1/scanners` 顯示 `EVIDENCE_SEALING_FAILED`）。
- **API**：`GET /api/v1/scans/{id}` 的 `engines[].evidence`（none／pending／sealed／purged／manual_intervention_required，以及隔離紀錄 `hold`）；finding 來源追溯的 artifact 有 `encrypted`、`purged_at`。原始輸出沒有下載 API。
- **報告與摘錄**：寫入 DB 之前加密，30 天後清除內容：報告下載回 410 `REPORT_EXPIRED`，摘錄的 `content` 變成 null；metadata 與 sha256 保留。
- **升級**：`make migrate`（v0021、v0022、v0023）之前先 `make down` 停 api、worker 與 runner，再以 `make db-up` 只啟動資料庫（v0021 建立外鍵時會鎖住 `scanner_runs`，兩個 migration 在同一個 transaction 中執行）。既有的報告與摘錄在升級時加密，期限是升級時間加 30 天。
- **runs volume 的 layout**（`docs/DECISIONS.md` §30.13）：runs volume 分成 `active/`（一般的 run 目錄；worker 只以 subpath 唯讀掛載這裡）與 `held/`（隔離的目錄；worker 讀不到）。`make up` 先執行一次性的 `runs-init` 檢查 layout，舊的 layout 時 runner 與 worker 不啟動。既有的開發 volume 依序升級：`make down` → `make db-up` → `make migrate`（v0024）→ `make runs-layout-migrate DRY_RUN=1`（只列出計畫）→ `make runs-layout-migrate` → `make up`。搬移指令以和 `make up` 相同的設定解析實際的 volume、確認 compose 的標籤與沒有任何容器使用它，才在 runner 容器內搬移；可以重跑。如果 runner 曾經異常結束、留下容器還沒確認刪除的 run，搬移會拒絕，依下面的人工修復處理。降級之前要先把 `active/` 的目錄搬回根目錄、刪除 `.layout`。
  **runner 異常結束之後的人工修復**（OOM、kill -9、Mac 睡眠讓 OrbStack 停止回應之後，`make runs-layout-migrate` 回報「容器還沒確認刪除」時）：搬移指令不刪紀錄、不略過檢查，必須先讓 runner 對帳（Docker 確認容器已刪除，或刪除這個 run 的容器，才結算）。新版的 runner 在舊的 layout 上不會啟動，而舊版的 runner 只接受 0023 的 schema，所以：
  1. `make down`。
  2. `uv run alembic downgrade 0023`：只有沒有 v0024 的隔離資料、也沒有執行過 layout 搬移時才會成功（搬移指令在寫入任何東西之前就拒絕，所以這時會成功）；被拒絕就停止，改為人工確認，不要強制降級。
  3. 切回升級之前的版本（例如 `git switch --detach 61a5cd3`），先確認沒有排隊中的 scan（舊版的 runner 會認領它們），再 `make up`；runner 啟動時就對帳，log 出現「容器已確認不存在：已結算」。Docker 不可用時不會結算，先修復 Docker。
  4. `make down`，切回新的版本，`make migrate`，再執行 `make runs-layout-migrate DRY_RUN=1`：它會再檢查一次；仍有未確認的容器就重複第 1 到 4 步。
  5. `make runs-layout-migrate`，`make up`。**機密性隔離的 Docker 實際驗證（2026-11-11，獨立的測試環境，`held/` 中有隔離的資料）與 Live 驗收（2026-11-12）都已通過。**全新、空的 runs volume 不需要搬移，`runs-init` 會直接建立新的 layout。
- **保留期限**（1–365 天，`.env` 中可調整）：`EVIDENCE_RETENTION_DAYS`（預設 7）、`REPORT_RETENTION_DAYS`（30）、`EXCERPT_RETENTION_DAYS`（30）；`EVIDENCE_PLAINTEXT_MAX_MINUTES`（預設 60）是等待解析的上限。既有的資料從升級之後才開始計時，升級不會立刻刪除任何東西。刪除只是 unlink，不抹除磁碟的資料區塊；DB 的 WAL 與備份會保留舊資料。
- **管理指令**（`docs/API_CONTRACT.md` §20）：
  - `uv run secscan-admin check-encryption-keys`：檢查三組金鑰合法、互不共用，只顯示數量。
  - `uv run secscan-admin retention-status`：各狀態的數量；隔離的各階段，隔離未完成（明文仍在 `active/`）超過 15 分鐘的列為需要緊急處理（主動告警是 T35）；以及需要人工處理的目錄（數量、錯誤代碼、最早的 10 個目錄名稱；唯讀）。
  - `uv run secscan-admin rotate-content-keys`：報告與摘錄的換版。
  - `docker compose --profile app exec runner secscan-admin rotate-evidence-keys`：原始證據的換版（只有 runner 容器有這組金鑰）。
  - `docker compose --profile app exec runner secscan-admin export-evidence --run <id> [--path <路徑>]`：break-glass，列出加密檔，或先寫 audit 再把一個檔案的明文寫到 stdout。
  - `docker compose --profile app exec runner secscan-admin retry-evidence --directory <目錄名稱> --reason <理由> [--max-depth N] [--max-entries N] [--max-path-chars N]`：人工處理 `retention-status` 列出的「需要人工處理」目錄（超過深度、條目數或路徑總長度的上限、連續 3 次加密失敗而被隔離，明文保留）；keeper 先把隔離的目錄搬到 `held/`；這個指令先寫 audit，在 `held/` 以指定的上限（最多深度 64、條目 50,000、路徑總長度 16M 字元）加密並逐一驗證，再搬回 `active/`、再驗證，才解除隔離。中斷之後再執行一次就從正確的步驟繼續。沒有不加密就解除或刪除目錄的指令（`docs/DECISIONS.md` §30.12、§30.13）。
- **換版**：新金鑰放在那一組的最前面（逗號分隔）→ 重啟持有它的容器 → 執行換版 → 移除舊金鑰、重啟 → 再換版一次確認全部解得開；確認之前保留舊金鑰的備份。
- **bench 結果**：`make bench-key` 建立本機的金鑰檔（預設 `~/.config/secscan/bench-keys`，可用 `BENCH_KEY_FILE` 指定；不可放在 repo 中；已經存在就失敗、不覆寫）。之後 `make bench` 寫出的每個檔案都是 `<名稱>.sealed`，`bench-evaluate` 先核對 `SHA256SUMS`、解密、再核對明文的 sha256 才評估。T23a 之前的明文結果目錄以 `make bench-seal BENCH_SOURCE=<原目錄> BENCH_NAME=<新名稱>` 轉成新的加密目錄，原目錄不修改也不刪除。**金鑰檔遺失之後結果無法復原，請另外備份。**

#### 隔離 lab 靶場（T03）

需要先啟動 OrbStack（`orb start`）。lab 只接 internal network、不發布任何 port：

```bash
make lab-up                     # 啟動 Juice Shop 與 VAmPI（vulnerable/secure）；先以 make lab-net 建立 lab_net
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
