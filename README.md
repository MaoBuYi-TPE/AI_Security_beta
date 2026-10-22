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
| `docs/API_CONTRACT.md` | REST API、權限、資料格式與錯誤語意；§13 是 T05 已實作的 key、專案與權限，§14 是 T06 已實作的 target 與 scope grant |
| `docs/SECURITY_AND_TESTING.md` | 平台自身的安全要求、測試矩陣與實驗設計 |
| `docs/TASKS.md` | 依里程碑排列的工作、依賴、驗收條件與降階方案 |
| `docs/START_HERE.md` | 開發順序，以及給 Claude Code 的第一段任務提示 |
| `docs/DECISIONS.md` | 兩份規劃的比較與設計取捨，可作為報告素材 |
| `docs/SOURCES.md` | 已查核的一手技術文件與引用對照 |

## 使用方式

先閱讀 `docs/START_HERE.md`，再依 `docs/TASKS.md` 的順序開發。根目錄使用大寫檔名 **`CLAUDE.md`**。[S01]

目前完成到 M1 的 T06：
- **M0**：FastAPI 骨架與品質命令（T02）；隔離 lab（`compose.lab.yaml` + `make lab-up`）與三個掃描器經 proxy 的工具 spike（T03，結果見 `docs/TOOLS.md`）。
- **T04**：PostgreSQL 資料層（`compose.yaml`、Alembic migration、repository），第一批資料表 projects、api_keys、audit_events，以及 `GET /health/ready`。
- **T05**：平台 API key（DB 只存 hash、一定會過期、可撤銷）、project 與 object-level 權限、`/api/v1` 的 projects、keys 與稽核查詢端點，以及建立初始管理 key 的本機 CLI `secscan-admin`（見下方「平台 API key」與 `docs/API_CONTRACT.md` §13）。
- **T06**：掃描目標（target）與管理員核准的掃描範圍（scope grant）：origin 的嚴格解析、`LAB_ONLY`／`LAB_CIDR`、pending／approved／revoked／expired 的轉換，以及建立 scan 前要通過的檢查（見下方「掃描目標與授權」與 `docs/API_CONTRACT.md` §14）。

還沒有規格上傳、認證設定、掃描任務等其他業務 API（T07 起），也還沒有 runner 或正式的 Adapter／egress guard（M2 起）。其他文件中的指令與 API 仍是**待實作的契約**；`tests/fixtures/` 的真實輸出是給未來 Parser 開發用的樣本，不代表平台已能端到端掃描，也不能把 Mock 當成真實掃描成功的證明。

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

- **密碼**：都在 `.env`（權限 600，不進 git）。`make env` 只會補上缺少的隨機值，不會覆寫既有的值；`db-up`、`test-db-up`、`test` 會自動呼叫它。
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
- 建立 scan 的 API 在 T09；規則、錯誤碼與範例見 `docs/API_CONTRACT.md` §14，設計理由見 `docs/DECISIONS.md` §10。

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
