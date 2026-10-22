# 開發任務清單

所有項目初始都是未完成。標記完成時，必須附上實作檔案、實際測試結果與尚未涵蓋的限制；不能因為文件描述過就勾選。

- 時程：1 人開發，2026/10/16 – 2027/06/30（約 37 週）。
- 日期是規劃值，可以依學校行事曆調整；調整後要同步更新 `PROJECT_PLAN.md` §10。
- 任務編號沿用原稿（T01–T29），整合版新增的任務從 T30 開始編號。

## M0｜10/16 – 11/08：範圍、骨架與可行性

- [x] T01 凍結題目、P0/P1、研究問題與排除項目。
  - 產出：需求摘要與待驗證假設；訪談 2–3 位開發者為選做。
  - DoD：能清楚說明相對於手動使用工具，本系統增加了什麼；沒有任何自訂前端任務。
  - 交付（2026-10-17，done）：
    - 產出 `docs/REQUIREMENTS.md`，內容包括題目、與手動使用工具的比較表（每列附驗證方式）、P0/P1/不做、RQ1–RQ3，以及 H1–H5 與各自的驗證時點。題目已經指導教授確認。
    - DoD 檢查：以 `grep -n "前端"` 檢查所有文件，出現的地方都是排除項目、限制，或「日後若要做前端」的檢討條件（`DECISIONS.md` §2、§6），沒有任何前端任務。
    - 未執行：訪談（選做），不影響 P0；時間允許時再補。
- [x] T02 建立 Python 專案與品質命令。
  - 產出：
    - pyproject.toml、uv.lock、.env.example
    - Makefile：bootstrap、dev、test、lint、typecheck（`lab-up` 移到 T03，與 `compose.lab.yaml` 一起建立）
    - 最小的 `src/secscan/main.py` 與健康端點
    - 品質工具：pytest（含 coverage 門檻）、ruff、mypy、import-linter、pre-commit
  - DoD：在乾淨環境能啟動健康端點，並實際跑過 test、lint、typecheck；README 中的指令都有效。
  - 交付（2026-10-17，done）：
    - 檔案：`pyproject.toml`、`uv.lock`、`.python-version`、`.env.example`、`Makefile`、`.pre-commit-config.yaml`、`src/secscan/`（`main.py`、`core/`、`health/`）、`tests/`。依賴由 uv 實際解析，例如 Python 3.12.6、fastapi 0.143.3、pydantic 2.14.1、pytest 9.1.1、mypy 2.4.0、ruff 0.17.1；完整版本見 `uv.lock`。
    - 實際執行：先寫測試並確認失敗（`ModuleNotFoundError`），實作後才通過。`make test` 35 passed、coverage 100%（含分支）；`make lint`、`make typecheck`、`pre-commit run --all-files` 都通過。
    - 負向檢查：core import 功能模組，或新增未列入 layers 的模組時，import-linter 都會失敗；測試中建立 TCP socket 會被封鎖。
    - 啟動與重建：`make dev` 只監聽 127.0.0.1:8000，`/health/live` 回傳 envelope。從分支重新 clone 後，bootstrap、test、lint、typecheck 全部通過。
    - code-reviewer 結果是 APPROVE（0 CRITICAL、0 HIGH），MEDIUM 與 LOW 項目已修正；Docker socket 的測試防護記在 T10。
    - 未做：`/health/ready`（需要 DB，M1/T04）；統一錯誤 handler 與 request_id（M1，目前 404 仍是 FastAPI 預設格式）；structlog。
    - 後續調整：Starlette 1.8 已棄用 TestClient 搭配 `httpx`，因此改用 `httpx2` 2.13.1（只影響開發依賴）。改用後棄用警告消失，TestClient 回應的型別也從 `Any` 恢復成 `Response`，mypy 能檢查測試程式。
    - 已知限制：`/docs` 會從 CDN 載入 Swagger UI，M1 有平台 API key 後需要重新評估。
- [x] T03 確認掃描器映像、模板與實驗網路。
  - 前置：啟動 OrbStack，確認 `docker compose` 可用（不行就改用 `docker-compose`）。uv 已在 T02 安裝。
  - 產出：
    - 工具相容性表：名稱、版本、digest、arm64 支援、授權條款、必要的可寫路徑、唯讀 rootfs 相容性、proxy/auth/output 相容性。
    - lab compose：Juice Shop、VAmPI vulnerable/secure，只接 internal network；同時建立 `make lab-up`（從 T02 移過來）。
  - 做法：用一個暫時的 mitmproxy 讓三個工具都經 proxy 掃描 lab。把真實輸出錄到 `tests/fixtures/<tool>/`，並量測各工具的請求量與耗時，作為之後調整預算的依據。
  - 需要逐項確認：
    - ZAP 的 upstream proxy 設定鍵與 report 格式
    - Nuclei `-sf` 檔案格式，以及經 proxy 時的 DNS 行為
    - Schemathesis `--proxy` 的行為與 NDJSON 結構
    - Docker volume subpath
    - 各工具的秘密注入方式
  - DoD：取得 ZAP、Nuclei、Schemathesis 的真實輸出樣本並保存 hash；不經 proxy 的直連必須失敗。
  - 限制：只掃自建的 lab，不能提前開放任意 URL 的平台功能。環境不可用時標為 blocked，不能改掃公共網站，也不能把 Mock 當成 live 成果。
  - 交付（2026-10-17，done）：
    - 檔案：`compose.lab.yaml`、`Makefile`（`lab-up`／`lab-down`，自動選 compose）、`spikes/t03/`（guard-spike、canary、ZAP plan、schemathesis.toml、模板清單、遮罩與彙整腳本、README）、`tests/contract/test_fixture_manifest.py`、`tests/fixtures/`（zap/nuclei/schemathesis 遮罩樣本 + `manifest.json`）、`docs/TOOLS.md`。完整相容性表、量測與逐項驗證結果見 `docs/TOOLS.md`。
    - 映像（arm64、digest 鎖定）：zaproxy/zap-stable 2.17.0、projectdiscovery/nuclei v3.11.1、schemathesis 4.31.1、mitmproxy 12.2.3、bkimminich/juice-shop v20.3.0、erev0s/vampi latest。nuclei-templates v10.5.0（commit f8b8b8d）。
    - 直連必須失敗（D1–D7）：scan_net 解析不到、連不到 lab；只有經 guard 且帳密正確才成功；被擋的請求以 canary 證明未送達（403/407，canary 無紀錄）。`internal + gateway_mode_ipv4=isolated` 下連 `host.docker.internal` 都解析不到。
    - 真實輸出（已遮罩，sha256 記於 `tests/fixtures/manifest.json`）：ZAP traditional-json（juice-shop 4 告警、vampi）、Nuclei JSONL（juice-shop 13、vampi 14 findings）、Schemathesis JSON/NDJSON/JUnit（提交的 fixture 取自 max-examples=2 的 compact run：119 cases/14 failures；另有 max-examples=15 的量測 run 314 cases/16 failures 記於 `TOOLS.md`）。三工具流量全部經 guard，上游 IP 皆在 LAB_CIDR。
    - 逐項確認：ZAP proxy 鍵 + `-configfile`（不洩漏密碼）+ `-silent`（擋自身對外）+ `ZAP_AUTH_HEADER` 注入；Nuclei `-sf` host:port 完全比對 + 經 proxy 不需本機 DNS；Schemathesis `--proxy`/bearer 以 `${ENV}`、NDJSON 結構、exit code；volume subpath in/out；秘密不落命令列。
    - 實際執行：先寫會失敗的 `test_fixture_manifest.py`（RED，示範 fixture 竄改 → sha256 與 JWT 檢查同時失敗），遮罩補齊後 `make test` 58 passed、coverage 100%；`make lint`、`make typecheck`、`pre-commit run --all-files` 皆通過。
    - 未執行（選做）：Z3/N3/S2（vampi-secure 負控制組）與 ZAP active scan，留待 M3；原因為時間與 spike 範圍。
    - 限制：Juice Shop 不相容唯讀 rootfs（已放寬並保留 cap_drop/no-new-privileges）；OrbStack 記憶體上限實測 8 GiB（低於規劃，影響 M3 active scan 預算）。詳見 `docs/TOOLS.md` §5–§6。
    - code-reviewer 與 security-reviewer（M0 收尾，依 §12）：兩者皆 APPROVE，0 CRITICAL、0 HIGH，確認無任何真實秘密進入 git（含歷史）。合併前已處理的建議：guard 改 fail-closed（policy 載入失敗 deny-all、判斷例外回 500）、canary 覆蓋所有 method 並讀完 body、強化 fixture 防洩密測試（Bearer/Basic/userinfo/base64 解碼）、遮罩改用與測試共用的 JWT 樣式並處理 Werkzeug SECRET、補 `run_scans.sh` 使隔離旗標可稽核、`lab-up` 加 `lab-verify`（internal+isolated+無對外 port，失敗即收回）、移除誤導的 `block_global`、`.gitignore` 擴充秘密形態。其餘列為 M2 輸入（路徑正規化、HMAC telemetry、socket-proxy 最小開關）。

## M1｜11/09 – 12/13：API 與資料基礎

前置：T01–T02。

- [x] T04 建立 DB Model、Alembic、Repository 與設定。
  - DoD：全新 DB 可完成 migration；FK、unique、index 都有測試；測試資料與正式配置分離。
  - 交付（2026-10-18，done）：
    - 範圍：資料層基礎，以及第一批資料表 projects、api_keys、audit_events（T05 的 key 與稽核要用）。其餘資料表由 T06–T09 各自以 migration 與測試加入，不預先建立還沒有功能測試驅動的欄位（`ARCHITECTURE.md` §6.2）。
    - 檔案：
      - 環境：`compose.yaml`（`db`、`db-test`）、`deploy/postgres/initdb/10-app-role.sql`、`Makefile`（`env`、`db-up`、`test-db-up`、`db-down`、`migrate`；`make test` 會先啟動 db-test）、`.env.example`、`pyproject.toml`（`[tool.alembic]`、import-linter、coverage）、`.pre-commit-config.yaml`（擋下 `.env`）
      - 程式：`src/secscan/core/`（`config`、`db`、`errors`、`request_id`、`pagination`、`text`、`json_types`）、`src/secscan/{projects,api_keys,audit}/`（`domain`、`models`、`repository`）、`src/secscan/migrations/`（`env.py`、`metadata.py`、`versions/v0001_identity_and_audit.py`）、`/health/ready`
      - 測試：`tests/integration/`、`tests/unit/`、`tests/api/test_errors.py`
    - 依賴（uv 實際解析）：sqlalchemy 2.1.5、alembic 1.20.0、psycopg[binary] 3.3.6。PostgreSQL 映像為 `postgres:18.6-trixie@sha256:74935e72…`（arm64；19 仍是 RC，不採用）。
    - DoD 對照：
      - **全新 DB 可完成 migration**：每個測試 session 都在 db-test 建立全新資料庫並 upgrade head。另外測了：downgrade base 後再 upgrade、model 與 migration 無漂移（autogenerate 比較結果為空）、離線 `--sql` 不需連線與密碼、`env.py` 依 `DB_*` 連線（`make migrate` 的路徑）。
      - **FK、unique、index**：直接用 SQL 觸發每個約束，驗證 SQLSTATE 與約束名稱：FK 3 個、unique 3 個、CHECK 11 個，以及刪除被引用的 project（RESTRICT）與 NOT NULL。另有通用測試比對「model 宣告的 CHECK」與「DB 實際的 CHECK」，因為 autogenerate 看不到 CHECK。索引以 `pg_indexes` 確認；audit_events 的 UPDATE、DELETE、TRUNCATE 都被 trigger 拒絕。
      - **測試資料與正式配置分離**：
        - 整合測試只讀 `TEST_DB_*`，只接受 loopback 位址上 `cluster_name=secscan-test` 的伺服器。
        - 每個 session 以專屬的非 superuser 角色和全新資料庫執行，結束時刪除。角色時區刻意設成 Asia/Taipei，用來驗證應用程式自己固定成 UTC。
        - 測試不讀 `.env`、會清除 `DB_*`；非整合測試連 DB 會直接失敗（psycopg 走 libpq，pytest-socket 擋不到）。
        - prod 缺少 `DB_PASSWORD` 時，啟動就失敗。
        - 決策理由見 `DECISIONS.md` §7：以 compose 管理的 db-test 取代 testcontainers，測試程序不碰 Docker daemon。
    - 一併補上 T02 延後的項目：
      - `GET /health/ready`：DB 可連線且 schema 在目前版本才回 200，否則回 503 `DEPENDENCY_UNAVAILABLE`。不洩漏主機或帳號；失敗原因（例外類別、SQLSTATE）記在伺服器端。
      - 統一錯誤處理：AppError、404、405、422、500 都回 envelope，並帶伺服器產生的 request_id（`X-Request-ID`，不採用 client 送來的值）。
        - 422 只列欄位位置，不回顯輸入。
        - 500 回通用訊息，只記 request_id 與例外類別（`API_CONTRACT.md` §12）。
    - 其他設計：
      - 時間欄位用 `UtcDateTime`，拒絕沒有時區的 datetime。
      - engine 設 `hide_parameters`；約束錯誤不接上含資料值的原始例外。
      - domain 的 `New*` 物件先驗證長度、空白與 NUL；分頁頁碼上限 10,000。
      - 功能模組依呼叫關係分層（`DECISIONS.md` §8）；`main` 載入完整的 model 登記。
    - 實際執行：
      - 先寫測試並確認失敗。第一輪：`ModuleNotFoundError`、設定測試 14 failed、`/health/ready` 回 404。審查修正那一輪：7 failed，包括 registry、loopback、時區、readiness log。實作後才通過。
      - model 與 migration 是依 `ARCHITECTURE.md` §6 先寫的，所以另做突變檢查，每一項都會讓測試失敗：
        - 拿掉 row trigger
        - model 少一個 index
        - 拿掉 `NewApiKey` 驗證
        - migration 少一個 CHECK
        - `main` 沒載入 model 登記
        - engine 沒有 `hide_parameters`
        - 專案排序改成反向
      - `make test` 260 passed、coverage 100%（含分支；改以路徑量測後，`env.py` 與 migration 檔也納入）。`make lint`、`make typecheck`、`pre-commit run --all-files` 都通過。
      - `make migrate` 把開發 DB 升級到 `0001 (head)`；`make dev` 後 `/health/ready` 回 200。db-test 在測試後沒有殘留的角色或資料庫。
    - 安全檢查（實測）：
      - db 與 db-test 只綁 127.0.0.1，從區網 IP 連線被拒。
      - 容器以非 root（999）、唯讀 rootfs、`cap_drop: ALL`、`no-new-privileges` 執行，並有記憶體與 pids 上限。
      - 容器內的本機連線也要 SCRAM 密碼，沒有 trust。
      - 應用程式角色 `secscan_app` 不是 superuser，`COPY ... PROGRAM` 被拒，也連不進 `postgres` 維運資料庫。
      - 秘密只存在 `.env`（權限 600，`make env` 產生 192-bit 隨機值，並檢查 openssl 確實有輸出）與容器環境變數。不在 argv、git，也不在容器日誌（實測 0 筆）。init SQL 建立角色時，失敗也不會把密碼寫進日誌。
    - 審查（依 CLAUDE.md §12 與全域規則，T04 結束時執行）：
      - code-reviewer：REQUEST CHANGES（0 CRITICAL、1 HIGH、5 MEDIUM、7 LOW）。
        - HIGH 與 MEDIUM 已全部修正：入口未載入 model 登記、功能分層、統一錯誤 envelope、naive datetime、5 個 CHECK 沒有測試、readiness 吞錯。
        - LOW 已修 5 項：排序與 UTC 測試沒有鑑別力、測試隔離、DataError 與頁碼、domain 檢查範圍。
        - LOW 的 `.env` 拆分列入 M2；基礎設施提醒寫在下方「給後續任務」。
      - security-reviewer：APPROVE（0 CRITICAL、0 HIGH）。
        - MEDIUM 已修：SQL 參數進入例外、unit 測試可連 DB。
        - MEDIUM 的 DDL/DML 角色分離列入 M2/T23（`DECISIONS.md` §7）。
        - LOW 已修：init 日誌含密碼、容器內 trust、readiness log、500 沒有 request_id、`make env` 未檢查 openssl、守衛沒有測試、pre-commit 擋 `.env`、trigger 函式的 search_path。
        - LOW 的連線逾時與 sslmode 列入 T09／M2。
      - 修正後重新執行全部測試與突變檢查（見上方「實際執行」）。
    - 限制：
      - 資料庫擁有者仍可停用 audit trigger，目前只能稱「防誤改」。
      - 開發 db 的密碼只在第一次初始化時寫入。
      - `make test` 需要 OrbStack。
      - superuser 與應用程式密碼同在 `.env`。
      - 尚未設定 `statement_timeout`、`sslmode`。
    - 給後續任務：
      - **T05**：
        - key 至少 128-bit CSPRNG，以 SHA-256 或 HMAC＋pepper 雜湊，用 `hmac.compare_digest` 比對；完整值只顯示一次；「不存在」與「錯誤」回同樣的回應。
        - 對外 schema 不帶 `key_hash`。
        - `ConstraintViolationError` 要對應成穩定錯誤碼，不回傳約束名稱。
        - 補「A 專案讀不到 B 專案」的 404 測試；`redacted_changes` 要先遮罩並限制大小。
        - 建立正式的 request-scoped session（commit／rollback）。重試類邏輯用 `begin_nested()`。
        - 初始管理 key 的 CLI 也必須 import model 登記。
      - **T09**：
        - 目前的 `db_session` fixture（單一連線、外層交易）測不了 SKIP LOCKED 與併發，需要每個測試一個資料庫，或用 template DB。
        - `created_at` 是交易開始時間，佇列順序要用序號欄位。
        - 補上 statement 與 idle-in-transaction 的逾時。
      - **M2／T23**：
        - DDL/DML 角色分離。
        - 秘密改用 compose `secrets:` 與 `POSTGRES_PASSWORD_FILE`，並拆開基礎設施與應用程式的秘密。
        - DB 只接 internal 的 control_net，加 `sslmode`。
        - 正式映像評估 `psycopg[c]`。
        - 已確認 `uv build` 的 wheel 包含 `migrations/`（`env.py`、樣板與 `versions/`）。
- [x] T05 建立 API key、project 與 object-level 權限。
  - DoD：
    - key 高熵且只存 hash，支援過期與撤銷。
    - viewer 不可寫入；A 專案不能讀 B 專案的資料。
    - 初始管理 key 由本機 CLI 建立，且只顯示一次。
  - 交付（2026-10-19，done）：
    - 範圍：
      - 平台 API key 的產生、驗證、到期與撤銷；project 的建立與查詢；以 project 與角色為準的 object-level 授權；稽核查詢；建立初始管理 key 的本機 CLI。
      - 沒有新增 migration（`0001` 的欄位已足夠）。
      - 設計決定見 `DECISIONS.md` §9，API 見 `API_CONTRACT.md` §13。
    - 檔案：
      - 程式：
        - `src/secscan/security/`：`api_key_tokens`（產生、格式檢查、SHA-256、常數時間比對）、`redaction`（遮罩）
        - `src/secscan/api_keys/`：`domain`（權限、期限、`ProjectScope`）、`service`、`access`、`dependencies`、`router`、`schemas`
        - `src/secscan/projects/`：`service`、`router`、`schemas`；`src/secscan/audit/`：`service`、`schemas`
        - `src/secscan/core/`：`api`（版本前綴、分頁 query）、`db`（request session）、`errors`（新錯誤碼、回應 header）、`request_id`（給日誌用的 context variable）
        - `src/secscan/cli.py`（`secscan-admin`）、`src/secscan/main.py`（`/api/v1`）
      - 設定：`pyproject.toml`（`[project.scripts]`；import-linter 加入 `cli` 與 `security`）、`.pre-commit-config.yaml`（擋下平台 key 格式的字串）
      - 測試：
        - `tests/unit/security/`、`tests/unit/test_access_policy.py`、`tests/unit/test_api_schemas.py`、`tests/unit/test_cli.py`、`tests/unit/test_admin_key_callers.py`、`tests/unit/core/test_api.py`
        - `tests/api/test_authentication.py`、`tests/api/test_authorization.py`
        - `tests/integration/` 的 service、API、CLI 測試、撤銷競爭測試與 `api_support.py`
    - 端點：
      - `POST`、`GET /api/v1/projects`
      - `GET /api/v1/projects/{project_id}`（新增）
      - `POST /api/v1/projects/{project_id}/keys`
      - `DELETE /api/v1/keys/{key_id}`
      - `GET /api/v1/projects/{project_id}/audit-events`
    - DoD 對照：
      - **key 高熵且只存 hash**：
        - secret 是 `secrets.token_hex(32)`（256-bit），prefix 另外產生；測試確認兩者分開向 CSPRNG 取亂數，1,000 把 key 互不重複。
        - DB 只存 prefix 與 SHA-256。以 `row_to_json` 搜尋 api_keys 與 audit_events，找不到 key 與 secret；之後的回應、audit 與 log 也都找不到；OpenAPI 沒有 `key_hash`。
        - 以 `hmac.compare_digest` 比對。以下情況的回應完全相同：
          - 沒帶 key、格式錯、key 不存在
          - secret 錯誤
          - 已撤銷
          - 已過期但 secret 錯誤
      - **支援過期與撤銷**：
        - 所有 key 都有到期時間（預設 90 天、最多 365 天），到期那一刻就失效（邊界測試）；過期回 `API_KEY_EXPIRED`。沒有到期時間的 key（只可能直接寫 DB 產生）一律視為過期。
        - 撤銷後立即回 401；重複撤銷回 204，audit 只記一次。
        - 兩個連線同時撤銷只算一次，同一個 session 已載入的 key 也以 DB 最新值判斷（兩個測試分別固定 `FOR UPDATE` 與 `populate_existing`）。
      - **viewer 不可寫入**：
        - viewer 與 operator 呼叫所有管理端點：自己的 project 回 403，其他 project 回 404。
        - PROJECT_WRITE 規則以整張表測試，並用測試 app 確認 viewer 403、operator 允許。
        - 真正寫入 project 資源的端點要到 T06 才有，屆時直接沿用。
      - **A 專案不能讀 B 專案**：
        - A 的 viewer、operator 在清單只看到 A。
        - `GET /projects/{B}`、`POST /projects/{B}/keys`、`GET /projects/{B}/audit-events` 都回 404，回應與不存在的 project、不存在的路徑完全相同。
      - **初始管理 key 由本機 CLI 建立，且只顯示一次**：
        - `secscan-admin create-admin-key` 在 commit 成功後才寫出 key 一次：寫到 stdout，或寫到 `--output` 新建、權限 600 的檔案（已存在就拒絕）。stderr 只有 id、prefix 與到期時間。
        - DB 只有 hash；audit 的 actor 為空、來源標為 CLI。
        - 失敗時都不寫出 key、不留下空檔，訊息不含密碼：
          - 設定錯誤、DB 未 migrate 或連不上
          - commit 失敗（以 DEFERRABLE trigger 模擬）
        - key 已建立但寫不出去時，只回報 id。
    - 其他設計：
      - `/api/v1` 在 router 層強制驗證。測試走訪所有路由與 OpenAPI，確認每個端點都要求 key；另用一個沒宣告驗證參數的路由，確認 router 層本身就會擋。
      - request transaction 以 `scope="function"` 的依賴在回應送出前 commit。以 DEFERRABLE constraint trigger 讓 commit 失敗，確認 client 收到 500 而不是 201。
      - prefix 碰撞在 savepoint 內重試（最多 3 次），外層 transaction 仍可使用。
      - 清單查詢收明確的 `ProjectScope`（`AllProjects`／`OneProject`），不用 `None` 代表全部；傳錯就失敗。
      - 被拒絕的存取寫進日誌（decision、key_id、角色、權限、project_id、request_id）。
      - audit 的 changes 先遮罩再寫入：
        - 遮罩依欄位名稱（含 NFKC 正規化），以及文字中的平台 key、Bearer／Basic 值與 JWT。
        - 重複遮罩到結果不變；JWT 樣式保持線性時間；tuple 不能繞過。
        - domain 再檢查已遮罩且不超過 8 KiB；讀出時再遮罩一次。
      - 約束對應成穩定錯誤碼，回應不含約束名稱；以測試確保 src 中只有 CLI 呼叫 `issue_admin_key`。
    - 實際執行：
      - TDD：每一步先寫測試並確認失敗，例如：
        - `ModuleNotFoundError`（security、service、CLI）
        - `ImportError`（domain 與 core 的新名稱）
        - repository 新介面 5 failed
        - UTC 正規化 1 failed（暫時拿掉實作確認）
        - 審查後的修正：遮罩 16 failed、CLI 7 failed
        - 例外：API 的整合測試是在 router 完成後才寫的，以下方的突變檢查證明鑑別力。
      - 測試本身的問題（都已修正）：
        - 走訪路由的測試一開始空轉通過：FastAPI 0.143 的 `app.routes` 只放 include 進來的 router。被「端點清單」測試抓到，改用 `iter_route_contexts()` 並要求清單非空。
        - stale identity map 的測試一開始也空轉通過：identity map 只弱參照 ORM 物件，沒人引用就被回收。改成保留參照。
      - 突變檢查（24 項，每一項都讓測試失敗）：
        - 權限：其他 project 改回允許、其他 project 改回 403、清單不過濾 project、未知 scope 當成全部、`OneProject` 接受 None、拿掉 router 層驗證、授權拒絕不記日誌
        - 驗證：拿掉 hash 比對、拿掉撤銷檢查、拿掉到期檢查、沒有到期時間的 key 視為有效、先判斷到期再比對 secret
        - 撤銷與 transaction：撤銷不用 `FOR UPDATE`、撤銷不刷新已載入的物件、session 改回預設 scope、拿掉 savepoint 重試
        - 遮罩與 audit：audit 寫入時不遮罩、audit domain 不檢查遮罩、audit 讀出時不遮罩、遮罩只做一輪、JWT 樣式沒有 lookbehind、tuple 不遮罩
        - 其他：拿掉 `no-store`、CLI 失敗時不刪除輸出檔
      - 檢查結果：
        - `make test` 571 passed、coverage 100%（含分支；`security/` 與權限規則都是 100%）。
        - `make lint`（含新的 import-linter 契約）、`make typecheck`、`pre-commit run --all-files` 都通過。
        - 新的 pre-commit hook 實測會擋下含平台 key 的檔案。
      - 手動端到端：在 db-test 上建立暫時資料庫，審查前後各跑一次，結束後刪除。
        1. CLI 建立 admin key，只寫入 0600 檔；第二次執行拒絕覆寫。
        2. 啟動 API，依序確認：
           - 建立 project 與 viewer key，回應有 `no-store`。
           - viewer 讀得到自己的 project，寫入與管理操作被拒，撤銷後回 401。
           - audit 依序為 revoke、create、create。
           - OpenAPI 只有 `PlatformApiKey`，沒有 `key_hash`。
           - 伺服器日誌找不到完整的 key；被拒絕的存取有 request_id。
        3. 撤銷這把 admin key，刪除暫時資料庫與檔案；db-test 沒有殘留的資料庫或角色。
    - 審查（依 CLAUDE.md §12 與全域規則：驗證與授權程式必須做安全審查）：
      - code-reviewer：APPROVE（0 CRITICAL、0 HIGH、4 MEDIUM、5 LOW），MEDIUM 全部已修：
        - 遮罩不是 idempotent，特定名稱會讓 API 回 500。
        - 文件誤稱「驗證在讀取 body 之前」。
        - 「先比對 secret 再判斷到期」與並發撤銷沒有測試固定。
        - JWT 樣式是二次方時間。
      - code-reviewer 的 LOW：已修 4 項（「所有 key 都會過期」只在 service 層成立、`Permission.PLATFORM_ADMIN` 易與角色混淆、CLI commit 失敗沒有測試、只是釘住常數的斷言）。過度遮罩與 405 的 `Allow` 不完整記為取捨或框架行為。
      - security-reviewer：REQUEST CHANGES（輕度；0 CRITICAL、0 HIGH、1 MEDIUM、8 LOW）。
        - MEDIUM（body 在驗證前就被讀取與解析）：文件與測試已改成實際行為，middleware 列入 T07、T23。
        - LOW 已修：
          - 遮罩：二次方時間、tuple 繞過、全形名稱與常見名稱。
          - 沒有到期時間的 key。
          - 授權拒絕沒有日誌。
          - CLI 輸出檔的覆寫與寫出失敗。
          - `None` 當作「全部」。
          - API 誤用 `issue_admin_key`。
          - `/docs` 的提醒、措辭過滿的文件、pre-commit 擋平台 key。
        - LOW 延後：事故應變工具、自行託管 Swagger UI、遮罩的其他缺口（`DECISIONS.md` §9.5）。
      - 修正後重跑全部測試、24 項突變檢查與手動端到端。
    - 限制：
      - 沒有速率限制與請求大小上限（OWASP API2:2023 建議驗證端點要有）。key 是 256-bit，API 目前只綁 127.0.0.1；列入 T07、T23，T23 完成前不發布 port。
      - 沒有 `last_used_at`、列出 key、依 prefix 撤銷等事故應變工具。沒有所屬 project 的 audit（admin key 的建立與撤銷）只能直接查 DB，查詢 API 留給 T21。
      - 只有回傳完整 key 的回應有 `no-store`；全域安全 header 列入 T23。
      - 遮罩依欄位名稱與樣式判斷，不保證認得所有秘密；HAR 成對格式、URL 帳密等留給 T08 與 M3。
      - SEC-16 的 scan、finding、artifact 跨專案測試，隨相關資源完成。
    - 給後續任務：
      - **T06 起**：
        - 新路由掛在 `/api/v1` router 底下就會自動要求 key，並加進 `tests/api/test_authentication.py` 的 `V1_ROUTES`。
        - service 一開始呼叫 `authorize()`：讀取用 `PROJECT_READ`，寫入用 `PROJECT_WRITE`（viewer 403），grant 核准等管理操作用 `PLATFORM_MANAGE` 搭配 project_id。
        - 清單查詢收 `ProjectScope`。以 id 讀取的資源（例如 `GET /targets/{id}`）要在查詢加上 project 條件，或取出 project_id 後再 `authorize()`；其他 project 與不存在一樣回 404，並補 A/B 兩個 project 的測試。
        - 需要稽核的變更經 `AuditTrail.record`，與業務變更在同一個 transaction。
      - **T07**：規格上傳前，先在 `/api/v1` 加上驗證前的 body 大小上限（413）與格式檢查（`DECISIONS.md` §9.5）。
      - **T09**：建立 scan 沿用 `DbSession`；runner 與 worker 不經 HTTP，需要自己的 session 與 transaction 管理。
      - **M2／T23**：速率限制、全域安全 header、key 的事故應變工具、自行託管 Swagger UI；以上完成前不發布 port、不綁非 loopback 位址。
- [x] T06 建立 target、ScopeGrant 與審批流程。
  - DoD：
    - pending/approved/revoked/expired 的轉換正確。
    - 沒有核准就不能開始掃描。
    - `LAB_ONLY` 時，grant 的 IP 必須在 `LAB_CIDR` 內。
    - 留下 audit 紀錄。
  - 交付（2026-10-22，done）：
    - 範圍：
      - target（要掃描的靶場）的建立、查詢、改名與停用；scope grant 的申請、查詢、核准與撤銷。
      - 建立 scan 前的唯一檢查入口（掃描 gate）；建立 scan 的 API 在 T09。
      - 設定 `LAB_ONLY`、`LAB_CIDR`；migration `0002`（targets、scope_grants 與生命週期 trigger）。
      - 設計決定見 `DECISIONS.md` §10，API 見 `API_CONTRACT.md` §14。T06 不對使用者給的 URL 發出任何流量（不解析 DNS、不連線）。
    - 檔案：
      - 程式：
        - `src/secscan/targets/`：`domain`（origin 的嚴格解析、`LabNetwork`）、`models`、`repository`、`service`、`errors`、`schemas`、`router`、`dependencies`
        - `src/secscan/grants/`：`domain/scope`（範圍、預算、期限）、`domain/lifecycle`（狀態、轉換、掃描 gate）、`models`、`repository`、`service`、`schemas`、`router`
        - `src/secscan/migrations/versions/v0002_targets_and_scope_grants.py`
        - `src/secscan/core/`：`config`（`LAB_ONLY`、`LAB_CIDR`）、`errors`（新錯誤碼）、`text`（拒絕控制字元與格式字元）；`main.py`（`app.state.lab`、兩個 router）；`migrations/metadata.py`
      - 設定：`pyproject.toml`（layers 加入 targets、grants；開發依賴 hypothesis 6.170.2）、`.env.example`
      - 測試：
        - unit：`tests/unit/targets/`、`tests/unit/grants/`、`test_scope_schemas.py`、`test_lab_dependency.py`、`core/test_config.py`、`core/test_text.py`
        - integration：`test_scope_schema.py`、`test_scope_repositories.py`、`test_target_service.py`、`test_grant_service.py`、`test_grant_races.py`、`test_targets_api.py`、`test_grants_api.py`
        - 共用：`sql_support.py`、`scope_support.py`、`locks.py`（等鎖 helper 從 `test_revocation_race.py` 移出）；`api_support.py` 的 `Seeder` 加上 target、grant、approve
    - 端點：
      - `POST`、`GET /api/v1/projects/{project_id}/targets`
      - `GET`、`PATCH /api/v1/targets/{target_id}`
      - `POST`、`GET /api/v1/targets/{target_id}/scope-grants`（GET 為新增）
      - `GET /api/v1/scope-grants/{grant_id}`（新增）
      - `POST /api/v1/scope-grants/{grant_id}/approve`、`/revoke`
    - DoD 對照：
      - **pending/approved/revoked/expired 的轉換正確**：
        - DB 只存 pending、approved、revoked；expired 由 `valid_until` 推導（到期那一刻起），revoked 優先於 expired。不需要排程工作，也沒有「已過期、DB 卻還是 approved」的空窗。
        - domain：4 種狀態 × 2 種動作的轉換表，並有測試確認「允許」與「拒絕」兩張表合起來涵蓋所有組合；時間邊界以注入的 `now` 測試（`valid_until` 前 1µs、等於時）。
        - service 與 API：核准只限 pending；撤銷 pending、approved；重複撤銷回 200、不重記 audit；其他一律 409 `INVALID_STATE_TRANSITION`。讀取時的 `status` 由當下時間推導（API 測試直接寫入一筆期限已過的資料，讀出為 expired、不能核准）。
        - DB：trigger `scope_grants_guard` 只允許 pending→approved、pending→revoked、approved→revoked，範圍欄位不可修改，DELETE、TRUNCATE 一律拒絕；以 raw SQL 逐一測試每種非法轉換與每個範圍欄位。
        - 併發：同時核准與撤銷時，後到的等先到的 commit 再判斷（`FOR UPDATE` 加 `populate_existing`），以 `pg_stat_activity` 確認在等列鎖；「撤銷先開始、核准先 commit」另有確定性測試（見下方審查）。
      - **沒有核准就不能開始掃描**：
        - `ScopeGrantService.require_usable()` 是唯一的判斷：pending、已撤銷、尚未生效回 403 `SCOPE_NOT_APPROVED`，過期回 403 `SCOPE_EXPIRED`，target 停用回 409 `TARGET_DISABLED`，IP 不在目前的 `LAB_CIDR` 內回 422 `SCOPE_OUTSIDE_LAB`，其他 target 的 grant 或 target 的 origin 不在 grant 內回 422，其他 project 回 404。
        - 以 `FOR SHARE` 依序鎖住 target 與 grant：併發測試確認撤銷或停用 commit 之後 gate 拒絕，gate 持有鎖時撤銷會等待。
        - 建立 scan 的 API 要到 T09 才有：T06 只能證明這個判斷本身，`POST /scans` 呼叫它的 API 層測試留給 T09。
      - **`LAB_ONLY` 時 grant 的 IP 必須在 `LAB_CIDR` 內**：
        - 設定：`LAB_ONLY=false` 時啟動失敗；`LAB_CIDR` 必須在 RFC 1918 內、前綴 /16–/30，預設值與 `compose.lab.yaml` 的 lab_net 一致（測試比對兩者）。
        - grant 的每個 IP 必須是 `LAB_CIDR` 內的主機位址（網段位址、廣播位址、IPv6 都拒絕），IP 形式的 target 主機也一樣。
        - 申請、核准、gate 三個時點都以當下的設定檢查：申請後縮小 `LAB_CIDR`，核准與 gate 都會拒絕。
      - **留下 audit 紀錄**：`target.create`、`target.update`（只記有變動的欄位與前後值）、`scope_grant.create`、`scope_grant.approve`、`scope_grant.revoke`，與業務變更在同一個 transaction；被拒絕或失敗的操作不留紀錄；changes 經遮罩（測試確認 Bearer 樣式的授權文件編號被遮掉）。
    - 實際執行：
      - TDD：每一步先寫測試並確認失敗，例如：
        - `ImportError`（`DEFAULT_LAB_CIDR`、`GrantRequest`）、`ModuleNotFoundError`（targets、grants、service、schemas）
        - schema 測試在 migration 之前：`relation "targets" does not exist`（17 failed、71 errors）
        - 路由：`V1_ROUTES` 先更新，12 failed；API 整合測試先寫，27 failed（T05 的 API 測試是路由完成後才補的，這次改正）
        - 審查後的修正：13 failed（含確定性重現的 `ck_scope_grants_decision_times` 違反）
        - 例外：repository 的 14 個測試寫在實作之前，但沒有先執行確認失敗；鑑別力以下方的突變檢查補證明。
      - 測試本身的問題（都已修正）：
        - 隨機輸入的 property test 一開始在 2,000 個樣本中只接受 1 個，幾乎只測到「不會丟出其他例外」；改成由合法與危險片段拼成的 URL（約 20% 被接受），並以 Hypothesis 的 `find()` 證明兩種結果都存在。
        - 「轉換表涵蓋所有組合」的測試一開始永遠不會失敗；改成檢查允許與拒絕兩張表的聯集等於所有組合。
        - 「valid_until 必須晚於現在」的情境，一開始其實被「開始必須早於結束」先擋下；補上整段期間都在過去的案例。
        - 長度上限的測試一開始沒有測到剛好 256 字元的邊界。
        - 上鎖時讀最新值的兩個測試一開始空轉通過：identity map 只弱參照 ORM 物件，沒人引用就被回收（T05 的同一個教訓）。被突變檢查抓出，改成刻意保留參照。
        - 離線 migration 的既有測試假設 head 版本直接寫入 `alembic_version`；有兩個 migration 後改成檢查最後停在 head。
      - 突變檢查（66 項，每一項都讓測試失敗；腳本不進 repo，跑完還原檔案）：
        - 第一輪 58 項抓到 56 項：漏掉的是 grant、target「上鎖時不讀最新值」，原因是上面那兩個空轉的測試；修正測試後 2/2 抓到。
        - 審查後更新受影響的目標字串並新增 8 項，最後全部重跑 66/66。
        - 權限：建立 target 不檢查權限、viewer 可以建立 target 或申請 grant、operator 可以核准或撤銷、以 id 讀 target 或 grant 不檢查 project
        - 轉換：撤銷後還能核准、可以核准已過期的申請、可以撤銷已過期的 grant、到期判斷差一格、revoked 不優先於 expired、重複撤銷再寫一次
        - `LAB_CIDR`：建立 target、申請、核准、gate 任一處不檢查；接受網段或廣播位址；`LAB_ONLY` 可以關閉；`LAB_CIDR` 不限 RFC 1918
        - URL：接受 userinfo、反斜線、非 ASCII、模糊的數字 host、IPv6、https、localhost、前導 0 的 port
        - 範圍與上限：path 接受 `..` 或 `%`、method 接受 TRACE、空清單代表全部 path、grant 不需包含 target 的 origin、IP 形式的 origin 不需列在 allowed_ips、拿掉預算或期限上限、期限可以在過去
        - gate：pending、尚未生效、target 停用、別的 target 的 grant 可以通過
        - 鎖：gate 不鎖 grant 或 target、核准與撤銷不鎖 grant、申請時不鎖 target、grant 或 target 上鎖時不讀最新值、target 鎖的模式不分
        - DB：拿掉 row trigger 或 TRUNCATE trigger、trigger 不檢查範圍欄位、讀取時把網段當成主機
        - audit 與回應：申請、核准、撤銷、建立 target、修改 target 不寫 audit；回應的 status 不推導 expired
        - 審查後新增：撤銷時間改回 transaction 開始時間、極端時間不轉成 422、gate 不比對 target 的 origin、待核准的申請沒有上限、過期的申請也佔名額、target 數量沒有上限、文字欄位接受控制字元、先驗證說明文字再檢查權限
      - 檢查結果：
        - `make test` 1166 passed、coverage 100%（含分支；`targets`、`grants` 的 domain 都是 100%）。
        - `make lint`（含新的 layers）、`make typecheck`、`pre-commit run --all-files` 都通過（新檔案先以 `git add -N` 納入，否則 `--all-files` 不會檢查未追蹤的檔案）。
      - 手動端到端：做法同 T05（db-test 上的暫時資料庫、API 跑在 127.0.0.1:8765、key 只寫入 0600 檔），審查前後各跑一次，結束後刪除。不啟動 lab，target 只是登記，沒有任何流量送往靶場。
        1. CLI 建立 admin key；admin 建立 project A、B，以及 A 的 operator、viewer key。
        2. target：
           - operator 以 `HTTP://VAMPI-VULN:5000/` 建立，canonical origin 為 `http://vampi-vuln:5000`。
           - viewer 建立回 403；含帳密的 base_url 回 422 `INVALID_TARGET`，回應不含密碼；lab 以外的 IP 回 422 `SCOPE_OUTSIDE_LAB`。
        3. grant 申請：
           - operator 申請成功，201、pending、version 1；IP 不在 `LAB_CIDR` 內回 422 `SCOPE_OUTSIDE_LAB`。
           - 審查後那次另確認：授權文件編號含 bidi 控制字元、`valid_until` 為 `9999-12-31T23:59:59-05:00`，都回 422 `INVALID_REQUEST`。
        4. operator 核准回 403；admin 核准後 viewer 查得到 approved；再核准一次回 409 `INVALID_STATE_TRANSITION`。
        5. A 的 operator 讀 B 的 target 回 404，回應除了 request_id 之外與不存在的 id 完全相同。
        6. admin 撤銷：`revoked_at` 不早於 `approved_at`；重複撤銷回 200、`revoked_at` 不變；核准已撤銷的 grant 回 409。operator 停用 target。
        7. A 的 audit 依序為 project.create、api_key.create ×2、target.create、scope_grant.create、scope_grant.approve、scope_grant.revoke、target.update；被拒絕的操作與重複撤銷都沒有紀錄。
        8. OpenAPI 有 11 個 `/api/v1` 路徑。撤銷驗證用的 admin key。伺服器日誌沒有完整的 key、測試密碼或未處理的例外；被拒絕的存取都有記錄（forbidden ×2、not_found ×1）。
        9. 刪除暫時資料庫與檔案；db-test 沒有殘留的資料庫或角色。
    - 審查（依 CLAUDE.md §12 與全域規則：授權與輸入驗證必須做安全審查）：
      - 第一次啟動的兩個審查因 API 用量上限中途停止，重新執行後完成。
      - code-reviewer：APPROVE（0 CRITICAL、0 HIGH、2 MEDIUM、4 LOW），全部已修：
        - M1：撤銷的 transaction 比同時進行的核准更早開始、卻在核准 commit 之後才拿到鎖時，`revoked_at`（原本是 `now()`，即 transaction 開始時間）早於 `approved_at`，違反 CHECK，撤銷回 500。改用 `clock_timestamp()`，並加上不需要執行緒的確定性測試。
        - M2：極端時區的期限（例如 `9999-12-31T23:59:59-05:00`）換算成 UTC 時溢位，回 500；改成先以原本的時區比較，溢位回 422。
        - LOW：`environment` 欄位被接受後丟掉、approve／revoke 先驗證說明文字再檢查權限、一個測試名稱與內容不符、交付紀錄尚未更新。
      - security-reviewer：APPROVE（0 CRITICAL、0 HIGH、1 MEDIUM、4 LOW、5 INFO）。沒有找到能繞過 gate、`LAB_CIDR` 或 origin 解析的方法，也沒有跨 project 洩漏；它以約 21.5 萬個字串和 Node 的 WHATWG `new URL()` 及 `urlsplit` 比對被接受的 origin，0 個不一致。
        - MEDIUM 與 code-reviewer 的 M1 相同，已修。
        - LOW 已修：
          - 極端日期回 500（同 M2）。
          - gate 沒比對 target 的 origin 是否在 grant 內（只有直接改 DB 才會不一致）：gate 加上這項比對。
          - 無法刪除的大型 pending grant 沒有數量上限：每個 target 最多 10 個待核准的申請、每個 project 最多 100 個 target（409 `QUOTA_EXCEEDED`，`DECISIONS.md` §10.9）。
          - 文字欄位接受控制字元與 bidi 字元：`require_text` 拒絕 Unicode 類別 Cc、Cf（也影響 T05 的名稱，`DECISIONS.md` §10.10）。
        - INFO（path 比對語意、lab 網段內的基礎設施位址、gate 的時間與鎖等待、停用 target 不是權威的停止手段、報告以 `approved_at` 為授權時間）寫進 `DECISIONS.md` §10.5、§10.8 與下方「給後續任務」。
      - 修正後重跑全部測試、突變檢查與手動端到端。
    - 限制：
      - 建立 scan 的 API 還不存在：「沒有核准就不能開始掃描」目前由 gate 本身的測試證明，`POST /scans` 的 API 層測試在 T09；撤銷 grant 或停用 target 之後停止執行中的 scan，在 T09、T13。
      - 平台不驗證 origin 與 IP 的對應（不解析 DNS），由管理員核准時人工核對；執行時的 DNS/IP 綁定由 M2 的 guard 強制。SEC-02、SEC-05 目前只完成應用層。
      - origin 解析的自動化測試只與標準函式庫 `urlsplit` 做 parser differential；與 WHATWG 的一致性靠「只接受最嚴格的子集」的設計、對照表測試與一次性的審查比對，與 mitmproxy 的比對在 T11。
      - path 與 method 的比對規則還沒有實作（T07、T11），T06 只定語法。
      - admin 可以核准自己提出的申請（只有一位管理員；audit 記下申請者與核准者）。核准新版本不會自動撤銷舊版本。
      - 到期是推導出來的：到期當下沒有 audit 事件（到期時間記在 `scope_grant.create`）。
      - trigger 與 CHECK 只防程式錯誤造成的誤改；擁有 DDL 權限的人仍可停用 trigger（`DECISIONS.md` §7）。targets 沒有 trigger，origin 的不可修改由 API 與 gate 的比對保證。
      - target 數量是軟上限，同時建立時可能略為超過。
      - 預算上限沿用 M0–M2 的保守值，期限最長 30 天；M3 量測後若要調整，在 DECISIONS 記錄。
      - 仍沒有請求大小上限與速率限制（T05 已知，列入 T07、T23）。
      - 環境：開發期間 OrbStack VM 的時鐘一度比主機慢約 149 秒，T05 三個比較 DB 時間與應用程式時間（容許 1 分鐘）的測試因此暫時失敗；時鐘恢復同步後重跑全部通過。其後 OrbStack 曾停止，依 README 以 `orb start` 重新啟動。
    - 給後續任務：
      - **T07**：
        - 規格上傳前，先在 `/api/v1` 加上驗證前的 body 大小上限（413）與格式檢查（T05 已列）。
        - operation 是否在範圍內：依 grant 的 `allowed_paths`（literal 與 `{name}` 佔位）、`allow_all_paths`、`excluded_paths`（排除優先）、`allowed_methods` 判斷；比對至少和伺服器語意一樣寬（`DECISIONS.md` §10.8）。
      - **T09**：
        - `POST /scans` 在同一個 transaction 呼叫 `ScopeGrantService.require_usable()`，並把 grant 的 id、version 與範圍放進不可變的 scan 快照。取得鎖之後再取 `now`，並設定 `lock_timeout`。
        - scan 與 grant、target、project 的 DB 層一致性（例如複合 FK）。
        - 撤銷 grant 或停用 target 時，處理已建立但尚未執行的 scan；runner 啟動前再呼叫一次 gate。
      - **T11（M2）**：guard 以 grant 快照逐請求強制 origin、DNS/IP 綁定、path、method 與預算；以 mitmproxy 的 URL 解析做 parser differential；lab 網段內的基礎設施位址（guard、canary）要排除；實際收包證據補齊 SEC-01、SEC-02、SEC-05。
      - **M3**：ZAP web profile 需要的 seed path；依量測調整預算上限（`grants/domain/scope.py` 的常數與 `DECISIONS.md` §10.3）。
      - **T21**：全域的待核准清單與全域 audit 查詢；報告以 `approved_at` 作為授權成立的時間。
- [ ] T07 建立 OpenAPI 上傳與受限的 operation inventory。
  - DoD：驗證大小、格式、$ref、servers，包含惡意與跨 origin 的測試；不從外部抓取任何東西。
- [ ] T08 建立 auth profile 與 secret 生命週期。
  - DoD：secret 以 MultiFernet 加密、只寫不讀、支援換版、不寫入 log；preflight 定義有驗證。
- [ ] T09 建立 scan、scanner_run 工作佇列、idempotency、狀態機與 FakeRunner。
  - DoD：
    - API 回 202；scan 與 scanner_runs 在同一個 transaction 建立。
    - SKIP LOCKED 認領與 lease 有測試，包含兩個 consumer 同時認領的情境。
    - 相同 Idempotency-Key 與相同內容不會重複建立；相同 key 不同內容回 409。
    - FakeRunner 能跑完、失敗、被取消。
    - scan_events 可以輪詢。

里程碑證據：不用真工具，也能從 API 建立受控任務、查詢狀態，並得到假 runner 明確標記的測試結果；所有權限測試都通過。

## M2｜12/14 – 01/24：Runner 與強制安全邊界（期末考期間，排輕一點）

前置：T03、T06、T09。

- [ ] T10 建立 runner、docker-socket-proxy、ExecutionPlan 驗證與容器限制。
  - DoD：
    - api、worker、掃描容器都沒有 Docker socket，也不是 privileged。
    - socket-proxy 只開放容器需要的區段。
    - 未核准的映像、path、args、網路都會被拒絕（SEC-12、SEC-21）。
    - 測試隔離：unit/contract 測試不能連到 Docker daemon。pytest-socket 目前整個放行 AF_UNIX（asyncio 需要），所以要在 conftest 拒絕 `tmp_path` 以外的 AF_UNIX connect、把測試時的 `DOCKER_HOST` 設為無效值，並禁止未標記 `live` 的測試使用 `enable_socket`。
- [ ] T11 完成 internal networks、egress guard，以及 DNS/IP/path/method/redirect 檢查。
  - DoD：
    - SEC-02 到 SEC-10 中適用的項目都通過。
    - 以 canary 的收包紀錄證明沒有越界。
    - guard 不可用時 fail closed；無法約束的 profile 一律關閉。
- [ ] T12 完成共享預算、telemetry 與認證 preflight 路徑。
  - DoD：
    - 所有掃描流量共用同一個上限，preflight 也計入。
    - Token 只送往核准的 origin。
    - 從 telemetry 可以算出實際請求數。
- [ ] T13 實作心跳/lease、取消、timeout、孤兒容器清理與 reconciler。
  - DoD：
    - 重複認領時不會重複啟動容器。
    - 中斷後不會永遠停在 running。
    - 取消時先封鎖 guard，再回收容器。

放行規則：T10–T13 全部通過前，不對操作者開放真實的 active scan API。只支援完全封閉的 HTTP 靶場；不跳過 HTTPS guard 測試來擴大範圍。

上學期成果展示的內容：授權流程、FakeRunner 任務、guard 擋下越界請求、取消，以及 M0 的工具 spike 結果。

## M3｜01/25 – 02/28：ZAP Adapter（寒假與農曆年）

前置：M2。

- [ ] T14 實作 ZAP capability probe 與 Web/API ExecutionPlan。
  - DoD：
    - 使用 `-silent` 與伺服器產生的 AF plan。
    - auth 以 `ZAP_AUTH_HEADER*` 環境變數注入；沒有 auth 的 profile 明確標為 anonymous。
    - API spec 的 origin 綁定到核准目標；profile 與 method 不相容時拒絕。
- [ ] T15 實作版本化的 ZAP JSON Parser 與觀察輸入契約。
  - DoD：clean、findings、malformed、timeout、exit 各種 fixture 都有測試；非零退出不一律當成 crash。
- [ ] T16 執行 ZAP 真實 e2e 與失敗情境。
  - DoD：
    - Juice Shop 與 VAmPI 的已知正例/負例、Token 失效、工具超時、取消，都有真實證據。
    - 保留版本與 guard 的流量資訊。
    - 依量測結果調整 lab profile 的預算，並留下紀錄。
- [ ] T30 建立自製 fixture app 與 ground truth 初稿。
  - DoD：
    - fixture app 可以切換弱點版與修補版，只放在 lab_net。
    - 約 12 個資安案例與 6 個 contract/robustness 案例，都寫好預期行為與確認方式。

里程碑證據：第一次走通 API → 真實工具 → 解析 → DB → 查詢的完整閉環，而不只是啟動容器。

## M4｜03/01 – 04/04：Nuclei 與結果整合

前置：M3。去重的單元測試可以提早進行。

- [ ] T17 凍結 Nuclei 的 HTTP 模板清單與執行設定。
  - DoD：
    - 依 tag/類型產生 ID 清單，記錄 release、hash 與 ID。
    - 以類別為單位審查，並抽查高風險模板。
    - 使用 `-ni -duc -pt http`；禁用 code/headless/dos 模板、OAST 與雲端上傳。
- [ ] T18 實作 Nuclei Adapter、JSONL Parser 與真實 e2e。
  - DoD：空檔、壞行、重複、非零退出、取消、timeout 都有明確定義；零告警與失敗可以區分。
- [ ] T19 實作 Observation/Finding、rule_groups、mapping 版本與保守的 fingerprint。
  - DoD：
    - 正確保留來源、kind、severity、confidence。
    - OWASP Top 10:2025 與 API 2023 的對應都記錄 mapping_source。
    - 不可信的映射不跨工具合併。
- [ ] T20 建立去重的反例測試與來源追溯查詢。
  - DoD：
    - 這些情況都不會誤合併：同 CWE 但參數不同、同 route 但身分或物件不同、不同的弱點。
    - 所有證據都能追溯到來源。

里程碑證據：兩個引擎能在同一個 API 流程中取得真實結果，並展示共享預算、部分失敗，以及同一問題有多個來源。

## M5｜04/05 – 04/25：報告、複掃與 P0 驗收

前置：M4。

- [ ] T21 完成人工 triage、audit 與 JSON/Markdown 報告。
  - DoD：未確認的告警有清楚標記；artifact 的權限、遮罩、下載都安全；不執行 HTML，也不載入遠端資源。
- [ ] T22 實作比較快照、coverage 判斷與差異分類。
  - DoD：scope、auth、工具或 spec 不一致時顯示理由；漏掃不會顯示成已修補；舊的 scan 保留。
- [ ] T23 完成所有 P0 的安全、故障、整合測試，並在乾淨環境重建。
  - DoD：
    - 安全負向測試全部通過。
    - 整體 coverage ≥ 80%，核心模組 branch coverage ≥ 90%。
    - 原始證據以加密方式保存。
    - 文件與實際的 API 一致。
- [ ] T31 建立 benchmark harness。
  - DoD：透過自己的 API 執行各實驗組別，保存 manifest 與 guard 計數；`evaluate.py` 是純函式，並且有測試。

放行規則：M5 通過（Gate A–D）後，才能啟動 M6 的第三引擎；沒通過時，M6 改為補強期。

## M6｜04/26 – 05/23：Schemathesis 與 SARIF（或補強）

前置：M5。

- [ ] T24 查核 Schemathesis 鎖定版本的 JSON/NDJSON 輸出，以及 phase、method、proxy、auth、seed 的行為。
  - DoD：使用受控的 spec 與 seed；確實停止發送未授權的 method；能取得可以對應到 operation 的觀察。
- [ ] T25 實作第三個 Adapter，並把 contract/robustness 分開統計。
  - DoD：HTTP 500 與 schema failure 不會直接變成 confirmed security；真實輸出的解析與故障測試都有。
- [ ] T26 視進度細化 API 覆蓋率，並提供一份 CI 呼叫範例。
  - DoD：以 guard telemetry 證明真正送出過哪些核准的 operation，缺資料時回 N/A；不用告警數量推估覆蓋率。
- [ ] T32 SARIF 匯出與 dogfooding。
  - DoD：SARIF 通過 schema 驗證；在 lab 中用 Schemathesis 掃描平台自己的 API，並記錄結果。

降階：刪除 T24、T25、T32，保留兩個引擎，不影響核心研究問題；把時間用在 T23 與 T27–T29。

## M7｜05/24 – 06/30：實驗、分析與展示

- [ ] T27 凍結 ground truth、holdout、工具版本、預算與資料快照。
  - DoD：指導教授或同學抽樣複核至少 20% 的案例；自訂模板的實驗另外列出；相同總預算的規則清楚。
- [ ] T28 執行重複實驗，保存真實結果並計算指標。
  - DoD：
    - 每組重複 5 次（至少 3 次）。
    - security 與 contract 分開統計。
    - 報告 TP/FP/FN、去重 precision/recall、時間與請求數，以及失敗情形。
- [ ] T29 完成報告、操作/部署文件與口試 demo。
  - DoD：在乾淨環境重建一輪；能說明哪些範圍沒有覆蓋、哪些地方失敗；沒有把示意數字當成成績。

## 各功能共同 Definition of Done

- 功能要同時包含：實作、輸入驗證、權限、錯誤語意、測試、文件，以及必要的 migration。
- 採用 TDD：先有會失敗的測試，再實作。
- 掃描相關的功能，另外需要真實的 live 證據、版本紀錄與清理測試。
- 「完成」指的是可以驗證的行為，不是 class、route 或檔案存在。

## 每次交付紀錄格式

```text
任務：Txx
狀態：not_started / in_progress / blocked / done
修改檔案：
實際執行測試與結果：
未執行測試與原因：
安全/相容性限制：
下一個依賴已滿足的任務：
```

不要先填「全部通過」。如果工具、網路或環境不可用，就標為 blocked，並保存之後需要補驗證的具體內容。
