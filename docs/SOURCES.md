# 一手技術來源

查核日期：S01–S19 為 2026-10-15；S20–S31 為 2026-10-16；S32–S36 為 2026-10-17；S37–S40 為 2026-10-18；S41–S58 為 2026-10-19。以下是選型與設計的參考，不代表已在本專題環境驗證過相容性或效能。官方 stable 文件可能會變動；實作時需同時記錄已安裝的版本、CLI help 與 Parser fixture。

| ID | 文件與網址 | 本計畫引用的要點 |
|---|---|---|
| S01 | [Claude Code — How Claude remembers your project](https://code.claude.com/docs/en/memory) | 專案根目錄放 CLAUDE.md；建議保持精簡；指示文件不是強制的安全設定 |
| S02 | [ZAP — Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) | 以 YAML 編排掃描工作、context、active scan 等 |
| S03 | [ZAP — Docker API Scan](https://www.zaproxy.org/docs/docker/api-scan/) | 匯入 OpenAPI/SOAP/GraphQL 後，進行 API 調校的 active scan |
| S04 | [ZAP — Docker Documentation](https://www.zaproxy.org/docs/docker/about/) | 映像名稱為 `zaproxy/zap-stable`/weekly/nightly/bare（GHCR 同 tag）；範例 `zap.sh -cmd -autorun /zap/wrk/zap.yaml`；Baseline、Full、API 掃描模式的區別 |
| S05 | [ZAP — OpenAPI Support](https://www.zaproxy.org/docs/desktop/addons/openapi-support/) | OpenAPI 規格匯入；需留意實際版本與格式限制 |
| S06 | [ProjectDiscovery — Running Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/running) | 模板選擇、HTTP/其他協定、JSONL、redirect、rate-limit、輸出與認證設定 |
| S07 | [Schemathesis — CLI Options](https://schemathesis.readthedocs.io/en/stable/reference/cli/) | `--report` 支援 junit、vcr、har、ndjson、json、wfc、allure、html；`--proxy`（所有網路請求的 proxy）；`--seed`（可重現的測試） |
| S08 | [Schemathesis — Checks](https://schemathesis.readthedocs.io/en/stable/reference/checks/) | 規格/健壯性檢查；停用 unsupported_method 告警，不會自動停止發送該類請求 |
| S09 | [Schemathesis — API Authentication](https://schemathesis.readthedocs.io/en/stable/guides/auth/) | 與 securitySchemes 對應的 API key、Bearer、Basic 等認證設定 |
| S10 | [FastAPI — Background Tasks](https://fastapi.tiangolo.com/tutorial/background-tasks/) | 較重、需要獨立程序的工作，應交給外部的工作佇列工具 |
| S11 | [Celery — Tasks](https://docs.celeryq.dev/en/stable/userguide/tasks.html) | idempotency、acknowledgment、重新派送、timeout 的注意事項（`DECISIONS.md` 比較用） |
| S12 | [Docker — Engine security](https://docs.docker.com/engine/security/) | Docker daemon 的高權限、API 與掛載風險、容器資源與 capability 限制 |
| S13 | [OWASP — SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | allowlist、redirect、DNS 與網路層的出站限制 |
| S14 | [OWASP — API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) | 物件層授權取決於使用者與資源之間的存取關係，不只是 endpoint 能不能呼叫 |
| S15 | [OWASP — API Security Top 10, 2023 edition](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) | 本專題採用的固定分類版本；不聲稱這份清單是完整的測試規格 |
| S16 | [OWASP — Juice Shop](https://owasp.org/projects/juice-shop) | 可自行部署的故意脆弱 Web 教學靶場；只掃自己的副本 |
| S17 | [OWASP — crAPI](https://owasp.org/projects/crapi) | 可選的 API 故意脆弱靶場，非 MVP 必備 |
| S18 | [mitmproxy — Addons overview](https://docs.mitmproxy.org/stable/addons/overview/) | 以事件 hook 整合 request/response 的控制與觀察 |
| S19 | [mitmproxy — Certificates](https://docs.mitmproxy.org/stable/concepts/certificates/) | 檢視 HTTPS 需要 client 信任 CA；upstream certificate sniffing 的連線行為 |
| S20 | [ZAP — Command Line Options](https://www.zaproxy.org/docs/desktop/cmdline/) | `-silent`：確保 ZAP 不主動發出任何請求（包含檢查更新）；`-cmd`、`-config` |
| S21 | [ZAP — Handling Auth Yourself](https://www.zaproxy.org/docs/getting-further/authentication/handling-auth-yourself/) | `ZAP_AUTH_HEADER_VALUE`、`ZAP_AUTH_HEADER`、`ZAP_AUTH_HEADER_SITE`：必須在 ZAP 啟動前設定，執行中無法修改 |
| S22 | [ZAP — Download](https://www.zaproxy.org/download/) | 查核時的 stable 版本為 2.17.0 |
| S23 | [Nuclei — GitHub README](https://github.com/projectdiscovery/nuclei)；[Releases](https://github.com/projectdiscovery/nuclei/releases) | `-ni`（關閉 interactsh/OAST）、`-duc`、`-sf`（authenticated scan 的 secret 檔）、`-p`、`-jsonl`、`-pt`、`-id`、`-lna`；查核時最新版本為 v3.11.1 |
| S24 | [Schemathesis — CI/CD Integration](https://schemathesis.readthedocs.io/en/stable/guides/cicd/) | 官方 Docker 映像 `schemathesis/schemathesis:stable` |
| S25 | [OWASP Top 10:2025](https://top10.owasp.org/2025) | A01 Broken Access Control … A10 Mishandling of Exceptional Conditions；用於 Web 類 finding 的對應 |
| S26 | [VAmPI](https://github.com/erev0s/VAmPI) | MIT 授權；`erev0s/vampi`，port 5000；`vulnerable=1/0` 切換弱點版與安全版；OpenAPI 規格在 `openapi_specs/` |
| S27 | [Tecnativa — docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) | 依 API 區段（CONTAINERS、EXEC、VOLUMES…）與 POST 開關限制 Docker API；文件沒有說明會檢查 request body |
| S28 | [PostgreSQL — SELECT：The Locking Clause](https://www.postgresql.org/docs/current/sql-select.html#SQL-FOR-UPDATE-SHARE) | `SKIP LOCKED` 會略過無法立即鎖定的列，適合多個 consumer 存取的佇列型資料表 |
| S29 | [Docker — Volumes](https://docs.docker.com/engine/storage/volumes/) | `--mount` 的 `volume-subpath`：只掛載 volume 的子目錄 |
| S30 | [全國法規資料庫 — 中華民國刑法](https://law.moj.gov.tw/LawClass/LawAll.aspx?pcode=C0000001) | 第三十六章妨害電腦使用罪（§358–363）；查核時頁面顯示最新修正日期為民國 115 年 07 月 22 日 |
| S31 | [Celery — Using Redis](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/redis.html) | 未在 visibility timeout（Redis 預設 1 小時）內確認的工作，會重送給其他 worker 執行（`DECISIONS.md` §3 的理由） |
| S32 | [Docker — Packet filtering and firewalls / port publishing](https://docs.docker.com/engine/network/port-publishing/) | `internal` 網路仍配 gateway 位址、容器可連宿主該位址；`gateway_mode_ipv4=isolated`（需搭配 `--internal`）不配 gateway（T03 §3 驗證） |
| S33 | [OrbStack — Container networking](https://docs.orbstack.dev/docker/network) | macOS 可直接連容器 IP、`*.orb.local`、`host.docker.internal`；IPv6 預設關閉（T03 以 isolated 網路驗證隔離行為） |
| S34 | [mitmproxy — proxyauth / htpasswd 原始碼](https://github.com/mitmproxy/mitmproxy/blob/v12.2.3/mitmproxy/utils/htpasswd.py) | `proxyauth=@file` 只接受 bcrypt 與 `{SHA}`；驗證後把 (user, password) 存入 `flow.metadata["proxyauth"]` 並移除 `Proxy-Authorization` |
| S35 | [ZAP network add-on ConnectionOptions](https://github.com/zaproxy/zap-extensions/blob/main/addOns/network/src/main/java/org/zaproxy/addon/network/ConnectionOptions.java) | upstream proxy 設定鍵 `network.connection.httpProxy.{enabled,host,port,authEnabled,username,password}` |
| S36 | [Nuclei authprovider file.go](https://github.com/projectdiscovery/nuclei/blob/v3.11.1/pkg/authprovider/file.go) | `-sf` 的 `domains` 以不分大小寫完全比對 host:port（只去 :80/:443）；`domains-regex` 未錨定 |
| S37 | [Docker Hub — postgres（Docker Official Image）](https://hub.docker.com/_/postgres) | 18 版起 `PGDATA=/var/lib/postgresql/18/docker`、volume 掛在 `/var/lib/postgresql`；`/docker-entrypoint-initdb.d` 只在資料目錄為空時執行；`POSTGRES_USER` 是 superuser（T04 以 `docker image inspect` 與實際啟動確認） |
| S38 | [Alembic — Tutorial（pyproject.toml 設定）](https://alembic.sqlalchemy.org/en/latest/tutorial.html) | 1.16 起可用 `[tool.alembic]`；`%(here)s` 與 `%%` 跳脫；post_write_hooks；離線 `--sql` 模式 |
| S39 | [SQLAlchemy — Configuring Constraint Naming Conventions](https://docs.sqlalchemy.org/en/20/core/constraints.html#configuring-constraint-naming-conventions) | `MetaData(naming_convention=…)` 讓約束與索引名稱固定，autogenerate 可重現（T04 以實際 DDL 確認） |
| S40 | [PostgreSQL — psql](https://www.postgresql.org/docs/current/app-psql.html) | `\getenv` 把環境變數讀進 psql 變數；`:'var'`、`:"var"` 以字串常值或識別字插入（T04 的初始化 SQL 用它避免把密碼放進命令列） |
| S41 | [RFC 6750 — OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750) | §2.1 `Authorization: Bearer <b64token>` 的格式；§3 請求沒帶憑證或憑證無效時，回應必須含 `WWW-Authenticate`（T05 的 401 都帶 `WWW-Authenticate: Bearer`） |
| S42 | [Python — secrets](https://docs.python.org/3/library/secrets.html)；[hmac.compare_digest](https://docs.python.org/3/library/hmac.html#hmac.compare_digest) | `token_hex(n)` 產生 n bytes 亂數的 hex 字串；「一般認為 32 bytes（256 bits）的亂數已足夠」；`compare_digest` 以常數時間比對，降低 timing attack 的風險 |
| S43 | [FastAPI — Dependencies with yield：Early exit and scope](https://fastapi.tiangolo.com/tutorial/dependencies/dependencies-with-yield/#early-exit-and-scope) | yield 依賴預設（`scope="request"`）在回應送出之後才結束；`scope="function"` 在送出之前結束（T05 的 request transaction；另以 FastAPI 0.143.3 原始碼與 commit 失敗的測試確認） |
| S44 | [OWASP — API2:2023 Broken Authentication](https://api-security.owasp.org/editions/2023/en/0xa2-broken-authentication) | API key 用於驗證 API client，不用於使用者登入；驗證端點應有比一般更嚴格的防暴力猜測與速率限制（T05 尚未做速率限制，列入 M2/T23，見 `DECISIONS.md` §9.5） |
| S45 | [SQLAlchemy — Session.get](https://docs.sqlalchemy.org/en/21/orm/session_api.html#sqlalchemy.orm.Session.get) | 物件已在 identity map 時直接回傳、不查 DB；`populate_existing` 一定重新查詢並以新資料更新物件。T05 以 SQLAlchemy 2.1.5 原始碼確認：`with_for_update` 會送出 `SELECT … FOR UPDATE`，但不覆寫已載入的屬性，所以撤銷 key 時兩者一起用 |
| S46 | [SQLAlchemy — Using SAVEPOINT](https://docs.sqlalchemy.org/en/21/orm/session_transaction.html#using-savepoint) | `begin_nested()` 內出錯只回滾 savepoint，外層 transaction 繼續；PostgreSQL 遇到 IntegrityError 通常會中止整個 transaction（T05 prefix 碰撞重試的依據） |
| S47 | [WHATWG — URL Standard](https://url.spec.whatwg.org/) | 瀏覽器與部分工具採用的解析規則：special scheme（http 等）把 `\` 當成 `/`（記為 validation error）；host 的最後一段是數字時交給 IPv4 parser，接受 `0x` 十六進位、前導 0 的八進位與不足 4 段（單一數字就是整個位址）；domain 經 UTS #46 ToASCII（例如全形字母對應成半形）。T06 只接受與它解讀一致的子集（`DECISIONS.md` §10.2） |
| S48 | [Python — urllib.parse](https://docs.python.org/3.12/library/urllib.parse.html) | `urlsplit()`／`urlparse()` 不驗證輸入，官方建議有安全影響時自行檢查各部分；3.12 起去掉開頭的 C0 控制字元與空白；`hostname` 轉小寫。T06 以它做 parser differential 測試，並以 Python 3.12.6 實測 `http://lab\@evil` 解出 host `evil` |
| S49 | [Python — ipaddress](https://docs.python.org/3.12/library/ipaddress.html) | 3.9.5 起 `IPv4Address` 不接受前導 0（與 glibc `inet_pton()` 一樣嚴格），也接受 32-bit 整數輸入；`IPv4Network` 在 strict 模式下 host bits 不為 0 時拋出 `ValueError`；`network_address`、`broadcast_address` |
| S50 | [RFC 3986 — URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986) | §3.3：`pchar = unreserved / pct-encoded / sub-delims / ":" / "@"`；`.`、`..` 是 dot-segment，在解析參照時會被移除。§2.1–2.4：percent-encoding 的大小寫與 unreserved 字元的編碼都視為等價。所以 T06 的 path 不接受 `%` 與點段落，避免同一條 path 有多種寫法 |
| S51 | [RFC 6454 — The Web Origin Concept](https://www.rfc-editor.org/rfc/rfc6454) | §4：由 URI 取 origin 時 scheme 與 host 轉小寫；§6.2：序列化時只有 port 不是該 scheme 的預設值才附加（T06 的 canonical origin 省略 `:80`） |
| S52 | [RFC 1918 — Address Allocation for Private Internets](https://www.rfc-editor.org/rfc/rfc1918) | §3：私有網段 10/8、172.16/12、192.168/16（`LAB_CIDR` 必須在其中） |
| S53 | [RFC 6761 — Special-Use Domain Names](https://www.rfc-editor.org/rfc/rfc6761) | §6.3：`localhost.` 與 `.localhost.` 底下的名稱都解析到 loopback（T06 拒絕這類 target） |
| S54 | [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) | §9.1：method token 區分大小寫；§9.2.1：GET、HEAD、OPTIONS、TRACE 是 safe method。T06 只接受大寫的 GET、HEAD、OPTIONS、POST、PUT、PATCH、DELETE；TRACE 會回顯請求內容，掃描用不到，不接受 |
| S55 | [RFC 5891 — IDNA Protocol](https://www.rfc-editor.org/rfc/rfc5891) | §4.2.3.1：標籤的第 3、4 個字元不可是 `--`（保留給 `xn--` 等國際化網域名稱；T06 不接受） |
| S56 | [PostgreSQL — CREATE TABLE](https://www.postgresql.org/docs/current/sql-createtable.html) | 多個 CHECK 依名稱的字母順序檢查（9.5 起）；CHECK 不能有子查詢、只能參照同一列的欄位，所以 `LAB_CIDR` 這類設定無法放進 CHECK |
| S57 | [PostgreSQL — Explicit Locking：Row-Level Locks](https://www.postgresql.org/docs/current/explicit-locking.html) | `FOR UPDATE` 阻擋其他 transaction 的 UPDATE、DELETE 與任何 `FOR …` 鎖；`FOR SHARE` 阻擋 UPDATE、DELETE、`FOR UPDATE`，但彼此不衝突；`SELECT … FOR UPDATE` 等到對方的 transaction 結束後，回傳更新後的列。鎖在 transaction 結束時釋放（T06 的核准、撤銷與掃描 gate） |
| S58 | [Hypothesis — API reference：settings](https://hypothesis.readthedocs.io/en/latest/reference/api.html) | `derandomize=True` 以測試函式的 hash 決定亂數，每次執行測同一組輸入；`database=None` 不保存範例資料庫。`find()` 回傳符合條件的最小例子（以已安裝的 6.170.2 確認找不到時拋出 `NoSuchExample`） |

## 需要在 M0–M2 實際確認的事項

> T03（2026-10-17）已完成以下 1–6 針對三個引擎與 egress 的 M0 部分，結果與證據見 `TOOLS.md`。第 7 項（docker-socket-proxy 的最小開關組合）屬 runner 範疇，T03 未做，留待 M2／T10。DNS/IP 綁定、redirect 重檢、HTTPS CA 等也留待 M2。


1. 三個引擎的映像版本、digest、arm64 支援與授權條款。
2. ZAP：
   - 引擎與 add-on 版本、report job 的 JSON 欄位與退出碼契約
   - upstream proxy 的設定鍵（含 proxy 帳密）
   - `-silent` 的實際效果
3. Nuclei：
   - templates 的 release 與 hash、ID 清單的產生方式
   - `-sf` 的檔案格式
   - 經 proxy 掃描時，是否需要自行解析 lab 主機名稱
4. Schemathesis：
   - 鎖定版本的 CLI、JSON/NDJSON 結構、seed 與 generation phase 行為
   - `--proxy` 的實際行為
5. egress guard：
   - mitmproxy 對 `Proxy-Authorization` 的處理
   - IP 綁定與 redirect 檢查
   - 日後 HTTPS 的 CA 信任與上游憑證驗證
6. 各映像與非 root、唯讀 rootfs、必要可寫目錄、volume subpath 的相容性（OrbStack 的 Docker Engine）。
7. docker-socket-proxy 讓 runner 能 create/start/stop/wait/取回 archive 所需的最小開關組合。

## 來源與推論的界線

- 工具支援哪些功能，取自上述官方文件。
- 以下都是本計畫提出的工程方案或待驗證的假設，不是官方保證，也不是市場調查結果：
  - 後端框架與工作佇列的選擇
  - 工期、人數、預算
  - 驗收指標、去重設計
  - 專題定位
- 兩份規劃的比較與取捨記錄在 `DECISIONS.md`。
