# 一手技術來源

查核日期：S01–S19 為 2026-10-15；S20–S31 為 2026-10-16；S32–S36 為 2026-10-17；S37–S40 為 2026-10-18；S41–S58 為 2026-10-19；S59–S68 為 2026-10-24；S69–S78 為 2026-10-25；S79–S82 為 2026-10-26；S83–S86 為 2026-10-27；S87–S93 為 2026-10-28。以下是選型與設計的參考，不代表已在本專題環境驗證過相容性或效能。官方 stable 文件可能會變動；實作時需同時記錄已安裝的版本、CLI help 與 Parser fixture。

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
| S28 | [PostgreSQL — SELECT：The Locking Clause](https://www.postgresql.org/docs/current/sql-select.html#SQL-FOR-UPDATE-SHARE) | `SKIP LOCKED` 會略過無法立即鎖定的列，適合多個 consumer 存取的佇列型資料表，但「provides an inconsistent view of the data」；指定 `FOR UPDATE OF` 的資料表時，只鎖那些資料表的列；READ COMMITTED 下 `ORDER BY` 搭配鎖可能回傳排序欄位已被改過的列（2026-10-26 查核）。T09 的認領以 `FOR UPDATE OF scans SKIP LOCKED` 先鎖 scan，鎖到之後以新的 statement 再確認（`DECISIONS.md` §13.5） |
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
| S57 | [PostgreSQL — Explicit Locking：Row-Level Locks](https://www.postgresql.org/docs/current/explicit-locking.html) | `FOR UPDATE` 阻擋其他 transaction 的 UPDATE、DELETE 與任何 `FOR …` 鎖；`FOR SHARE` 阻擋 UPDATE、DELETE、`FOR UPDATE`，但彼此不衝突；`SELECT … FOR UPDATE` 等到對方的 transaction 結束後，回傳更新後的列。鎖在 transaction 結束時釋放（T06 的核准、撤銷與掃描 gate；T09 建立 scan 時以 `FOR SHARE` 鎖 target、grant 與 auth profile，讓撤銷、停用與 PATCH 等它 commit） |
| S58 | [Hypothesis — API reference：settings](https://hypothesis.readthedocs.io/en/latest/reference/api.html) | `derandomize=True` 以測試函式的 hash 決定亂數，每次執行測同一組輸入；`database=None` 不保存範例資料庫。`find()` 回傳符合條件的最小例子（以已安裝的 6.170.2 確認找不到時拋出 `NoSuchExample`） |
| S59 | [OpenAPI Specification 3.0.4](https://spec.openapis.org/oas/v3.0.4.html) | 2024-10-24 發布。Format：建議 YAML 1.2，「Tags MUST be limited to those allowed by YAML's JSON schema ruleset」、「Keys used in YAML maps MUST be limited to a scalar string」；沒有 `servers` 時預設是 url 為 `/` 的 Server Object；只差在佔位名稱的 path「MUST NOT exist as they are identical」；operationId「MUST be unique among all operations」；Link 的 `operationRef`（URI reference）與 `server`、Example 的 `externalValue`（指向範例的 URL）、Discriminator 的 `mapping`（schema 名稱或 URI reference）、Operation 的 `callbacks`。T07 依此決定拒絕與改綁的範圍（`DECISIONS.md` §11.3、§11.4） |
| S60 | [YAML 1.2.2](https://yaml.org/spec/1.2.2/) | §5.4：YAML 1.1 把 NEL、LS、PS 當成換行，1.2 起是一般字元；§10.3 core schema 的 tag 解析：`null\|Null\|NULL\|~` 與空值、`true…FALSE`、`[-+]?[0-9]+`、`0o[0-7]+`、`0x[0-9a-fA-F]+`、浮點數、`.inf`、`.nan`，其他 plain scalar 都是 str；§10.2 JSON schema 中對不到的 plain scalar 是錯誤 |
| S61 | [RFC 6901 — JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901) | §3：`~` 寫成 `~0`、`/` 寫成 `~1`，解碼時先 `~1` 再 `~0`；§4：陣列索引不可有前導 0，`-` 指向不存在的元素；§6：URI fragment 表示法要 percent-encode（T07 不接受 `%`，見 `DECISIONS.md` §11.4） |
| S62 | [RFC 8259 — JSON](https://www.rfc-editor.org/rfc/rfc8259) | §4：名稱 SHOULD 唯一，不唯一時「the behavior of software that receives such an object is unpredictable」；§6：Infinity 與 NaN 不允許；§8.1：不可加 BOM（parser MAY 忽略）。T07 拒絕重複的 key、NaN 與 BOM |
| S63 | [RFC 9512 — YAML Media Type](https://www.rfc-editor.org/rfc/rfc9512) | 註冊 `application/yaml` 與 `+yaml` 後綴；建議 UTF-8；安全考量：alias 重複展開造成指數成長（billion laughs）、參照形成循環、tag 解析可能執行程式碼，deserializer 預設應關閉。T07 拒絕 anchor、alias 與 tag |
| S64 | [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) | §15.5.9：408 Request Timeout；§15.5.14：413 Content Too Large；§15.5.16：415 Unsupported Media Type（T07 的上傳時間、大小與 Content-Type；408 於 2026-10-25 審查後補查）。T08（2026-10-25 查核）：§5.1 `field-name = token`；§5.6.2 `tchar` 是 `!`、`#`、`$`、`%`、`&`、`'`、`*`、`+`、`-`、`.`、`^`、`_`、反引號、`|`、`~`、數字與英文字母；§5.5 field-value 的字元是 VCHAR 與 obs-text，「Field values containing CR, LF, or NUL characters are invalid and dangerous」；§7.6.1 中介者轉送前應移除 Proxy-Connection、Keep-Alive、TE、Transfer-Encoding、Upgrade 等 connection-specific 欄位。T08 的 header 名稱只收 token 的子集（英數字與 `-`），值不收 CR、LF、NUL、tab 與 obs-text，並拒絕這些欄位 |
| S65 | [PyYAML Documentation](https://pyyaml.org/wiki/PyYAMLDocumentation) | `parse(stream)` 產生 parsing events；LibYAML 綁定是選用的，預設是純 Python；`yaml.load` 不可用於不可信的輸入。T07 只用純 Python 的事件 API，自己組成資料（以已安裝的 6.0.3 實測：plain scalar 的 style 在純 Python 為 None、在 C 版為空字串） |
| S66 | [Python — json](https://docs.python.org/3.12/library/json.html) | 預設接受並輸出 `Infinity`、`-Infinity`、`NaN`；`parse_constant`、`parse_float`、`object_pairs_hook`；重複的名稱預設只留最後一個；3.11 起 `int()` 受 integer string conversion length limitation 限制（預設 4,300 位，以 3.12.6 實測超過時拋出 ValueError） |
| S67 | [PostgreSQL — Binary String Functions](https://www.postgresql.org/docs/current/functions-binarystring.html) | `sha256(bytea) → bytea`。T07 以 CHECK `document_sha256 = sha256(document)` 讓 DB 核對規格文件的 hash |
| S68 | [GitHub Advisory Database — python-multipart](https://github.com/advisories?query=python-multipart) | 以 `gh api /advisories` 查核：CVE-2024-24762（Content-Type 的 ReDoS，0.0.7 修正）、CVE-2024-53981（boundary 造成的 DoS，0.0.18）、CVE-2026-40347（preamble／epilogue 的 DoS，0.0.26）、CVE-2026-42561（part header 沒有上限的 DoS，0.0.27）等。T07 不用 multipart 的理由之一 |
| S69 | [cryptography — Fernet (symmetric encryption)](https://cryptography.io/en/latest/fernet/) | key 是 url-safe base64 編碼的 32 bytes；`InvalidToken` 表示 token 格式錯誤、簽章不符或超過 ttl；「The encrypted message contains the current time when it was generated in *plaintext*」；MultiFernet「performs all encryption options using the *first* key in the list」，解密時依序嘗試每個金鑰；`rotate()` 以主要金鑰重新加密並保留原本的時間戳記；換版的做法是把新金鑰放在最前面、rotate 既有的 token，再移除舊金鑰；AES-128-CBC、PKCS7、HMAC-SHA256；適合放得進記憶體的資料。T08 的 secret 加密與 `rotate-secret-keys`（`DECISIONS.md` §12.1、§12.3） |
| S70 | [Fernet Spec](https://github.com/fernet/spec/blob/master/Spec.md) | token 是 `Version ‖ Timestamp ‖ IV ‖ Ciphertext ‖ HMAC`：Version 8 bits（0x80）、Timestamp 64 bits、IV 128 bits、Ciphertext 是 128 bits 的倍數、HMAC 256 bits，以 base64url 編碼；key 是 signing key 與 encryption key 各 128 bits。T08 的 DB 以 CHECK 確認密文以 `gAAAAA` 開頭（版本 0x80），並由最大的明文推算長度上限 |
| S71 | [PyPI — cryptography 50.0.2](https://pypi.org/project/cryptography/50.0.2/) | 2026-09-30 發布（最早的檔案 2026-09-30T14:43Z）；license expression `Apache-2.0 OR BSD-3-Clause`；`requires_python` 為 `!=3.9.0,!=3.9.1,>=3.9`；有 `cp311-abi3-macosx_11_0_arm64` 等 wheel；依賴 `cffi>=2.0.0`。T08 新增的執行期依賴 |
| S72 | [RFC 6750 — OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750) | §2.1：`b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`、`credentials = "Bearer" 1*SP b64token`；§5.3：bearer token 不應放在 URL 中。T08 的 bearer secret 只收 b64token |
| S73 | [RFC 6265 — HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265) | §4.1.1：`cookie-pair = cookie-name "=" cookie-value`、`cookie-name = token`、`cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )`、`cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E`（不含控制字元、空白、雙引號、逗號、分號與反斜線）；§4.2.1：`cookie-string = cookie-pair *( ";" SP cookie-pair )`；§4.2.2：同名的 cookie 出現兩次時，伺服器不應依賴它們的順序。T08 的 cookie secret 只收這個文法，並拒絕重複的名稱 |
| S74 | [PostgreSQL — Partial Indexes](https://www.postgresql.org/docs/current/indexes-partial.html) | Example 11.3：`CREATE UNIQUE INDEX … WHERE success`，「This enforces uniqueness among the rows that satisfy the index predicate, without constraining those that do not」。T08 以 `WHERE encrypted_secret IS NOT NULL` 保證每個 profile 最多一份密文 |
| S75 | [OWASP WSTG — Test HTTP Methods](https://github.com/OWASP/wstg/blob/master/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/06-HTTP_Methods.md) | HTTP Method Overriding：有些框架以 `X-HTTP-Method`、`X-HTTP-Method-Override`、`X-Method-Override` 覆寫實際的 method，目的常是繞過擋下特定 method 的中介者；也有框架以 `_method` 參數覆寫。T08 的 api_key_header 拒絕這三個 header；`_method` 留給 guard（T11） |
| S76 | [PortSwigger Web Security Academy — Access control](https://portswigger.net/web-security/access-control) | 「Broken access control resulting from platform misconfiguration」：有些框架支援以 `X-Original-URL`、`X-Rewrite-URL` 覆寫請求的 URL，前端依 URL 限制時可以被繞過。T08 的 api_key_header 拒絕這兩個 header |
| S77 | [httpoxy](https://httpoxy.org/) | 「RFC 3875 (CGI) puts the HTTP `Proxy` header from a request into the environment variables as `HTTP_PROXY`」，信任這個環境變數的 HTTP client 就把對外的請求送往攻擊者指定的代理；CVE-2016-5385（PHP）、CVE-2016-5386（Go）、CVE-2016-5387（Apache HTTP Server）、CVE-2016-1000110（Python CGIHandler）等；建議「block `Proxy` request headers as early as possible」，這個 header 不是 IETF 定義的。T08 的 api_key_header 拒絕 `Proxy`（審查後補上） |
| S78 | [PortSwigger Web Security Academy — Exploiting HTTP Host header vulnerabilities](https://portswigger.net/web-security/host-header/exploiting) | 「Inject host override headers」：除了 `X-Forwarded-Host`，還有 `X-Host`、`X-Forwarded-Server`、`X-HTTP-Host-Override`、`Forwarded` 等作用相同的 header。T08 的 api_key_header 拒絕這些 header（`X-Forwarded-*` 以前綴拒絕） |
| S79 | [IETF — The Idempotency-Key HTTP Header Field（draft-ietf-httpapi-idempotency-key-header-08，2026-10-22）](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/) | 「Idempotency-Key is an Item Structured Header Field」，值是 String，範例 `Idempotency-Key: "8e03978e-40d5-43e8-bc93-6894a57f9324"`；缺少 key 時「SHOULD reply with an HTTP 400」；同一個 key 搭配不同內容「SHOULD reply with an HTTP 422」；原請求還在處理時「SHOULD reply with an HTTP 409」；「Uniqueness of the key MUST be defined by the resource owner」；期限由資源定義並寫在文件中；「An idempotency fingerprint MAY be used in conjunction with an idempotency key」。仍是草案。T09 的 `POST /scans`（`DECISIONS.md` §13.2） |
| S80 | [PostgreSQL — Client Connection Defaults](https://www.postgresql.org/docs/current/runtime-config-client.html) | `statement_timeout`、`lock_timeout`、`idle_in_transaction_session_timeout` 預設 0（關閉），沒有單位時是毫秒；前兩者「Setting … in postgresql.conf is not recommended because it would affect all sessions」；`lock_timeout`「applies separately to each lock acquisition attempt」，且「if statement_timeout is nonzero, it is rather pointless to set lock_timeout to the same or larger value」；`idle_in_transaction_session_timeout` 終止整個 session。T09 的連線逾時（`DECISIONS.md` §13.8） |
| S81 | [PostgreSQL — Error Codes（Appendix A）](https://www.postgresql.org/docs/current/errcodes-appendix.html) | 55P03 `lock_not_available`、57014 `query_canceled`、25P03 `idle_in_transaction_session_timeout`、23505 `unique_violation`、40P01 `deadlock_detected`。T09 把等鎖與查詢逾時對應到 503 |
| S82 | [PostgreSQL — CREATE TABLE](https://www.postgresql.org/docs/current/sql-createtable.html) | `GENERATED ALWAYS AS IDENTITY`：INSERT 指定的值只在 `OVERRIDING SYSTEM VALUE` 時接受，UPDATE 成 DEFAULT 以外的值一律拒絕；「MATCH SIMPLE allows any of the foreign key columns to be null; if any of them are null, the row is not required to have a match」，MATCH SIMPLE 是預設；`ON DELETE RESTRICT`。T09 的 `queue_position` 與 scan 的複合 FK |
| S83 | [wollomatic/socket-proxy — README](https://github.com/wollomatic/socket-proxy)；[Releases](https://github.com/wollomatic/socket-proxy/releases)；Docker Hub `wollomatic/socket-proxy` | 每個 HTTP method 一個 regex（`-allowGET` 等），「`^` and `$` are added automatically」，沒有設定的 method 一律拒絕；`-allowfrom` 預設只允許 127.0.0.1，可以寫主機名稱；`-allowbindmountfrom` 檢查 container create 等端點的 body，只放行列出目錄下的 host bind，`VolumesFrom` 拒絕，named volume 不算 bind，「is a request filter, not a sandbox」；不限制 privileged、host namespace、capability 與 device；scratch 映像、`-allowhealthcheck`、`-watchdoginterval` 與 `-stoponwatchdog`。1.13.0（2026-08-08）修補 bind mount 的檢查；1.13.1（2026-08-15，`sha256:3935b709…`）只升 Go。T10 的 socket-proxy（`DECISIONS.md` §14.1） |
| S84 | [Tecnativa/docker-socket-proxy — haproxy.cfg](https://github.com/Tecnativa/docker-socket-proxy/blob/master/haproxy.cfg) | `http-request deny unless METH_GET \|\| { env(POST) -m bool }`：POST 是全域開關；`CONTAINERS` 的規則 `^(/v[\d.]+)?/containers` 沒有結尾錨點，`/containers/{id}/exec`、`/containers/{id}/archive` 也會放行。T10 不採用的理由 |
| S85 | [Docker SDK for Python — Change log](https://docker-py.readthedocs.io/en/stable/change-log.html)；[PyPI docker](https://pypi.org/project/docker/) | 7.2.0（2026-07-09）：「Added subpath support for volumes」；「docker.from_env() now honors the active Docker CLI context when DOCKER_HOST is not set」。7.1.0 的預設 API 版本 1.44。T10 的 runner 用低階 `APIClient`、版本固定 1.45 |
| S86 | [Docker Engine API — Version history](https://docs.docker.com/reference/api/engine/version-history/) | v1.45：`POST /containers/create` 的 `Mounts` 可以用 `VolumeOptions.Subpath` 只掛載 volume 的子目錄。T10 的掃描容器只以 subpath 掛載該 run 的目錄 |
| S87 | [mitmproxy — Options](https://docs.mitmproxy.org/stable/concepts/options/) | `connection_strategy`（預設 eager）、`upstream_cert`、`http2`、`http3`、`websocket`、`rawtcp`、`ignore_hosts`、`tcp_hosts`、`body_size_limit`、`stream_large_bodies`、`validate_inbound_headers` 等選項的語意。T11 的 guard 逐一設定並讀回核對（`DECISIONS.md` §15.2） |
| S88 | [mitmproxy — Event Hooks](https://docs.mitmproxy.org/stable/api/events.html) | `requestheaders`、`request`、`http_connect`、`server_connect`（「Setting `data.server.error` kills the connection」）、`client_connected`（設定 `client.error` 中止）、`tcp_start`、`websocket_start` 等 hook 的時機。T11 的 addon |
| S89 | [mitmproxy 12.2.3 原始碼](https://github.com/mitmproxy/mitmproxy/tree/v12.2.3)（從鎖定 digest 的映像取出） | `proxy/layers/http/__init__.py`：origin-form 轉換在 `requestheaders` 之前、addon 設定 response 時不建立上游連線、streaming 在 `request` hook 之前就連線；`http.py`：設定 `host` 會改寫 Host、`method` 轉成大寫；`addonmanager.py` 的 `safecall` 吞掉 addon 的例外；`master.py` 與 `addons/errorcheck.py` 的啟動檢查。T11 的實測對照（`DECISIONS.md` §15） |
| S90 | [mitmproxy discussion #5255 — Running mitmproxy from a Python script](https://github.com/mitmproxy/mitmproxy/discussions/5255) | 在 `asyncio.run` 中建立 `DumpMaster`、`addons.add()` 再 `await master.run()` 的嵌入用法。T11 的 `run_guard.py` |
| S91 | [PyPI — mitmproxy 12.2.3](https://pypi.org/project/mitmproxy/12.2.3/) | 相依：`cryptography<=48.1,>=42.0`、`typing-extensions<=4.14,>=4.13.2`（python < 3.13）；映像內 `importlib.metadata` 讀到相同的值。與 uv.lock（50.0.2、4.16.0）衝突，guard 改以官方映像執行 |
| S92 | [moby/moby#47589](https://github.com/moby/moby/pull/47589)；[CVE-2024-29018](https://github.com/moby/moby/security/advisories/GHSA-mq39-4gv4-mvpx) | Docker Engine 26 起，只接 internal network 的容器不再經宿主轉送外部 DNS 查詢（修補經 DNS 外洩資料的問題）。T11 的 scan_net 與 lab_net |
| S93 | [RFC 9112 §3.2.2 — absolute-form](https://www.rfc-editor.org/rfc/rfc9112#section-3.2.2) | proxy 收到 absolute-form 的請求時，以 request target 的 authority 取代 Host。T11 的 guard 要求兩者逐字相同，並把 Host 寫回 canonical 的值 |
| S94 | [ZAP — AF Environment](https://www.zaproxy.org/docs/desktop/addons/automation-framework/environment/) | context 的 urls、includePaths／excludePaths、`env.parameters.maxDuration`（秒）、`${變數}` 的代換。T14 的 AF plan（`DECISIONS.md` §18.4） |
| S95 | [zap-extensions — ExtensionAutomation.java](https://github.com/zaproxy/zap-extensions/blob/main/addOns/automation/src/main/java/org/zaproxy/addon/automation/ExtensionAutomation.java)、[AutomationPlan.java](https://github.com/zaproxy/zap-extensions/blob/main/addOns/automation/src/main/java/org/zaproxy/addon/automation/AutomationPlan.java)、[ContextWrapper.java](https://github.com/zaproxy/zap-extensions/blob/main/addOns/automation/src/main/java/org/zaproxy/addon/automation/ContextWrapper.java) | maxDuration 到期以 `stopPlan(false)` 停止、`alwaysRun` 的 job 仍執行；退出碼 1（錯誤）、2（警告）；context 的每個 url 成為 `url.*` 的 include。T14（§18.4、§18.5） |
| S96 | [zaproxy — HttpSenderAuthHeaderListener.java](https://github.com/zaproxy/zaproxy/blob/main/zap/src/main/java/org/zaproxy/zap/extension/authentication/HttpSenderAuthHeaderListener.java) | `ZAP_AUTH_HEADER_SITE` 以 `getHostName().contains()` 比對；以 `setHeader` 覆寫同名的 header。T14（§18.2） |
| S97 | [zap-extensions — RateLimitOptions.java、RateLimitRule.java](https://github.com/zaproxy/zap-extensions/tree/main/addOns/network/src/main/java/org/zaproxy/addon/network/internal/ratelimit)、[Rate Limit](https://www.zaproxy.org/docs/desktop/addons/network/options/ratelimit/) | `network.ratelimit.rules.rule(i).{description,enabled,matchStr,regex,reqsPerSec,groupBy}`；以 host 完整比對。T14 的 zap.properties（§18.3） |
| S98 | [zaproxy — zap.sh](https://github.com/zaproxy/zaproxy/blob/main/zap/src/main/dist/zap.sh)、[Dockerfile-stable](https://github.com/zaproxy/zaproxy/blob/main/docker/Dockerfile-stable) | `zap.sh` 只認 cgroup v1 的記憶體上限、接受 `-Xmx…` 參數；映像以 zap(1000) 執行、`HOME=/home/zap/`、宣告 HEALTHCHECK。T14（§18.2） |
| S99 | [ZAP — OpenAPI Automation Framework Support](https://www.zaproxy.org/docs/desktop/addons/openapi-support/automation/)、[OpenAPI Support](https://www.zaproxy.org/docs/desktop/addons/openapi-support/) | openapi job 的 `apiFile`、`targetUrl`；context 排除的端點不匯入；匯入時跟隨 redirect。T14（§18.4、§18.6） |
| S100 | [ZAP — Spider AF job](https://www.zaproxy.org/docs/desktop/addons/spider/automation/)、[activeScan AF job](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/) | spider 的 `postForm`、`parseRobotsTxt`、`threadCount`；activeScan 的 `policyDefinition`（`defaultThreshold`、`rules`）、`threadPerHost`。T14（§18.4） |

## 需要在 M0–M2 實際確認的事項

> T03（2026-10-17）已完成以下 1–6 針對三個引擎與 egress 的 M0 部分，結果與證據見 `TOOLS.md`。第 7 項由 T10（2026-10-27）完成：改用 wollomatic/socket-proxy，逐一放行 method＋path（`DECISIONS.md` §14.1），以 live 測試確認。DNS/IP 綁定、redirect 重檢、HTTPS CA 等留待 T11。


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
7. docker-socket-proxy 讓 runner 能 create/start/stop/wait/取回 archive 所需的最小開關組合（T10：只放行 create、start、stop、刪除與查詢；不用 wait 與 archive，改為輪詢狀態、從 volume 收集輸出）。

## 來源與推論的界線

- 工具支援哪些功能，取自上述官方文件。
- 以下都是本計畫提出的工程方案或待驗證的假設，不是官方保證，也不是市場調查結果：
  - 後端框架與工作佇列的選擇
  - 工期、人數、預算
  - 驗收指標、去重設計
  - 專題定位
- 兩份規劃的比較與取捨記錄在 `DECISIONS.md`。
