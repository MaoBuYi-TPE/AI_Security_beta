# 一手技術來源

查核日期：S01–S19 為 2026-10-15；S20–S31 為 2026-10-16。以下是選型與設計的參考，不代表已在本專題環境驗證過相容性或效能。官方 stable 文件可能會變動；實作時需同時記錄已安裝的版本、CLI help 與 Parser fixture。

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
