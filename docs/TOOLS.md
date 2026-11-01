# 工具相容性與 spike 結果（T03）

- 日期：2026-10-17
- 狀態：**已完成**。在隔離 lab 上以真實工具驗證；原始輸出與量測保存在本機 `runs/spike-t03/`（未進 git），遮罩後樣本在 `tests/fixtures/`。
- 環境：Apple M1 Pro、16 GB、macOS、OrbStack 2.2.1（Docker Engine 29.4.0、linux/arm64、cgroup v2）。OrbStack 記憶體上限實測為 **8 GiB**（規劃假設 10–12 GB，需在 M3 ZAP active scan 時留意）。
- `docker compose` 子命令不可用（無 cli-plugins），全程以 `docker-compose` v5.1.2 執行；`make` 會自動選擇。
- 重現方式見 `spikes/t03/README.md`。本文的數字是這次 spike 的實測值，不是驗收保證。

## 1. 映像相容性

所有映像皆為 `linux/arm64`，以 index digest 鎖定（`docker image inspect` 的 RepoDigests）。授權由各上游 repo 的 LICENSE 查核。

| 映像 | 版本 | index digest | 授權 | 容器 user | read-only rootfs |
|---|---|---|---|---|---|
| zaproxy/zap-stable | 2.17.0（tag 20261016） | sha256:5ccfff9a4117… | Apache-2.0 | zap(1000)；T14 起以 10001 執行 | 可（T14：tmpfs `/tmp` 768 MiB、noexec，`-dir /tmp/zap`；見 §7） |
| projectdiscovery/nuclei | v3.11.1 | sha256:582d5546902e… | MIT | root | 可（tmpfs `/root/.config`、`/root/.cache`、`/tmp`） |
| schemathesis/schemathesis | 4.31.1 | sha256:e6d34d7defc8… | MIT（但含 tracecov，見下） | schemathesis(1000) | 可（`--generation-database none` + 可寫 report-dir + tmpfs `/tmp`） |
| mitmproxy/mitmproxy | 12.2.3 | sha256:00b77b5d8804… | MIT | 1000（需覆寫 entrypoint） | 可（confdir tmpfs 需 mode 01777） |
| bkimminich/juice-shop | v20.3.0 | sha256:cea5a4af4aac… | MIT | 65532（distroless，node 在 `/nodejs/bin/node`，無 shell） | **不相容**（見 §5） |
| erev0s/vampi | latest | sha256:0a5a224b6e14… | MIT | root | 可（tmpfs `/tmp`、`/vampi/database`） |
| busybox | 1.38.0 | sha256:fd7dc98638c8… | GPL-2.0-only（僅作 probe，不散布） | root | — |
| wollomatic/socket-proxy（T10 加入） | 1.13.1 | sha256:3935b709275e… | MIT | 以 `65534:0` 執行（OrbStack VM 內 docker.sock 是 root:root 0660） | 可（scratch 映像） |
| python（T10，secscan 映像的基底） | 3.12.15-slim-bookworm | sha256:6a0e06f5ba0b… | PSF-2.0 | secscan 映像以 10001 執行 | 可（`/tmp` 用 tmpfs） |
| astral-sh/uv（T10，只在建置階段） | 0.13.1 | sha256:4a1f3666816d… | MIT／Apache-2.0 | — | — |
| secscan-guard（T11，egress guard） | 基底 mitmproxy/mitmproxy 12.2.3（Python 3.14.5） | 基底 sha256:00b77b5d8804… | MIT（基底） | 10001（不用映像的 entrypoint，直接以 `python3 -I -B` 執行啟動程式） | 可（confdir 在 `/tmp` 的 tmpfs；映像宣告的 VOLUME 另掛空的 tmpfs） |

- **tracecov**：schemathesis 映像預設 `SCHEMATHESIS_COVERAGE=true`，會載入 `tracecov`（PyPI 0.25.3，授權 `LicenseRef-TraceCov-Community-1.0`，**非 OSI**、限 Internal Use、會寫 `/app`）。本專題一律設 **`SCHEMATHESIS_COVERAGE=false`** 關閉，避免授權與唯讀 rootfs 問題。
- **T10 的 busybox**：fake 引擎的掃描容器改以 `10001:10001`、唯讀 rootfs 執行 `/bin/sleep`／`/bin/false`（live 測試通過）。
- **mitmproxy entrypoint**：預設 entrypoint 需 root（跑 `usermod` 再 `gosu`）。改以 `entrypoint: [mitmdump]` + `user: "1000:1000"` 直接啟動。
- **T11 的 guard 映像**（`deploy/guard/Dockerfile`，`DECISIONS.md` §15.1）：FROM 上表的 mitmproxy digest，只 COPY guard 載入的 secscan 模組與 `run_guard.py`（屬於 root），以 10001 執行。`/home/mitmproxy` 是 0700、屬於 mitmproxy 使用者，10001 進不去，所以 confdir 改放 `/tmp/mitmproxy`。mitmproxy 自己在 `-W error` 下會因 pyparsing 的 DeprecationWarning 失敗（guard 不開 `-W error`；我們的模組在 3.14 以 `-W error` 載入沒有警告）。

## 2. Nuclei 模板

- release **v10.5.0**（2026-10-05），tag commit `f8b8b8dcd70d93826c3767e1829ef8243af9f03b`。
- 壓縮檔 sha256 `80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41`，解壓 14,036 個 yaml。
- spike（T03）曾選用 20 個 HTTP、info/low 模板驗證流程（`spikes/t03/nuclei/templates.lock.txt`），皆無 `unsafe`/OAST 外呼；那不是凍結清單，只是 spike 的小集合。

### 2.1 T17 凍結清單（精選、對準 lab）

- 清單：`src/secscan/scanners/domain/nuclei/templates.lock.txt`（每行 `id sha256 path`）；policy 在同目錄的 `policy.py`；產生器 `tools/freeze_nuclei_templates.py`（`make nuclei-templates`）；provenance 登錄在 `tests/fixtures/manifest.json` 的 `nuclei_templates`。理由見 `DECISIONS.md` §23。
- 產生方式：驗證 archive sha256 → 乾淨解壓 → 在鎖定映像裡**離線**（`--network none`）跑 `nuclei -tl -id <清單> -pt http -ni -duc`，再對每個模板過**內容閘門**（排除含 `javascript`／`flow`／`code`／`tcp`… 等非 http／多協定頂層鍵或 `fuzz`／`dast`／`dos`／`oast` tag 的模板；`-pt http` 擋不住多協定模板），算每檔 sha256。不連任何目標、不出網（開發動作，比照 `make images`）。
- 規模：**42 個模板**（初版 46，審查移除 3 個含 `javascript:` 的 cookie／目錄列舉模板與 1 個會改 Host 的 `host-header-injection`，見 `DECISIONS.md` §23）。lock sha256 `1d97a25695a25bd5130a37beb5fb1e78988eed541456ed4be702171f1ecefc81`；定義 sha256（release／commit／旗標／每個 id·sha256·path 的 canonical JSON）`504ac80c34da54738903d4937d770cc618d4514f53b2d05cd7ed1579ac061469`。
- 執行設定：`-ni -duc -pt http -jsonl -silent`（T18 的 ExecutionPlan 以此組裝，每個 run 另加 `-id`／`-sf`／`-p`／`-o`／`-u` 與凍結速率/並行）。`-ni` 同時排除 OAST 類模板；code／headless／file／fuzz 在 nuclei 預設不載入。`-sf` 的 `domains` 完全比對 host:port（§6、S36）。

逐類別審查（DoD：以類別為單位審查、抽查高風險）：

| 類別 | 數量 | 選入（代表模板） | method／guard 相容性與高風險抽查 |
|---|---|---|---|
| exposures | 8 | openapi、swagger-api、wadl-api、wsdl-api、git-config、git-exposure、phpinfo-files、ds-store-file | 多為 GET 讀取偵測；wadl-api 另送 OPTIONS |
| miscellaneous | 15 | robots／sitemap／security.txt、dir-listing、options-method、http-trace、clientaccesspolicy、email／卡號／版權年份外洩偵測等 | options-method 送 OPTIONS、http-trace 送 TRACE（grant 不允許 TRACE 時為平台阻擋）；directory-listing 因 flow 腳本（非純 http）被內容閘門移除，改用 dir-listing |
| misconfiguration | 4 | http-missing-security-headers、missing-cookie-samesite-strict、xss-deprecated-header、exposed-docker-api | 皆 GET；http-missing-security-headers 是 negative matcher，T18 須濾掉 guard 的 403 拒絕回應以免誤報；HttpOnly／Secure 旗標的模板用 javascript 協定被移除，改由 ZAP 被動規則涵蓋 |
| technologies | 9 | tech-detect、fingerprinthub、favicon、waf-detect、flask-detect、werkzeug-debugger-detect、angular-detect、express-default-page、graphql-detect | 多為 GET；**waf-detect 送 POST /（帶 `<script>` 測試字串）、graphql-detect 送 POST 到多個候選 path（introspection）**，需 grant 允許 POST |
| vulnerabilities/generic | 6 | cors-misconfig、crlf-injection-generic、error-based-sql-injection、xss-uri-reflected、open-redirect-generic、generic-env | 主動探測（`ACTIVE_PROBE_TEMPLATE_IDS`），和 ZAP active scan 同類、只對已核准 grant 的 lab 執行；strict-1 下帶 % 的 path 探測多被 `PATH_AMBIGUOUS` 擋（xss-uri-reflected 全擋、open-redirect 82/94 擋） |

- 內容閘門與移除：`-pt http` 擋不住多協定模板，因此產生時以 `selection.template_violations` 讀全文把關；初版移除 `cookies-without-httponly`／`-secure`（含 `javascript:`）、`directory-listing`（含 `flow:` 與 `fuzz` tag）與 `host-header-injection`（改 Host，guard 一律 `ORIGIN_MISMATCH`）。
- 多來源（M4）：Nuclei 與 ZAP 疊同一問題（SQLi/XSS/CRLF/open-redirect/CORS）目前是**候選假設**；strict-1 的 guard 會擋掉多數帶 % 的 path 探測，實際可達性與重疊待 T18 量測後如實記載（見 `DECISIONS.md` §23.4）。
- 重現性：`make nuclei-templates-check`（或 `ENABLE_LIVE_LAB_TESTS=1` 下的 `tests/live/test_nuclei_templates_live.py`）重跑列舉並與已提交的 lock 逐位元組比對。
- 範圍限制：只收對準 lab 的通用＋技術棧模板，不含本 lab 不存在的特定產品模板；最終類別簽核由使用者確認（效度威脅，見 `DECISIONS.md` §23.4）。

## 3. 網路拓撲與隔離（DoD：直連必須失敗）

兩個網路都 `internal: true` + `gateway_mode_ipv4: isolated`（OrbStack Engine 29 接受）+ 固定子網 + 關閉 IPv6，無任何對外 port。

```text
scan_net 10.89.8.0/24：probe、zap、nuclei、schemathesis ──► guard-spike(10.89.8.10)
lab_net  10.89.7.0/24：guard-spike ──► juice-shop、vampi-vuln、vampi-secure、canary
```

直連檢查結果（接收端以 canary / 靶機 log 佐證）：

| # | 動作 | 結果 |
|---|---|---|
| D1 | scan_net 不經 proxy 連 vampi-vuln:5000 | 名稱解析不到（SERVFAIL），wget bad address ✅ |
| D2 | scan_net 不經 proxy 連 lab 容器 IP | Network is unreachable ✅ |
| D3 | scan_net `ip route` / 解析 example.com | 只有 link route、無 default；外部 DNS SERVFAIL ✅ |
| D4 | probe 帳密 → canary | 200；canary 收到請求，且 header 無 `Proxy-Authorization`（guard 已移除）✅ |
| D5 | 掃描器帳密（zap）→ canary（不在其 allowlist） | 403 not-in-allowlist；canary **沒有**收到 ✅ |
| D6 | 無/錯誤帳密 → guard | 407 ✅ |
| D7 | 各工具不設 proxy 直接掃 | 工具失敗、guard 計數 0、靶機無對應請求 ✅ |

- **isolated + internal 的額外結論（供 M2 SEC-06）**：OrbStack 下，這組設定讓容器連 `host.docker.internal` 都解析不到（SERVFAIL），外部 IP 一律 Network unreachable。內建 DNS 不轉送外部查詢。
- guard JSONL 顯示被 allow 的請求上游 IP 全部落在 `10.89.7.0/24`（= `LAB_CIDR` 候選）。

## 4. 各工具驗證（TASKS 要求逐項）

量測摘要（本次 spike 值）：

| run | 工具 | 目標 | 牆鐘 | 結果 | guard（allow/deny） |
|---|---|---|---|---|---|
| Z1 | ZAP spider+passive | juice-shop | 20s | 4 passive 告警，報告 traditional-json | 13 allow（+14 reactive-auth 407） |
| Z2 | ZAP openapi+passive（Bearer） | vampi-vuln | 13s | 報告產生；1 筆 DELETE 被擋 | 12 allow / 13 auth-407 / 1 method-deny |
| N1 | Nuclei（20 模板） | juice-shop | 4s | 13 findings | 26 allow |
| N2 | Nuclei（+`-sf` bearer） | vampi-vuln | 4s | 14 findings | 27 allow，全部帶 Authorization |
| S1（量測） | Schemathesis（max-examples=15） | vampi-vuln | 7s | 314 cases / 16 unique failures | 316 allow，79 帶 auth |

> 上表是量測 run 的數字。**提交到 `tests/fixtures/` 的 Schemathesis 三個格式**（JSON/NDJSON/JUnit）另取自一次 max-examples=2 的 compact run（119 generated / 14 unique failures），讓三格式一致且 NDJSON 不超過 pre-commit 500 KB 限制；各 fixture 的 run 標在 `manifest.json` 的 `run_id`。實際執行命令與每個掃描容器的隔離旗標見 `spikes/t03/run_scans.sh`。

- **ZAP upstream proxy 設定鍵**：`network.connection.httpProxy.{enabled,host,port,authEnabled,username,password}`，以 **`-configfile`（0400 檔）** 注入。確認報告格式 `traditional-json`：`site[].alerts[].{alert,alertRef,name,riskcode,confidence,cweid,count,desc,instances[].{method,uri,param,evidence,attack}}`。
- **ZAP `-silent`**（Z0，經你核准的對照）：不加 `-silent`，ZAP 啟動即對 `news.zaproxy.org`、`tel.zaproxy.org` 發 3 次請求（HTTPS CONNECT，被 guard `deny:connect`）；加 `-silent` 後為 0。確認 `-silent` 擋掉 ZAP 自身對外。
- **ZAP proxy 密碼不洩漏**：`-configfile` **不會**把設定值回顯到 log（與 `-config` CLI 會印 `Setting config … = …` 不同）；log 中搜不到密碼。→ M2 可安全以 configfile 注入（仍建議每 run 專屬帳密）。
- **ZAP 認證注入**（Z2）：`ZAP_AUTH_HEADER_VALUE`/`_SITE` 於啟動時注入 Bearer，`_SITE` 以 host 子字串比對 `vampi-vuln` 成立；guard 看到 26 筆皆帶 Authorization。
- **ZAP reactive proxy auth**（給 M2 預算）：ZAP 每個請求先不帶 `Proxy-Authorization` → 407 → 再帶帳密重送，故 guard 會看到約 2× 請求數，真正到 target 的是 authed 的一半。
- **Nuclei `-sf` 格式**（N2）：`static: - type: bearertoken` + `domains: [vampi-vuln:5000]`；`domains` 以不分大小寫、**完全比對 host:port**（只去掉 :80/:443），寫成 `vampi-vuln:5000` 命中，27 筆全注入 Bearer。
- **Nuclei 經 proxy 的 DNS**（N1）：以 `-p <檔案>`（填 guard IP）設 HTTP proxy 後，target 流量全部經 guard（upstream = 靶機 lab IP），Nuclei **不需自行解析**靶機名稱（scan_net 無 DNS 仍可運作）。
- **Schemathesis `--proxy` 與 NDJSON**（S1）：`proxy`、`[auth.openapi.bearerAuth] bearer` 於 `schemathesis.toml` 以 `${ENV}` 帶入；`--report ndjson,json,junit` 三種格式都取得。`max-examples` 需放 `[generation]`；exit code 1 = 有 failure。
- **Docker volume subpath**：各工具以 `runs` 子目錄 `in/`（唯讀）、`out/`（可寫）掛載，驗證可行。
- **秘密注入方式**：Bearer 經環境變數或 `-sf`/`-configfile` 檔案注入，均**不在命令列 argv**（`docker inspect` 的 `.Args` 無秘密）；guard 以 Authorization 的 sha12 前綴確認實際有送出，但不記錄明文。注意：以環境變數注入時（ZAP 的 `ZAP_AUTH_HEADER_VALUE`、Schemathesis 的 `ST_TOKEN`／含密碼的 `ST_PROXY`）仍會出現在 `docker inspect` 的 `.Config.Env`，CLAUDE.md §9 允許 env 注入；M2 建議 proxy 憑證改走 0400 檔（ZAP 已用 `-configfile`）。

## 5. 限制與 blocked

- **Juice Shop 不相容 read-only rootfs**：啟動要寫 `/juice-shop/logs`（access.log，EROFS）、`/juice-shop/ftp`（EACCES）、`data/` 下 SQLite（SQLITE_CANTOPEN），逐一 tmpfs 會蓋掉已播種資料。本 spike 對 Juice Shop 放寬 `read_only`，保留 `cap_drop: ALL` 與 `no-new-privileges`。靶機本身非安全邊界（邊界是網路隔離 + guard）。
- **VAmPI**：以 root 執行、`debug=True`（500 會回 Werkzeug debugger HTML）、Token 預設 60s 過期 → lab 設 `tokentimetolive=3600`，掃描前後以 `GET /me` 確認。spec `servers` 為 `http://localhost:5000`，需以 ZAP `targetUrl` / Schemathesis `--url` 覆寫。
- **Schemathesis NDJSON 體積**：15 例的 NDJSON 達 730 KB（超過 pre-commit 500 KB 限制），故 committed fixture 另以 `max-examples=2` 重錄（65 KB）；完整檔保存在本機 `runs/spike-t03/`。
- 未執行（選做）：Z3/N3/S2（vampi-secure 負控制組）、ZAP active scan。留待 M3 的 ZAP Adapter。

## 6. 給後續里程碑的輸入

- **M2 egress guard**：`guard_spike.py` 只是量測與最小 allowlist，M2 需補 DNS/IP 綁定、共享預算、redirect 重檢、HTTPS、policy volume。注意 ZAP reactive auth 對預算計數的影響；proxy 帳密可用 configfile 注入而不洩漏。
- **M3 ZAP**：報告 schema 已確認；active scan 的記憶體與耗時需在 8 GiB 上實測調整預算。
- **M4 Nuclei**：`domains-regex` 未錨定（會子字串命中），凍結清單時要用 `domains` 完全比對或錨定的 regex。
- **M6 Schemathesis**：coverage phase 會嘗試非規格 method（TRACE/QUERY/PATCH），M2 guard 需依 grant 限制 method；NDJSON 事件結構見 fixture。

## 7. T14：ZAP 的離線量測與規則審查（2026-10-30）

鎖定的映像 `zaproxy/zap-stable:20261016@sha256:5ccfff9a…`（2.17.0，arm64，1.17 GB）。量測一律在宿主以 `--network none` 執行（不連任何目標），結果決定 `DECISIONS.md` §18 的設定。

### 7.1 映像與強化設定

- `docker image inspect`：User 是 `zap`（1000）、`HOME=/home/zap/`、沒有 VOLUME；宣告 `HEALTHCHECK CMD-SHELL curl … http://localhost:$ZAP_PORT/`（每 30 秒在容器內執行）→ create 的 body 一律 `Healthcheck: {"Test": ["NONE"]}`。
- 以掃描容器的旗標啟動最小的 AF plan（只有 report job）：uid 10001、唯讀 rootfs、`--tmpfs /tmp:rw,noexec,nosuid,nodev,size=768m,mode=1777`、`-dir /tmp/zap`、`cap_drop ALL`、no-new-privileges、`--init`、`nofile` 1024、3 GiB（不能用 swap）、1024 個 pid、2 個 CPU：**13–15 秒以 0 結束**，報告寫到唯讀掛載之外的 out/。`noexec` 的 tmpfs 可用。
- `zap.sh` 讀不到 cgroup v2 的記憶體上限，印出「Available memory: 8005 MB」（VM 的記憶體）→ 一律傳 `-Xmx1536m`。
- 雜訊：user.home 不可寫，Java 的 preferences 記一筆 WARNING；`--network none` 時 log4j 解析不到容器的主機名稱（scan_net 上 Docker 會寫 /etc/hosts）。都不影響 AF 的退出碼。

### 7.2 設定檔與輸出

- **`-configfile` 會記下值**：daemon 模式、沒有 `-nostdout` 時，stdout 有 `Setting config network.connection.httpProxy.password = <值> was null`（INFO）。以實際的指令（`-cmd -nostdout -configfile … -autorun …`）執行時 stdout **0 次**；值只在 ZAP home 的 `zap.log`（tmpfs）。T03 的「-configfile 不會回顯」只在當時的組合成立，`-nostdout` 是必要的旗標。
- `-configfile` 的 `network.connection.httpProxy.*` 與 `network.ratelimit.rules.rule(0).*` 以 ZAP 的 API 讀回：proxy 的 host、port、帳號、密碼、認證開啟，速率規則（`.*`、regex、2 req/s、RULE）都生效。
- `-nostdout` 時 AF 的進度（Job … started／finished、warnings、Automation plan succeeded!）仍輸出到 stdout，script 把它導向 `out/zap.log`。
- 退出碼：plan 有錯誤 1、有警告 2、否則 0（`ExtensionAutomation`）。`activeScan-policy` 遇到不存在的規則 ID 記 `Unrecognised active scan rule ID … : 90025`（警告）→ 退出 2：probe 以「退出碼 0」確認白名單的每條規則都存在。
- 產生的 web 與 api plan（`plan_zap_run` 的輸出）離線執行：每個參數都被 AF 接受（沒有 Unrecognised），只因 `--network none` 連不到目標而在 spider／openapi 失敗；`alwaysRun` 的 report 仍寫出。
- AF 的 context：每個 `urls` 都成為 `url + ".*"` 的 include（`ContextWrapper`，不跳脫）→ `excludePaths` 另加「完整比對不到任何一條允許的 regex」的負向前瞻。

### 7.3 add-on

`/zap/plugin` 中多數 add-on 有兩個版本的檔案（建置時 `-addonupdate` 留下的），ZAP 載入最大的版本（daemon 的 `autoupdate/view/installedAddons` 確認）。plan 用到、probe 核對的版本：ascanrules 84、automation 0.61.0、commonlib 1.44.0、network 0.31.0、openapi 58、pscan 0.6.0、pscanrules 76、reports 0.46.0、spider 0.20.0。

### 7.4 active scan 的規則白名單（53 條逐條審查）

以 daemon 的 `ascan/view/scanners`（容器內的 localhost）列出。白名單之外一律關閉（`defaultThreshold: off`）；web 以全部為基準、api 以映像內建的 `API-Minimal.policy` 為基準，再去掉排除的類別。

| ID | 規則 | web | api | 排除的理由 |
|---|---|---|---|---|
| 0 | Directory Browsing | ✓ | ✓ | |
| 6 | Path Traversal | ✓ | | API-Minimal 沒有 |
| 7 | Remote File Inclusion | ✓ | ✓ | |
| 10045 | Source Code Disclosure - /WEB-INF Folder | ✓ | | |
| 10047 | HTTPS Content Available via HTTP | | | HTTPS（P0 只有 HTTP） |
| 10048 | Remote Code Execution - Shell Shock | ✓ | | |
| 10058 | GET for POST | ✓ | | 把 POST 改成 GET：api 的 grant 不一定允許 GET |
| 10104 | User Agent Fuzzer | | | 雜訊 |
| 10106 | HTTP Only Site | | | HTTPS |
| 20015 | Heartbleed OpenSSL Vulnerability | | | 非 HTTP（直接的 TLS 連線） |
| 20017、20018 | Source Code Disclosure／Remote Code Execution - CVE-2012-1823 | ✓ | | 20018 一律送 POST：grant 不允許 POST 時不執行（`DECISIONS.md` §18.7） |
| 20019 | External Redirect | ✓ | ✓ | |
| 30001、30002 | Buffer Overflow、Format String Error | | | DoS 類 |
| 40003 | CRLF Injection | ✓ | ✓ | |
| 40008 | Parameter Tampering | ✓ | ✓ | |
| 40009 | Server Side Include | ✓ | ✓ | |
| 40012 | Cross Site Scripting (Reflected) | ✓ | | |
| 40014、40016、40017 | Cross Site Scripting (Persistent)、Prime、Spider | ✓ | | |
| 40018 | SQL Injection | ✓ | ✓ | |
| 40019–40022、40027 | SQL Injection（各資料庫的時間型） | | | 時間型：耗掉時間預算（T16 再評估） |
| 40026 | Cross Site Scripting (DOM Based) | | | 需要瀏覽器 |
| 40028、40029、40032、40034 | ELMAH、Trace.axd、.htaccess、.env Information Leak | ✓ | | |
| 40035 | Hidden File Finder | ✓ | | |
| 40042 | Spring Actuator Information Leak | ✓ | ✓ | |
| 40043 | Log4Shell | | | OAST |
| 40044 | Exponential Entity Expansion (Billion Laughs Attack) | | | DoS 類 |
| 40045 | Spring4Shell | ✓ | | 也送 POST：grant 不允許 POST 時不執行 |
| 40048 | Remote Code Execution (React2Shell) | ✓ | | 一律送 POST：grant 不允許 POST 時不執行 |
| 50000 | Script Active Scan Rules | | | 執行 script |
| 90017 | XSLT Injection | ✓ | ✓ | |
| 90019 | Server Side Code Injection | ✓ | ✓ | |
| 90020 | Remote OS Command Injection | ✓ | ✓ | |
| 90021 | XPath Injection | ✓ | ✓ | |
| 90023 | XML External Entity Attack | | | OUT_OF_BAND |
| 90024 | Generic Padding Oracle | ✓ | | |
| 90026、90029 | SOAP Action Spoofing、SOAP XML Injection | | | SOAP、beta |
| 90034 | Cloud Metadata Potentially Exposed | | | 改 Host、metadata 的位址 |
| 90035 | Server Side Template Injection | ✓ | ✓ | |
| 90036 | Server Side Template Injection (Blind) | | | OUT_OF_BAND |
| 90037 | Remote OS Command Injection (Time Based) | | | 時間型 |
| 100043 | Swagger UI Secret & Vulnerability Detector | | | alpha |

web 31 條、api 13 條、排除 22 條。probe 以鎖定的映像執行兩份白名單：13 秒、退出 0（44 條都存在）。

### 7.5 live 量測（`make test-live-zap`，2026-10-31）

- **環境**：
  - 獨立的 `secscan-live` 專案，API 加上只給 live 的預覽開關。
  - 掃描的是 live 自己 lab 網路上的小型網站（`tests/live/zap_site.py`，10.89.10.210），旁邊有一個 canary（10.89.10.211）。
  - 每個情境用新的 project、target 與 grant。
- **結果**：
  - 審查的修正之前與之後各跑一次，都是 8 passed（8 分 04 秒、7 分 46 秒），跑完沒有殘留的容器、volume、網路。
  - 下列數字是 guard 的決策 log 與網站的收包紀錄。兩次不同的地方分別標出「修正前」「修正後」。

**probe**：
- `GET /scanners` 的 zap 顯示 2.17.0、`integrated: false`。
- probe 容器已刪除。

**web、anonymous**：
- 設定：grant 是整個 origin、排除 `/admin`、只允許 GET 與 HEAD；`max_duration_seconds` 240。
- run 是 collected，manifest 有 `zap-report.json` 與 `zap.log`，報告的 `@version` 是 2.17.0、site 只有 target。
- **修正前**：guard 放行 281 個。拒絕的有：
  - 407 `PROXY_AUTH_REQUIRED`：GET 14、POST 22。ZAP 先不帶 proxy 認證送出、收到 407 才帶上（challenge-response；哪些請求會先被 407 沒有逐一確認）。這些在辨識 run 之前就被拒，不轉送、不算預算。
  - `METHOD_NOT_AUTHORIZED`：POST 30。
- **grant 不允許 POST，ZAP 仍送出 POST**：
  - 共 52 個（含 407 的 22 個），全部被 guard 擋下，網站一個也沒收到。plan 的 `postForm` 是關閉的。
  - ZAP 的原始碼（zap-extensions main 分支）：20018（CVE-2012-1823 RCE）與 40048（React2Shell）一律送 POST，40045（Spring4Shell）先送 GET、再送 POST。
  - 改成 grant 不允許 POST 時不執行這三條（`DECISIONS.md` §18.7）。
- **修正後**：guard 放行 272 個，拒絕的只有 407 GET 14，**POST 是 0**。
- 網站只收到 GET 與 HEAD，沒有 `/admin`，沒有任何認證 header。canary 沒有連線，guard 只看到 target 的 host 與 port。
- **大於 1 MiB 的回應**：2 MiB 的 `/static/big.js` 取得成功。guard 的 `body_size_limit`（16 MiB）沒有擋下 2 MiB 的回應，這回答了 T12 的交接。
- 容器：Env 是 `SECSCAN_TARGET_AUTH=none`，沒有任何 `ZAP_AUTH*`；唯讀 rootfs、uid 10001。proxy 的 token 不在 `zap.log` 與報告中。

**api、bearer**：
- 設定：grant 是 `/api/items`、`/api/items/{id}`、`/me`，只允許 GET；240 秒。
- 上傳的規格另外含有：
  - `DELETE /items/{id}`
  - `links`、`discriminator`
  - 指向 canary 的 URL：contact、license、externalDocs、servers、schema 的 `id`、example
- guard 放行 15 個。拒絕的有：407 GET 76、`PATH_AMBIGUOUS` GET 136、`PATH_NOT_AUTHORIZED` GET 12。
- **path 中的 `%`（T11 的交接）**：
  - ZAP 對 path 參數的攻擊幾乎都以百分比編碼送出，例如 `/api/items/%00`、`%22`、`%22%27`。guard 依 `DECISIONS.md` §15.10 以 `PATH_AMBIGUOUS` 拒絕。
  - 扣掉 407 之後的 163 個請求，有 136 個（83%）是這一類。
  - path 參數的注入在目前的 guard 下**實際上測不到**：維持 fail closed，覆蓋的缺口在 T16 量化，並在報告中揭露。
- `PATH_NOT_AUTHORIZED` 的 12 個 path 沒有逐一記錄。
- 網站：
  - ZAP 送出的請求都在 `/api` 底下，沒有 DELETE。
  - `Authorization` 的值都等於設定的 token（以 sha256 前綴核對）。
- canary 沒有連線：規格中的 URL 一個也沒被取得。
- token 與 proxy 的 token 都不在 Env、Cmd、Labels 與 out/ 的檔案中。
- 容器的 Env 有 `SECSCAN_TARGET_AUTH=header`、`ZAP_AUTH_HEADER=Authorization`、`ZAP_AUTH_HEADER_SITE=<target 的 host>`。

**api_key_header、cookie**：
- 設定：`max_requests` 300，所以 maxDuration 是 300 ÷ 2 − 60 = 90 秒，ZAP 自己在期限內結束。
- 兩種 profile 各有 13 個 ZAP 的請求，`X-Api-Key` 與 `Cookie` 的值都恰好是設定的值。
- cookie 沒有和其他 cookie 合併。不過小型網站不發 `Set-Cookie`，和 ZAP 自己的 session cookie 怎麼合併，要到 T16 以 Juice Shop 確認。
- canary 是 0。

**取消（SEC-19；T13 的交接）**：
- policy 先變成 blocked，容器才收到 kill。之後網站沒有再收到請求。
- 封鎖之後被 guard 拒絕的請求：三次執行分別是 2、4、2 個。
- kill 到 die 分別是 2.06、2.01、2.05 秒：ZAP 收到 SIGTERM 之後約 2 秒結束，在 5 秒的寬限之內。

**參照炸彈（3^8 個展開，在上傳上限之內）**：
- run 是 collected，沒有錯誤碼，在容器的上限內完成。
- canary 是 0，guard 只看到 target。

**還沒量測**：
- 請求的實際間隔（速率由 guard 強制，T12 已證明）。
- 以 maxDuration 結束時的退出碼：測試只斷言是 0 或 2，沒有記下實際值。
- `_method`：小型網站的表單沒有這個欄位。
- HTTPS。

### 7.6 T15：輸出的量測（2026-10-31）

**離線（`--network none`，掃描容器的強化旗標，鎖定的映像）**：

| 情境 | 退出碼 | 報告 | log 的結尾 |
|---|---|---|---|
| `maxDuration: 20`，45 秒的 `delay` job | 2（34 秒結束） | 有，`site` 是空的 | `Automation plan warnings:`、tab 加 `Plan stopped after reaching maximum duration of 20 second(s)`；進度中另有 `Job delay interrupted` |
| spider 連不到 host | 1（14 秒） | 有，`site` 是空的 | `Automation plan failures:`、tab 加 `Job spider failed to access URL … check that it is valid : …`（訊息含 URL） |
| 錯誤加上警告（未知的 job 參數） | 1 | 有 | failures 在前、warnings 在後，各一次 |
| 沒有錯誤與警告 | 0 | 有 | `Automation plan succeeded!` |
| ZAP 不認得的啟動參數 | 1（12 秒） | 沒有 | `Unsupported option …` 與 usage，沒有摘要 |
| `-Xmx100000g` | 137（2 秒） | 沒有 | JVM 被 kill：不在收集的退出碼中 |

- plan 的 `maxDuration` 到期時**中斷執行中的 job**，不是等 job 結束；第二個 `delay` 沒有執行，`alwaysRun` 的 report 照樣寫出。
- 摘要一定在 log 的最後。`ExtensionAutomation` 的順序是 failures、warnings；訊息本身可以有換行，所以不能假設每一行都以 tab 開頭。

**live（`make record-fixtures`：live lab 網路上的小型網站，anonymous；4 個情境 6 分 18 秒）**：

| 情境 | 設定 | 退出碼 | 摘要 | 告警／instance | 請求／回應 |
|---|---|---|---|---|---|
| findings | web，240 秒 | 0 | succeeded | 4／11 | 272／272 |
| clean | api，加了安全 header 的 JSON 端點，300 個請求 | 0 | succeeded | 0／0 | 13／13 |
| timeout | web，120 秒（maxDuration 60 秒） | 2 | maxDuration | 4／11 | 117／117 |
| unanswered | web，target 的 port 沒有人聽 | 2 | `Job spider error accessing URL … status code returned : 502 expected 200` | 3／9 | 71／0 |

- **報告的形狀**：`site` 只有 target；零告警時 `site` 有一項、`alerts` 是空的；連不到 host 時 `site` 是空的。`riskcode`、`confidence`、`cweid`、`wascid`、`pluginid` 都是字串，`systemic` 是布林。`desc` 與 evidence 是原始的 HTML（`<p>`、`<form …>`），不是跳脫的形式。
- **URI 和 telemetry**：findings 的每個 instance 的 (method, path) 都在 telemetry 中（path 不含 query）；根是 `http://host:3000/`。T03 的 Juice Shop 報告有沒有結尾斜線的 `http://juice-shop:3000`。
- **mitmproxy 自己的回應會被告警**：unanswered 的 3 種告警都是對 502 錯誤頁的：缺 CSP（10038）、Private IP Disclosure（2，evidence 是靶機的 IP `10.89.10.210`）、`Server: mitmproxy 12.2.3`（10036）。不排除的話，它們會成為目標的「觀察」，而且 run 看起來是成功的（`DECISIONS.md` §19.2 第 4 條、§19.4 第 3 層）。
- **`/admin` 的 guard 拒絕沒有出現**：ZAP 的 context 已排除（T14 的 scope），guard 只拒絕 14 個 407；所以 guard 的 403 被告警的情況還沒量到（§19.4 的第 4 層目前只有單元測試，T16 以真實靶機量測）。

**解析的成本**（以真實的 instance 複製，不進 repo；M1 Pro）：

| 報告 | instance | 解析 | Python 的峰值 | 程序的峰值 RSS |
|---|---|---|---|---|
| 1 MiB | 1,632 | 0.16 秒 | 2.9 MiB | 30 MiB |
| 4 MiB | 6,594 | 0.64 秒 | 11.3 MiB | 55 MiB |
| 8 MiB | 13,209 | 1.31 秒 | 21.9 MiB | 106 MiB |

8 MiB 在 worker 的 `mem_limit`（256m）之內；上限維持 8 MiB，T16 以真實的大報告重新確認。

**T14 還沒量測的項目**：以 maxDuration 結束時的退出碼是 2（上表）。

**完整的閉環（`make test-live-zap`，開放 zap、移除預覽開關之後；審查的修正之前與之後各跑一次，都是 11 passed，11 分 12 秒、11 分 15 秒，跑完沒有殘留的容器、volume、網路）**：

- web、anonymous：guard 放行 272 個，拒絕的只有 407 GET 14 個；run `succeeded`、scan `completed`；每個觀察的 (method, path) 都是網站真的收到的請求；manifest 的 hash 等於 runs volume 中遮罩之後的檔案。
- api、bearer：放行 16 個，拒絕 407 GET 78、`PATH_AMBIGUOUS` GET 136、`PATH_NOT_AUTHORIZED` GET 14 個。
- **遮罩**：`/api/echo` 把認證 header 寫進 HTML 註解，ZAP 的 Suspicious Comments（10027）把註解帶進報告。bearer、`api_key_header`、cookie 三種都是報告中遮罩 2 次：out/ 的報告與 log、`GET /observations` 的回應都沒有 secret 的原文，看得到 `[REDACTED:target-secret]`。worker 能解析遮罩之後的報告（0400、runner 的 uid）。
- maxDuration（web，120 秒）：run `timed_out`（`ENGINE_TIMEOUT`）、scan `timed_out`，觀察保留。
- 零告警（加了安全 header 的端點）：run `succeeded`、0 個觀察、guard 有轉送、網站有收到請求。
- 目標沒有回應（port 沒有人聽）：run `failed`（`NO_TARGET_TRAFFIC`），0 個觀察，`excluded.not_answered` 大於 0。
- 取消：封鎖之後被拒 2 個，kill 到 die 2.05 秒。參照炸彈：`succeeded`。

M2 的 `make test-live-runner`：42 passed（5 分 41 秒），撤銷授權的 scan 是 `failed`（`DECISIONS.md` §19.8）。

### 7.7 T16：Juice Shop 與 VAmPI 的真實掃描（`make test-live-lab`，2026-10-31）

靶機：`bkimminich/juice-shop:v20.3.0`、`erev0s/vampi`（`compose.lab.yaml` 的 digest），由測試在 live 自己的 lab 網路上以固定 IP 逐一啟動（一次一個）。VAmPI 的 grant 是規格中除了 `/createdb` 以外的 path、method 只有 GET 與 POST；Juice Shop 是 `allow_all_paths`、GET 與 HEAD。速率 2 req/s，預算省略時用 grant 的上限（5,000 次、1,500 秒）。

**第二輪（job 的上限是 0；8 passed，26 分 15 秒；跑完沒有殘留的容器、volume、網路）**：

| 情境 | 秒 | 轉送／回應 | guard 拒絕 | 407 | 觀察 | 報告 | ZAP／靶機的記憶體峰值 |
|---|---|---|---|---|---|---|---|
| VAmPI 弱點版，bearer | 312 | 425／425 | `PATH_AMBIGUOUS` 232、`PATH_NOT_AUTHORIZED` 26 | 139 | 11 | 10,785 B | 632／115 MiB |
| VAmPI，預算 180 秒 | 139（`timed_out`） | 204／204 | `PATH_AMBIGUOUS` 60 | 40 | 11 | 11,115 B | 683／112 MiB |
| VAmPI 安全版，bearer | 310 | 425／425 | 同弱點版 | 139 | 10 | 10,554 B | 653／114 MiB |
| VAmPI，token 90 秒 | 307 | 425／425 | `PATH_AMBIGUOUS` 204、`PATH_NOT_AUTHORIZED` 26 | 125 | 11 | 10,785 B | 722／115 MiB |
| Juice Shop，anonymous | 193 | 256／253 | 0 | 110 | 9 | 15,157 B | 846／144 MiB |
| Juice Shop，bearer | 204 | 256／253 | 0 | 110 | 9 | 15,157 B | 916／159 MiB |
| Juice Shop 的 REST 搜尋 | 51 | 59／59 | `PATH_NOT_AUTHORIZED` 6 | 4 | 2 | 5,860 B | 654／162 MiB |

- 取消（VAmPI，ZAP 送出流量之後）：取消後 9 秒 `cancelled`，容器刪除，之後 guard 沒有再為它放行。
- 第一輪（job 有自己的上限）的不同：預算 150 秒（plan 90 秒）的 VAmPI 只轉送 107 個就 `succeeded`：activeScan 在自己的 1 分鐘上限停止（log 是 `Job activeScan finished, time taken: 00:01:00`、`Automation plan succeeded!`，沒有警告）。ZAP 的記憶體峰值最高 1,265 MiB（Juice Shop、bearer）。
- **觀察**：VAmPI 只有 passive 的 3 種（`Server` 版本 10036、缺 `X-Content-Type-Options` 10021、Authentication Request Identified 10111），弱點版與安全版相同；Juice Shop 的 web profile 只有 passive 的 3 種（缺 CSP 10038、CORS 10098、Modern Web Application 10109）；REST 搜尋命中 **SQL Injection（40018）**：`GET /rest/products/search?q=apple'`，ZAP 的等級 High、信心 Low，evidence 是 `HTTP/1.1 500 Internal Server Error`。
- **path 參數的覆蓋缺口**：VAmPI 的 path 參數的攻擊都是百分比編碼（例如 `/users/v1/name1%27`、`/books/v1/%22`），guard 以 `PATH_AMBIGUOUS` 拒絕：每次 232 個（`/users/v1/…` 106、`/books/v1/…` 126），佔 guard 判斷的請求（不含 407）的 34%。
- **對照實驗**（不經平台）：同一個映像、第一輪的 plan.yaml 與規格，ZAP 與 VAmPI 只接一個 internal 的網路，沒有 guard 與速率限制：弱點版 34 秒內命中 `40018`（High，`GET /users/v1/%27`，參數 `username`），安全版沒有。
- **Juice Shop 的 spider**：traditional spider 13 秒找到 51 個 URL，都是靜態資源、`/ftp`、`/robots.txt`、`/sitemap.xml` 等；REST 與 API 都由前端的 JS 呼叫，走不到。`/ftp` 回目錄列表（`listing directory /ftp`），Directory Browsing 沒有告警。
- **Juice Shop 的認證**：`/rest/user/whoami` 只看 cookie（帶 bearer 也回 `{"user":{}}`）；`/api/Cards`、`/api/Addresss`、`/rest/basket/1`、`/api/Users` 以 Authorization 驗證（匿名 401）。
- **VAmPI 的 token**：`tokentimetolive` 過期之後 `/me`、`POST /books/v1`、`GET /books/v1/{title}` 回 401，`/books/v1`、`/users/v1` 照樣 200。資料庫要先 `GET /createdb`（清空重建，grant 排除它）。
- **速率**：實際約 1.5 req/s（2 req/s 的上限，ZAP 單執行緒）；沒有任何 run 用盡預算。

### 7.8 T30：自製 fixture app 的真實掃描（`make test-live-fixture`，2026-11-01）

靶機：自製的 fixture app（`tests/live/fixture_app/`），跑在 guard 映像的 python（stdlib，不需另建映像或靶機映像），由測試在 live 自己的 lab 網路上以固定 IP 啟動（一次一個，弱點版與修補版依序）。web 用 `web_active_lab`、`allow_all_paths`、GET/HEAD/POST；api 用 `api_active_lab`，grant 是規格的 path、GET/HEAD/POST，bearer 用種子 token。strict-1（預設）。

**4 passed，18 分 07 秒；跑完沒有殘留的容器、volume、網路。** 每個 run 的 `plan_hash` 是 sha256、profile 定義與 `/scan-profiles` 相同、`traffic_verified=true`、guard 只看到 target、每個觀察的 (method, path) 都是 guard 為這個 run 轉送過的請求。

| 情境 | 秒 | 轉送／回應 | guard 拒絕 | 407 | 觀察 | 報告 | ZAP／靶機記憶體峰值 |
|---|---|---|---|---|---|---|---|
| 弱點版 web | 381 | 700／699 | `PATH_AMBIGUOUS` 16 | 43 | 23 | 46,322 B | 650／16 MiB |
| 弱點版 api | 204 | 162／162 | `PATH_AMBIGUOUS` 322、`PATH_NOT_AUTHORIZED` 28 | 181 | 11 | 13,820 B | 707／16 MiB |
| 修補版 web | 278 | 512／512 | 0 | 34 | 4 | 10,434 B | 678／14 MiB |
| 修補版 api | 200 | 162／162 | `PATH_AMBIGUOUS` 322、`PATH_NOT_AUTHORIZED` 28 | 181 | 1 | 3,208 B | 724／15 MiB |

- **弱點版 web（23 個觀察）**：主動命中 **SQL Injection 40018×3**（`/search` 的 q、`/login` 的 user/pass）、**Reflected XSS 40012×1**（`/greet` 的 name）、**External Redirect 20019×1**（`/go` 的 next）；被動命中缺 CSP 10038×2、CORS `*` 10098×5、缺 X-Content-Type-Options 10021×5、缺 Anti-clickjacking 10020×2。另外命中超出 12 個列舉案例的 CRLF Injection 40003×1、Path Traversal 6×1、Absence of Anti-CSRF Tokens 10202×1（如實記錄，不改變計數）。
- **弱點版 api（11 個觀察）**：只有被動的 CORS 10098×5、缺 X-Content-Type-Options 10021×5 與 10111。path 參數注入的探測（`/api/orders/{id}`、`/api/users/{id}`、`/users/{username}` 的 `%27`、`%00`、`%22` 等共 322 個）全被 guard 以 **`PATH_AMBIGUOUS`** 擋下 ＝ **平台阻擋**（含 T30-FX-PB-01 的 path SQLi）；coverage 量到 6／6 eligible／observed／authenticated。BOLA、mass assignment、過度資料暴露（FX-10～12）不在 ZAP 能力範圍：GET 已轉送、以人工確認（案例表 §5.1.1）。
- **修補版（負例對照）**：web 與 api 都 **沒有任何 active scan 規則的告警**（web 4 個、api 1 個觀察，全是 passive／informational）。修補版 web 只剩 10055（CSP 指令不完整的 passive 提醒）、10202、10111；修補版 api 因為補了安全 header，連 CORS 與 XCTO 都不再出現，只剩 10111。
- **contract/robustness（C1–C6）**：ZAP 不評契約；以 `tests/contract/test_fixture_cases.py` 與人工確認弱點版回 500、修補版回 400／405。
- **對照（弱點 vs 修補）**：同一組掃描在弱點版有主動注入與設定告警、修補版清零，構成乾淨的正例／負例對照；strict-1 下 path 參數注入一律平台阻擋，與 §20.7 的 VAmPI 一致。
