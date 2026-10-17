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
| zaproxy/zap-stable | 2.17.0（tag 20261016） | sha256:5ccfff9a4117… | Apache-2.0 | zap(1000) | 未測（spike 以 cap_drop/no-new-privileges 執行，未強制 read-only；唯讀相容性列為 M3 待確認，見 §5） |
| projectdiscovery/nuclei | v3.11.1 | sha256:582d5546902e… | MIT | root | 可（tmpfs `/root/.config`、`/root/.cache`、`/tmp`） |
| schemathesis/schemathesis | 4.31.1 | sha256:e6d34d7defc8… | MIT（但含 tracecov，見下） | schemathesis(1000) | 可（`--generation-database none` + 可寫 report-dir + tmpfs `/tmp`） |
| mitmproxy/mitmproxy | 12.2.3 | sha256:00b77b5d8804… | MIT | 1000（需覆寫 entrypoint） | 可（confdir tmpfs 需 mode 01777） |
| bkimminich/juice-shop | v20.3.0 | sha256:cea5a4af4aac… | MIT | 65532（distroless，node 在 `/nodejs/bin/node`，無 shell） | **不相容**（見 §5） |
| erev0s/vampi | latest | sha256:0a5a224b6e14… | MIT | root | 可（tmpfs `/tmp`、`/vampi/database`） |
| busybox | 1.38.0 | sha256:fd7dc98638c8… | GPL-2.0-only（僅作 probe，不散布） | root | — |

- **tracecov**：schemathesis 映像預設 `SCHEMATHESIS_COVERAGE=true`，會載入 `tracecov`（PyPI 0.25.3，授權 `LicenseRef-TraceCov-Community-1.0`，**非 OSI**、限 Internal Use、會寫 `/app`）。本專題一律設 **`SCHEMATHESIS_COVERAGE=false`** 關閉，避免授權與唯讀 rootfs 問題。
- **mitmproxy entrypoint**：預設 entrypoint 需 root（跑 `usermod` 再 `gosu`）。改以 `entrypoint: [mitmdump]` + `user: "1000:1000"` 直接啟動。

## 2. Nuclei 模板

- release **v10.5.0**（2026-10-05），tag commit `f8b8b8dcd70d93826c3767e1829ef8243af9f03b`。
- 壓縮檔 sha256 `80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41`，解壓 14,036 個 yaml。
- 本 spike 選用 20 個 HTTP、info/low 模板（清單與各自 sha256 見 `spikes/t03/nuclei/templates.lock.txt`），皆無 `unsafe`/OAST 外呼。**這不是 T17 的凍結清單**，只是 spike 用的小集合。

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
