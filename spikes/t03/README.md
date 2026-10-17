# T03 工具 spike（一次性探查）

這個目錄是 T03 用來驗證掃描器映像、模板與實驗網路的腳本，**不是產品程式**：
在容器內以 mitmproxy/python 執行，不納入 mypy，也不是 `src/secscan` 的一部分。
結果與結論寫在 `docs/TOOLS.md`。原始輸出、量測與秘密只保存在本機 `runs/spike-t03/`（已 gitignore）。

## 內容

| 檔案 | 用途 |
|---|---|
| `compose.spike.yaml` | 長駐服務：`guard-spike`（量測 proxy）、`canary`（接收端證據） |
| `guard_spike.py` | mitmproxy addon：帳號 allowlist、擋 CONNECT、擋 scanner 的 DELETE/`/createdb`、每請求 JSONL |
| `policy.json` | guard 的 allowlist 與禁用規則 |
| `canary.py` | lab_net 上的小 HTTP 伺服器，記錄收到的請求（method/path/header 名稱） |
| `zap/*.plan.yaml` | ZAP Automation Framework plan（Z1 juice-shop、Z2 vampi） |
| `schemathesis.toml` | Schemathesis 設定（proxy/bearer 以 `${ENV}` 帶入） |
| `nuclei/templates.lock.txt` | 本 spike 選用的 20 個模板 ID 與 sha256 |
| `mask_fixture.py` | 遮罩真實輸出（JWT、lab token、proxy 帳密）後寫成 `tests/fixtures/` |
| `summarize.py` | 彙整 guard JSONL（請求數、決策、上游 IP、帶 auth 數） |

## 重現步驟（需 OrbStack）

```bash
orb start
make lab-up                     # 啟動 juice-shop、vampi-vuln、vampi-secure（只接 internal）

# 產生每工具專屬 proxy 帳密（bcrypt htpasswd，密碼走 stdin 不落 argv）。
mkdir -p runs/spike-t03/secrets && chmod 700 runs/spike-t03/secrets
# 在 runs/spike-t03/secrets/proxy.env 放 probe_PASS/zap_PASS/nuclei_PASS/schemathesis_PASS（hex），
# 然後 source spikes/t03/run_scans.sh 後呼叫 gen_htpasswd（用 htpasswd -c -i -B -C 4）。

cd spikes/t03 && docker-compose -f compose.spike.yaml up -d   # guard-spike + canary
```

各掃描的實際命令與隔離旗標寫在 `run_scans.sh`（`--network secscan_scan_net`、`--cap-drop ALL`、
`--security-opt no-new-privileges`、`--read-only` 等）。`source run_scans.sh` 後可呼叫
`gen_htpasswd`、`dseries`（D 系列直連檢查）、`zap_run`、`nuclei_run`、`schemathesis_run`。
把原始輸出收到 `runs/spike-t03/`，以 `mask_fixture.py` 遮罩後寫入 `tests/fixtures/`，再更新
`tests/fixtures/manifest.json`。各步驟的結果與結論見 `docs/TOOLS.md`。

## 清理

```bash
cd spikes/t03 && docker-compose -f compose.spike.yaml down   # 先停 spike（它接在 lab_net 上）
cd ../.. && make lab-down
docker volume rm secscan_spike_runs 2>/dev/null || true
rm -rf runs/spike-t03/secrets                                 # 刪掉 lab token 與 proxy 帳密
```

## 注意

- 只掃 `lab_net` 的靶機，不對外。guard-spike 僅量測，**不是** M2 的 egress guard。
- 秘密（lab token、proxy 帳密）一律走環境變數或 0400 檔案，不放命令列；遮罩後才進 git。
