# 開發任務清單

所有項目初始均為未完成。標完成必須附實作檔案、實際測試結果與未涵蓋限制；不能僅因文件描述過就勾選。

## M0｜第 1 週：範圍、骨架與可行性

- [ ] T01 凍結題目、P0/P1、研究問題與排除項目。
  - 產出：需求摘要、3–5 位訪談對象/問題、待驗證假設。
  - DoD：團隊能清楚說明相對手動使用兩工具增加什麼；沒有自訂前端任務。
- [ ] T02 建立 Python 專案與品質命令。
  - 產出：pyproject.toml、uv.lock、Makefile、最小 app/main.py、pytest、Ruff、型別檢查、忽略規則。
  - DoD：乾淨環境可啟動健康端點並實際跑 test/lint/typecheck；README 指令有效。
- [ ] T03 確認掃描器映像、模板與實驗網路。
  - 產出：工具名稱/版本/digest、CPU 架構、授權、必要可寫路徑、proxy/auth/output 相容性表。
  - DoD：在完全隔離、自有、無秘密的初始靶場取得 ZAP/Nuclei 真實輸出樣本；保存 hash。
  - 限制：M0 smoke test 僅於獨立實驗 VM 封閉網路，不能提前開放任意 URL 的平台功能。
  - 無隔離靶場則標 blocked，不能改掃公共網站或把 Mock 當 live 成果。

## M1｜第 2–3 週：API 與資料基礎

前置：T01–T02。

- [ ] T04 建立 DB Model、Alembic、Repository 與依賴設定。
  - DoD：全新 DB 可 migration；FK/unique/index 測試；測試資料與正式配置分離。
- [ ] T05 建立 key、project 與 object-level 權限。
  - DoD：高熵 key、只存 hash、過期/撤銷、viewer 不可寫、A 不可讀 B。
- [ ] T06 建立 target/scope grant 與審批流程。
  - DoD：pending/approved/revoked/expired 正確；無核准不得開始掃描；audit 留存。
- [ ] T07 建立 OpenAPI 上傳與受限 operation inventory。
  - DoD：大小/格式/ref/servers 驗證，含惡意與跨 origin 測試；無外部 fetch。
- [ ] T08 建立 auth profile 與 secret lifecycle。
  - DoD：secret 加密/只寫不讀、換版、不寫 log、preflight 定義驗證。
- [ ] T09 建 scan/outbox、idempotency 與 FakeRunner。
  - DoD：API 202、同 key 同內容不重複、不同內容 409；FakeRunner 可走完/失敗/取消。

里程碑證據：不用真工具也能從 API 建立受控任務、查狀態及得到假 runner 明確標記的測試結果，且所有權限測試通過。

## M2｜第 4–5 週：Runner 與強制安全邊界

前置：T03、T06、T09。

- [ ] T10 建立可信 launcher、固定映像/掛載 allowlist 與容器限制。
  - DoD：API/掃描容器無 Docker socket、非 privileged；任意映像/path/args 被拒絕。
- [ ] T11 完成 scanner network、egress guard、DNS/IP/path/method/redirect 檢查。
  - DoD：SEC-02–10 適用項通過；以禁用靶場收包證明零越界；無法約束的 profile 關閉。
- [ ] T12 完成共享 budget 與認證 preflight 路徑。
  - DoD：所有掃描流量共用上限，preflight 計數；Token 只送核准 origin。
- [ ] T13 實作心跳/lease、取消、timeout、orphan cleanup/reconciler。
  - DoD：重送不重複啟動；中斷不永久 running；取消先停新出站、後回收容器。

放行規則：T10–T13 未通過前不啟用對操作者的真實 active scan API。必要時只支援完全封閉的 HTTP 靶場，不跳過 HTTPS guard 測試來擴充範圍。

## M3｜第 6–7 週：ZAP Adapter

前置：M2。

- [ ] T14 實作 ZAP capability probe 與 Web/API ExecutionPlan。
  - DoD：沒有 auth 的 profile 明確 anonymous；API spec origin 被綁定；profile/method 不相容拒絕。
- [ ] T15 實作版本化 ZAP JSON Parser 與觀察輸入契約。
  - DoD：clean/findings/malformed/timeout/exit fixtures 全測；非零退出不一律 crash。
- [ ] T16 執行 ZAP 真實 e2e 與失敗情境。
  - DoD：已知正例/負例、Token 失效、工具超時與取消皆有真實證據；保留版本與流量資訊。

里程碑證據：第一次 API → 真實工具 → 解析 → DB → 查詢完整閉環，而非只啟動容器。

## M4｜第 8–9 週：Nuclei 與結果整合

前置：M3；去重單元測試可提早並行。

- [ ] T17 審查固定 Nuclei HTTP templates 與執行設定。
  - DoD：記錄 commit/IDs/hash；禁用未核准模板、OAST、code/headless、cloud、未知 raw 協定。
- [ ] T18 實作 Nuclei Adapter/JSONL Parser 與真實 e2e。
  - DoD：空檔/壞行/重複/非零/取消/timeout 都有定義；零告警與失敗可區分。
- [ ] T19 實作 Observation/Finding、mapping version、保守 fingerprint。
  - DoD：正確保留來源、kind、severity/confidence；不可信映射不跨工具合併。
- [ ] T20 建立去重反例與來源追溯查詢。
  - DoD：同 CWE 不同參數、相同 route 不同身分/物件、不同弱點不誤合併；所有證據可追溯。

里程碑證據：兩引擎同一 API 流程可成功取得真實結果，能展示共享預算、部分失敗及多來源同問題。

## M5｜第 10–11 週：報告、複掃與 P0 完整驗收

前置：M4。

- [ ] T21 完成人工 triage、audit 與 JSON/Markdown 報告。
  - DoD：未確認告警清楚標記；artifact 權限/遮罩/下載安全；不執行 HTML 或遠端資源。
- [ ] T22 實作比較快照、coverage 判斷與差異分類。
  - DoD：scope/auth/tool/spec 不一致顯示理由；漏掃不顯示已修補；保留舊 scan。
- [ ] T23 完成所有 P0 安全/故障/整合測試與乾淨環境重建。
  - DoD：安全負向測試通過、核心 branch coverage 目標 >=80%、文件/實際 API 一致。

放行規則：M5 過關才可以啟動 M6 的第三引擎；未過關時 M6 改為補強期。

## M6｜第 12–13 週：Schemathesis（可選）或補強

前置：M5。

- [ ] T24 查核 Schemathesis 鎖定版本、JSON/NDJSON、phase/method/proxy/auth 行為。
  - DoD：受控 spec/seed、停止發送未授權 method、能取得可對應 operation 的觀察。
- [ ] T25 實作第三 Adapter 與分離的 contract/robustness 統計。
  - DoD：HTTP 500/schema failure 不直接變 confirmed security；true output 解析與 fault tests。
- [ ] T26 視進度細化 API 覆蓋與一份 CI 呼叫示例。
  - DoD：證明真正送出過哪些核准 operation，缺資料回 N/A；不靠告警數估覆蓋。

降階：刪 T24–T25 保留兩引擎，不影響核心研究問題；將時間用在 T23、T27–T29。

## M7｜第 14–16 週：實驗、分析與展示

- [ ] T27 凍結 ground truth、holdout、工具版本、預算及資料快照。
  - DoD：至少兩人審核案例；custom template 實驗另列；相同總預算規則清楚。
- [ ] T28 執行重複實驗，保存真實結果並計算指標。
  - DoD：security 與 contract 分開；報 TP/FP/FN、去重 precision/recall、時間/請求、失敗。
- [ ] T29 完成報告、操作/部署文件與口試 demo。
  - DoD：由另一組員重建一輪；能說明未覆蓋範圍與失敗；沒有把示意數字當成績。

## 各功能共同 Definition of Done

功能要同時包含實作、輸入驗證、權限、錯誤語意、測試、文件和必要 migration。掃描相關另需真實 live 證據、版本紀錄與清理測試。完成是「可驗證的行為」，不是 class/route/檔案存在。

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

不要先填「全部通過」。若工具/網路/環境不可用，標 blocked 並保存需要補驗證的具體內容。
