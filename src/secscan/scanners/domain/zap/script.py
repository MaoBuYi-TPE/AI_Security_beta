"""ZAP 容器的 script（docs/DECISIONS.md §18.2、§18.8）：以 sha256 核准（runner 的政策另外寫一次）。

掃描的 script：
- 目標的認證以 ZAP_AUTH_HEADER* 環境變數交給 ZAP（DoD），但值不能出現在 plan 或 Docker 的設定中
  （§14.5）：plan 只有模式與 header 名稱，值由這裡從 0400 的 auth-header 檔讀出、只 export 給 ZAP。
  只用 shell 內建的指令（值不會出現在任何子程序的 argv），不印出任何一行。
- 模式與檔案不一致、header 模式缺少 header 名稱或 SITE（沒有 SITE 時 ZAP 對每個 host 都帶 header）
  就 exit 64（fail closed）；out/ 寫不了 exit 65。不用 set -eu：dash 在這些錯誤時
  以 2 退出，會和 AF 的「有警告」混淆。
- -silent：不主動對外連線；-nostdout：-configfile 的值（proxy 的密碼）不會寫進 stdout，也就不會
  進入收集的 zap.log（T14 的實測）；ZAP 的 home 在 tmpfs（/tmp/zap），隨容器刪除。
- -Xmx 明確指定：zap.sh 只認 cgroup v1 的記憶體上限，OrbStack 是 v2，會算出 VM 的 1/4。
probe 的 script：列出 /zap/plugin 的 add-on，再以同一套參數執行最小的 AF plan（不送任何請求）。
"""

CONFIG_FILE = "zap.properties"
PLAN_FILE = "plan.yaml"
SPEC_FILE = "openapi.json"
REPORT_NAME = "zap-report"
LOG_FILE = "zap.log"
PROBE_PLAN_FILE = "probe.yaml"
PROBE_REPORT_NAME = "probe-report"
PROBE_REPORT_FILE = f"{PROBE_REPORT_NAME}.json"
PLUGINS_FILE = "plugins.txt"
AUTH_MODE_VARIABLE = "SECSCAN_TARGET_AUTH"
HEADER_VARIABLE = "ZAP_AUTH_HEADER"
SITE_VARIABLE = "ZAP_AUTH_HEADER_SITE"
ANONYMOUS_MODE = "none"
HEADER_MODE = "header"
WRAPPER_REFUSED = 64
OUTPUT_UNWRITABLE = 65
JVM_HEAP = "-Xmx1536m"
# 容器內的 tmpfs（每個容器各自一份，隨容器刪除），不是宿主的暫存目錄。
ZAP_HOME = "/tmp/zap"  # noqa: S108
_ZAP = f"/zap/zap.sh {JVM_HEAP} -cmd -silent -nostdout -dir {ZAP_HOME}"

SCAN_SCRIPT = f"""umask 077
case "${{{AUTH_MODE_VARIABLE}:-}}" in
{ANONYMOUS_MODE})
  unset {HEADER_VARIABLE} ZAP_AUTH_HEADER_VALUE {SITE_VARIABLE}
  if [ -e /scan/secret/auth-header ]; then exit {WRAPPER_REFUSED}; fi
  ;;
{HEADER_MODE})
  [ -n "${{{HEADER_VARIABLE}:-}}" ] && [ -n "${{{SITE_VARIABLE}:-}}" ] || exit {WRAPPER_REFUSED}
  line=
  IFS= read -r line < /scan/secret/auth-header || [ -n "$line" ] || exit {WRAPPER_REFUSED}
  case "$line" in
  "${HEADER_VARIABLE}: "?*) ;;
  *) exit {WRAPPER_REFUSED} ;;
  esac
  ZAP_AUTH_HEADER_VALUE=${{line#"${HEADER_VARIABLE}: "}}
  export ZAP_AUTH_HEADER_VALUE
  ;;
*) exit {WRAPPER_REFUSED} ;;
esac
true > /scan/out/{LOG_FILE} || exit {OUTPUT_UNWRITABLE}
exec {_ZAP} -configfile /scan/secret/{CONFIG_FILE} -autorun /scan/in/{PLAN_FILE} \\
  > /scan/out/{LOG_FILE} 2>&1
"""

PROBE_SCRIPT = f"""umask 077
ls /zap/plugin > /scan/out/{PLUGINS_FILE} || exit {OUTPUT_UNWRITABLE}
exec {_ZAP} -autorun /scan/in/{PROBE_PLAN_FILE} > /scan/out/{LOG_FILE} 2>&1
"""
