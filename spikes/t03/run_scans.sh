#!/usr/bin/env bash
# T03 spike 的實際執行命令（可稽核、可重現）。這是 spike 腳本，不是產品程式。
# 前置：orb start；make lab-up；本目錄 docker-compose -f compose.spike.yaml up -d。
# 秘密只走環境變數或 0400/0600 檔案，不放命令列 argv。只掃 lab_net，不對外。
#
# 關鍵隔離旗標（每個工具容器都必須有）：
#   --network secscan_scan_net   只接 scan_net（唯一能連到的是 guard-spike）
#   --cap-drop ALL --security-opt no-new-privileges
#   --read-only（可行時）＋必要的 --tmpfs
# proxy 一律指向 guard 的 scan_net IP 10.89.8.10:8080，帳密來自 runs/spike-t03/secrets。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NET=secscan_scan_net
GUARD=10.89.8.10:8080
W="$ROOT/runs/spike-t03/work"
SECRETS="$ROOT/runs/spike-t03/secrets"
TPL="$ROOT/runs/spike-t03/templates/v10.5.0/extracted/nuclei-templates-10.5.0"
MITM=mitmproxy/mitmproxy:12.2.3
BUSYBOX=busybox:1.38.0

# shellcheck disable=SC1091
set -a; . "$SECRETS/proxy.env"; set +a

gen_htpasswd() { # 產生每工具專屬 bcrypt htpasswd（密碼從 stdin，不落 argv）
  rm -f "$SECRETS/proxy.htpasswd"; local first=1 pw
  for acct in probe zap nuclei schemathesis; do
    pw=$(eval "echo \${${acct}_PASS}")
    if [ $first = 1 ]; then htpasswd -c -i -B -C 4 "$SECRETS/proxy.htpasswd" "$acct" <<<"$pw"; first=0
    else htpasswd -i -B -C 4 "$SECRETS/proxy.htpasswd" "$acct" <<<"$pw"; fi
  done
  chmod 600 "$SECRETS/proxy.htpasswd"
}

# --- D 系列：直連必須失敗、經 guard 才成功（接收端以 canary 佐證）----------------
dseries() {
  echo "# D1/D3 scan_net 無 DNS、無預設路由"
  docker run --rm --network "$NET" "$BUSYBOX" ip route
  docker run --rm --network "$NET" "$BUSYBOX" nslookup vampi-vuln || true
  echo "# D4 probe 帳密 -> canary（200，無 Proxy-Authorization 轉送）"
  docker run --rm --network "$NET" -e PX="http://probe:${probe_PASS}@$GUARD" --entrypoint python "$MITM" -c \
    'import os,urllib.request;print(urllib.request.build_opener(urllib.request.ProxyHandler({"http":os.environ["PX"]})).open("http://canary:8000/d4",timeout=8).status)'
  echo "# D5 scanner 帳密 -> canary（403，canary 不應收到）"
  docker run --rm --network "$NET" -e PX="http://zap:${zap_PASS}@$GUARD" --entrypoint python "$MITM" -c \
    'import os,urllib.request,urllib.error
try: urllib.request.build_opener(urllib.request.ProxyHandler({"http":os.environ["PX"]})).open("http://canary:8000/d5",timeout=8)
except urllib.error.HTTPError as e: print("HTTP",e.code)' || true
}

# --- ZAP（proxy 以 0600 configfile 注入；-silent 擋自身對外；Bearer 以 env）--------
zap_run() { # $1 plan, $2 workdir, $3 extra-env-for-auth(0/1)
  local plan="$1" wd="$2" auth="$3"; local authenv=()
  [ "$auth" = 1 ] && authenv=(-e ZAP_AUTH_HEADER=Authorization -e ZAP_AUTH_HEADER_VALUE="Bearer $(cat "$SECRETS/vampi-token.txt")" -e ZAP_AUTH_HEADER_SITE=vampi-vuln)
  docker run --rm --network "$NET" --cap-drop ALL --security-opt no-new-privileges \
    "${authenv[@]}" \
    -v "$wd:/zap/wrk" -v "$W/proxy-zap.prop:/zap/proxy.prop:ro" \
    "zaproxy/zap-stable:20261016" \
    zap.sh -cmd -silent -configfile /zap/proxy.prop -autorun "$plan"
}

# --- Nuclei（proxy 與 secret 皆走檔案，不落 argv；唯讀 rootfs + tmpfs）------------
nuclei_run() { # $1 url, $2 outfile, $3 use-sf(0/1)
  local sf=(); [ "$3" = 1 ] && sf=(-sf /cfg/secrets.yaml)
  docker run --rm --network "$NET" --user 0:0 --cap-drop ALL --security-opt no-new-privileges \
    --read-only --tmpfs /root/.config --tmpfs /root/.cache --tmpfs /tmp \
    -v "$TPL:/templates:ro" -v "$W/nuclei-proxy.txt:/cfg/proxy.txt:ro" \
    -v "$W/nuclei-secrets.yaml:/cfg/secrets.yaml:ro" -v "$(dirname "$2"):/out" \
    "projectdiscovery/nuclei:v3.11.1" \
    -u "$1" -t /templates -id "$(cat "$W/ids.txt")" -ni -duc -pt http \
    -p /cfg/proxy.txt "${sf[@]}" -jsonl -o "/out/$(basename "$2")" -silent
}

# --- Schemathesis（proxy/bearer 走 ${ENV}；關閉 tracecov；唯讀 rootfs）------------
schemathesis_run() { # $1 url, $2 outdir
  docker run --rm --network "$NET" --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp \
    -e SCHEMATHESIS_COVERAGE=false \
    -e ST_PROXY="http://schemathesis:${schemathesis_PASS}@$GUARD" \
    -e ST_TOKEN="$(cat "$SECRETS/vampi-token.txt")" \
    -v "$ROOT/spikes/t03/schemathesis.toml:/cfg/schemathesis.toml:ro" \
    -v "$2/openapi.yml:/cfg/openapi.yml:ro" -v "$2/out:/out" \
    "schemathesis/schemathesis:4.31.1" \
    --config-file /cfg/schemathesis.toml run /cfg/openapi.yml --url "$1" \
    --generation-database none --report ndjson,json,junit --report-dir /out
}

echo "這個腳本記錄 T03 實際用的命令與隔離旗標。各函式可依 docs/TOOLS.md §3–§4 逐一呼叫。"
echo "用法範例：source 本檔後呼叫 gen_htpasswd、dseries、zap_run、nuclei_run、schemathesis_run。"
