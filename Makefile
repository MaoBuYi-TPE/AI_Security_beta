# 開發命令，依 docs/START_HERE.md §7 的約定建立。
# 這個 Makefile 的絕對路徑與 repo 的目錄（在其他目錄以 make -f 執行時也正確；必須在任何 include 之前）。
SELF_MAKEFILE := $(abspath $(lastword $(MAKEFILE_LIST)))
REPO_DIR := $(dir $(SELF_MAKEFILE))
# 一律使用 uv.lock 鎖定的依賴（--locked）；lock 與 pyproject.toml 不一致時直接失敗，不會默默更新。
UV_RUN := uv run --locked

# OrbStack 目前沒有 compose 外掛，`docker compose` 不可用時改用 docker-compose。
# 用遞延指派（=）：只有 lab 目標才會求值，避免每次 make test/lint 都 fork docker。
COMPOSE = $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)
DB_FILE := compose.yaml
# compose secrets 的來源目錄（T23b-b2；docs/DECISIONS.md §32）：compose.yaml 以 ${SECSCAN_SECRETS_DIR:?…}
# 引用，沒有設定或是空字串就在解析階段失敗，不會退回開發的 ./secrets。以 compose.yaml 執行的開發目標
# 一律經由 DEV_COMPOSE 明確設定（不受 shell 中同名變數的影響）；相對路徑由 compose 以專案目錄解析。
# Live 使用自己的拋棄式目錄（test-live-runner）。
DEV_SECRETS_ENV := SECSCAN_SECRETS_DIR=./secrets
DEV_COMPOSE = $(DEV_SECRETS_ENV) $(COMPOSE) -f $(DB_FILE)
# app stack 的 compose 設定：make up、make down 與 make runs-layout-migrate 共用（docs/DECISIONS.md
# §30.13：搬移時解析出來的 runs volume 必須和 make up 實際使用的相同，所以不覆寫環境變數、不加 -p）。
APP_COMPOSE = $(DEV_COMPOSE) --profile app
LAB_FILE := compose.lab.yaml
LAB_PROJECT := secscan-lab
# lab_net 與 scan_net 由這裡建立（docs/DECISIONS.md §15.6）：internal＋gateway isolated＋固定網段，
# 動態配發只在下半段（--ip-range）；egress guard 固定在每個網段的最後一個主機位址。
LAB_NET ?= secscan_lab_net
LAB_SUBNET ?= 10.89.7.0/24
LAB_IP_RANGE ?= 10.89.7.0/25
# 預設啟動全部靶機；可用 `make lab-up LAB_PROFILES="vampi"` 只啟動部分。
LAB_PROFILES ?= juice-shop vampi
LAB_PROFILE_ARGS := $(foreach p,$(LAB_PROFILES),--profile $(p))
# make env 會補齊的本機秘密（隨機 hex，只寫進不進 git 的 .env）。
LOCAL_SECRET_KEYS := DB_PASSWORD DB_ADMIN_PASSWORD TEST_DB_PASSWORD DB_OWNER_PASSWORD
# 平台的三組加密金鑰（docs/DECISIONS.md §12.1、§30.2）：目標 secret、原始證據、報告與人工複測摘錄。
# 每組都是 Fernet 金鑰（url-safe base64 的 32 bytes，44 個字元），各自獨立產生、分給不同的程序。
ENCRYPTION_KEYS_VARS := SECRET_ENCRYPTION_KEYS EVIDENCE_ENCRYPTION_KEYS CONTENT_ENCRYPTION_KEYS
# .env 中一行的開頭：dotenv 也接受 `export ` 前綴與等號前後的空白，比對時要一樣寬，
# 否則會再附加一行，而後面的那一行會默默取代原本的值（對加密金鑰而言，舊的 secret 就解不開了）。
ENV_LINE := ^[[:space:]]*(export[[:space:]]+)?

# app stack（docs/DECISIONS.md §14.8）。掃描容器的網路由這裡建立，compose 只引用（external）。
SCAN_NET ?= secscan_scan_net
SCAN_SUBNET ?= 10.89.8.0/24
SCAN_IP_RANGE ?= 10.89.8.0/25
# runner 不 pull 映像：核准的掃描器映像由這裡以 digest pull（和 runner/domain/policy.py 一致，
# tests/unit/test_deployment.py 會核對）。
SCANNER_IMAGES := busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e projectdiscovery/nuclei:v3.11.1@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb zaproxy/zap-stable:20261016@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6
# live 測試用的獨立 stack：自己的 DB volume、網路與 volume 名稱；API 只綁 127.0.0.1:8765。
# 專案、網路、volume 與 compose 檔都用 override（G1 審查 M2）：命令列、MAKEFLAGS 與 make -e 都改不了，
# 否則 LIVE_PROJECT=secscan 會讓清理段以 -p secscan 執行 down -v（刪掉開發的 db_data）。清理段本身
# 也不用這些變數：env_guard 以自己的常數核對所有權（tests/unit/test_live_isolation_make.py 核對一致）。
override LIVE_PROJECT := secscan-live
override LIVE_COMPOSE_FILE := compose.yaml
override LIVE_SCAN_NET := secscan_live_scan_net
override LIVE_SCAN_SUBNET := 10.89.9.0/24
override LIVE_SCAN_IP_RANGE := 10.89.9.0/25
override LIVE_LAB_NET := secscan_live_lab_net
override LIVE_LAB_SUBNET := 10.89.10.0/24
override LIVE_LAB_IP_RANGE := 10.89.10.0/25
override LIVE_ENV := SECSCAN_SCAN_NET=$(LIVE_SCAN_NET) SECSCAN_RUNS_VOLUME=secscan_live_runs \
	SECSCAN_SECRETS_VOLUME=secscan_live_run_secrets API_PORT=8765 DB_PORT=55434 \
	RUNNER_FAKE_HOLD_SECONDS=15 SECSCAN_LAB_NET=$(LIVE_LAB_NET) LAB_CIDR=$(LIVE_LAB_SUBNET) \
	SECSCAN_SCAN_SUBNET=$(LIVE_SCAN_SUBNET) SECSCAN_GUARD_IP=10.89.9.254 \
	SECSCAN_GUARD_LAB_IP=10.89.10.254 SECSCAN_GUARD_POLICIES_VOLUME=secscan_live_guard_policies \
	SECSCAN_GUARD_STATUS_VOLUME=secscan_live_guard_status \
	SECSCAN_GUARD_TELEMETRY_VOLUME=secscan_live_guard_telemetry
# Live 的白名單環境（T23b-b2；docs/DECISIONS.md §32；計畫 §3.1.1）。Live 的每一個 docker、compose 與
# uv 的呼叫都經由 LIVE_PROC_ENV（Live 不呼叫子 make）：env -i 只留下 PATH、HOME、TMPDIR、LC_ALL、非秘密的 Docker
# 連線變數，以及 LIVE_PASS_ENV（Live 需要、不是秘密的變數；BENCH_KEY_FILE 是金鑰檔的路徑，不是金鑰）。
# recipe 設定的值（LIVE_FIXED_ENV）放在最後：同名時後面的值勝出。SECSCAN_LIVE_PROJECT 與
# ENABLE_LIVE_LAB_TESTS 由這裡固定設定，不從 shell 傳入。白名單的變數用 override：命令列、MAKEFLAGS 與
# 環境變數都改不了。LIVE_PYTEST_ENV 只接受 LIVE_PASS_ENV 的名稱（recipe 檢查）。
override LIVE_SECRETS_PREFIX := secscan-live-secrets.
LIVE_PYTEST_ENV :=
LIVE_PYTEST_ARGS :=
override LIVE_PASS_ENV := SECSCAN_RECORD_DIR SECSCAN_PARTIAL_BUDGET_SECONDS BENCH_SPEC BENCH_NAME \
	BENCH_KEY_FILE
override LIVE_BASE_ENV = env -i PATH="$$PATH" HOME="$$HOME" TMPDIR="$${TMPDIR:-/tmp}" \
	$${LC_ALL:+"LC_ALL=$$LC_ALL"} $${DOCKER_HOST:+"DOCKER_HOST=$$DOCKER_HOST"} \
	$${DOCKER_CONTEXT:+"DOCKER_CONTEXT=$$DOCKER_CONTEXT"} \
	$${DOCKER_CONFIG:+"DOCKER_CONFIG=$$DOCKER_CONFIG"} \
	$(foreach name,$(LIVE_PASS_ENV),$${$(name):+"$(name)=$$$(name)"})
override LIVE_FIXED_ENV = $(LIVE_ENV) SECSCAN_IMAGE_TAG=dev COMPOSE_DISABLE_ENV_FILE=1 \
	SECSCAN_SECRETS_DIR="$${secrets_dir:-/nonexistent/$(LIVE_SECRETS_PREFIX)unset}" \
	SECSCAN_LIVE_SECRETS_DIR="$${secrets_dir:-/nonexistent/$(LIVE_SECRETS_PREFIX)unset}" \
	PGPASSFILE=/dev/null SECSCAN_LIVE_PROJECT=$(LIVE_PROJECT) ENABLE_LIVE_LAB_TESTS=1
override LIVE_PROC_ENV = $(LIVE_BASE_ENV) $(LIVE_FIXED_ENV)
override LIVE_COMPOSE = $(LIVE_PROC_ENV) docker compose -p $(LIVE_PROJECT) -f $(LIVE_COMPOSE_FILE) \
	--profile app
override LIVE_GUARD = $(LIVE_PROC_ENV) $(UV_RUN) python -I $(REPO_DIR)tests/live/env_guard.py
# compose config --environment 允許的名稱（白名單的名稱；compose 自己加上的由 env_guard 允許）。
override LIVE_ALLOWED_NAMES = PATH HOME TMPDIR LC_ALL DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG \
	$(LIVE_PASS_ENV) $(foreach assignment,$(LIVE_ENV),$(firstword $(subst =, ,$(assignment)))) \
	SECSCAN_IMAGE_TAG COMPOSE_DISABLE_ENV_FILE SECSCAN_SECRETS_DIR SECSCAN_LIVE_SECRETS_DIR \
	PGPASSFILE SECSCAN_LIVE_PROJECT ENABLE_LIVE_LAB_TESTS
# Live 的 alembic 只以 *_FILE 取得拋棄式的秘密（-x dotenv=off：不讀 .env）。
override LIVE_SECRET_FILES = DB_PASSWORD_FILE="$$secrets_dir/db_password" \
	DB_OWNER_PASSWORD_FILE="$$secrets_dir/db_owner_password" \
	SECRET_ENCRYPTION_KEYS_FILE="$$secrets_dir/secret_encryption_keys" \
	EVIDENCE_ENCRYPTION_KEYS_FILE="$$secrets_dir/evidence_encryption_keys" \
	CONTENT_ENCRYPTION_KEYS_FILE="$$secrets_dir/content_encryption_keys"

.PHONY: bootstrap dev test lint typecheck env docker-check db-up db-down test-db-up migrate \
	db-roles-migrate test-live-db-roles \
	lab-net lab-up lab-down lab-verify lab-images build images ensure-net scan-net up down \
	test-live-runner test-live-zap record-fixtures test-contract test-live-lab \
	test-live-fixture test-live-fixture-nuclei nuclei-templates nuclei-templates-check \
	owasp-top10 owasp-top10-check test-live-fixture-findings test-live-fixture-rescan \
	bench-check bench-live-check bench bench-evaluate bench-key bench-seal runs-layout-migrate \
	secrets test-live-secrets

# 安裝鎖定的依賴（含開發工具）並啟用 pre-commit hook。
bootstrap:
	uv sync --locked
	$(UV_RUN) pre-commit install

# 啟動 API 開發程序：只綁 127.0.0.1，APP_ENV=dev 才開啟 API 文件。API 需要 .env 中的加密金鑰，
# 所以先執行 make env（只補上缺少的值）。
dev: env
	APP_ENV=dev $(UV_RUN) uvicorn --factory secscan.main:create_app \
		--host 127.0.0.1 --port 8000 --reload --reload-dir src

# fixture 與工具輸出的 contract 測試：不連網、不碰 Docker 與 DB。
test-contract:
	$(UV_RUN) pytest tests/contract -q

# unit/contract/integration 測試與 coverage 門檻（分支覆蓋），不做 live scan、不跑 live 測試。
# 測試程序本身不連網、也不碰 Docker（tests/isolation.py）；整合測試用的 db-test 由這裡先啟動。
test: test-db-up
	$(UV_RUN) pytest -m "not live" --cov --cov-report=term-missing --cov-fail-under=80

# ruff lint、format 檢查與 import-linter 依賴方向檢查。
lint:
	$(UV_RUN) ruff check .
	$(UV_RUN) ruff format --check .
	$(UV_RUN) lint-imports

# mypy strict。
typecheck:
	$(UV_RUN) mypy

# 建立或補齊本機 .env（權限 600）：只新增缺少的秘密，不修改、重設或輪替既有的值（金鑰換版由
# 操作者手動進行，docs/DECISIONS.md §12.3、§30.6）。任何一個是空值時，在寫入之前就停止。
# 產生的值只寫進 .env，終端只顯示名稱。
env:
	@umask 077; touch .env; chmod 600 .env
	@for key in $(LOCAL_SECRET_KEYS) $(ENCRYPTION_KEYS_VARS); do \
		if grep -Eq "$(ENV_LINE)$$key[[:space:]]*=[[:space:]]*$$" .env; then \
			echo "錯誤：.env 的 $$key 是空值；請刪除那一行再執行 make env（不會覆寫既有的值）"; exit 1; \
		fi; \
	done
	@for key in $(LOCAL_SECRET_KEYS); do \
		if ! grep -Eq "$(ENV_LINE)$$key[[:space:]]*=" .env; then \
			secret=$$(openssl rand -hex 24) || exit 1; \
			[ "$${#secret}" -eq 48 ] || { echo "錯誤：openssl 沒有產生有效的隨機值"; exit 1; }; \
			if [ -s .env ] && [ -n "$$(tail -c1 .env)" ]; then echo >> .env; fi; \
			echo "$$key=$$secret" >> .env; \
			echo "已在 .env 產生 $$key（隨機值，只供本機使用）"; \
		fi; \
	done
	@for key in $(ENCRYPTION_KEYS_VARS); do \
		if ! grep -Eq "$(ENV_LINE)$$key[[:space:]]*=" .env; then \
			value=$$(openssl rand -base64 32 | tr '+/' '-_') || exit 1; \
			[ "$${#value}" -eq 44 ] || { echo "錯誤：openssl 沒有產生有效的金鑰"; exit 1; }; \
			if [ -s .env ] && [ -n "$$(tail -c1 .env)" ]; then echo >> .env; fi; \
			echo "$$key=$$value" >> .env; \
			echo "已在 .env 產生 $$key（加密金鑰；遺失之後用它加密的資料都解不開，請備份這一行）"; \
		fi; \
	done

docker-check:
	@docker version >/dev/null 2>&1 || { echo "Docker daemon 未執行，請先啟動 OrbStack（orb start）"; exit 1; }

# compose secrets 的秘密檔（T23b-b2；docs/DECISIONS.md §32）：由 .env 寫出 secrets/（目錄 0700、
# 檔案 0600、沒有結尾換行）；內容相同就不動，不同時原子替換。.env 不改；終端只顯示名稱。
# SECRETS_CHECK=1 只檢查、不寫入（缺少或不一致就失敗）。換版之後要 --force-recreate 持有它的服務；
# db 的角色密碼不會跟著改（README）。第一次初始化 db 期間不要執行（OrbStack 上執行中的容器會立刻
# 看到替換後的檔案）。需要 uv 與同步好的 venv。
secrets: env
	$(UV_RUN) secscan-admin sync-secret-files --dir secrets $(if $(SECRETS_CHECK),--check,)

# 開發用 PostgreSQL（只綁 127.0.0.1，預設 port 55432）。
db-up: env secrets docker-check
	$(DEV_COMPOSE) up -d --wait db

# 整合測試用 PostgreSQL（tmpfs，只綁 127.0.0.1，預設 port 55433）。
test-db-up: env secrets docker-check
	$(DEV_COMPOSE) --profile test up -d --wait db-test

# 停止 db 與 db-test；開發資料保存在 volume，不會刪除。
db-down:
	$(DEV_COMPOSE) --profile test down

# 把開發資料庫升級到最新 schema（Alembic upgrade head）；不做任何破壞性重置。以 owner 角色
# （DB_OWNER_*）執行，每次先檢查角色（docs/DECISIONS.md §31.4）；沒有 DB_OWNER_PASSWORD 就停止，
# 不退回應用程式角色。T23b-b1 之前建立的開發 DB 先執行 make db-roles-migrate（README）。
# 最後印出目前版本（例如 0025 (head)），確認實際升級到哪裡。
migrate:
	$(UV_RUN) alembic upgrade head
	@$(UV_RUN) alembic current

# 既有的開發 DB（T23b-b1 之前由應用程式角色擁有）：把擁有權移轉給 owner，只需要一次（§31.5）。
# 在主機上以 superuser（DB_ADMIN_PASSWORD）執行；範圍不符就拒絕、不做任何改變。先以 DRY_RUN=1
# 確認列出的範圍，再執行一次，之後 make migrate。執行之前先 make down（不能有應用程式的連線）。
db-roles-migrate:
	$(UV_RUN) secscan-admin migrate-db-roles $(if $(DRY_RUN),--dry-run,)

# 啟動隔離 lab 靶場（只接 internal network，不發布 port）。
lab-up: docker-check lab-net
	@# up 之前先擋掉對外 port 與 host 網路的設定
	@if $(COMPOSE) -f $(LAB_FILE) $(LAB_PROFILE_ARGS) config | grep -qE '^[[:space:]]*(published|network_mode):'; then \
		echo "錯誤：compose 含對外 port 或 network_mode，lab 必須完全隔離"; exit 1; fi
	$(COMPOSE) -f $(LAB_FILE) $(LAB_PROFILE_ARGS) up -d --wait
	@$(MAKE) --no-print-directory lab-verify \
		|| { echo "隔離檢查失敗，收回 lab"; $(COMPOSE) -f $(LAB_FILE) --profile juice-shop --profile vampi down; exit 1; }
	@echo "lab 已啟動（profiles：$(LAB_PROFILES)）；關閉用 make lab-down"

# 驗證 lab 真的隔離：internal、isolated gateway、無對外 port（M2 live 測試前置可共用）。
lab-verify:
	@n=$$(docker ps -q --filter "label=com.docker.compose.project=$(LAB_PROJECT)" | wc -l | tr -d ' '); \
		[ "$$n" -gt 0 ] || { echo "錯誤：找不到 lab 容器"; exit 1; }
	@docker network inspect $(LAB_NET) --format '{{.Internal}}' | grep -qx true \
		|| { echo "錯誤：$(LAB_NET) 不是 internal network"; exit 1; }
	@test "$$(docker network inspect $(LAB_NET) --format '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}')" = isolated \
		|| { echo "錯誤：$(LAB_NET) 不是 isolated gateway（舊 Engine 可能不支援）"; exit 1; }
	@ports=$$(docker ps --filter "label=com.docker.compose.project=$(LAB_PROJECT)" --format '{{.Ports}}'); \
		echo "$$ports" | grep -qF -- '->' && { echo "錯誤：偵測到對外發布的 port"; exit 1; } || true
	@echo "lab 隔離檢查通過（internal + isolated + 無對外 port）"

# 停止並移除 lab。注意：spike（spikes/t03）若仍接在 $(LAB_NET) 上，網路會刪不掉，需先停 spike。
lab-down:
	$(COMPOSE) -f $(LAB_FILE) --profile juice-shop --profile vampi down --remove-orphans

# 以 digest pull compose.lab.yaml 鎖定的靶機映像（Juice Shop、VAmPI）；不啟動任何容器。
lab-images: docker-check
	$(COMPOSE) -f $(LAB_FILE) --profile juice-shop --profile vampi pull --quiet

# 建立 secscan 的應用程式映像（api、runner、worker 共用）與 egress guard 的映像。
build: docker-check
	$(APP_COMPOSE) build api guard

# 以 digest pull 核准的掃描器映像與 socket-proxy（runner 本身不 pull）。
images: docker-check
	@for image in $(SCANNER_IMAGES); do docker pull --quiet "$$image" >/dev/null || exit 1; done
	$(APP_COMPOSE) pull --quiet socket-proxy

# 產生 T17 凍結的 Nuclei 模板清單（docs/DECISIONS.md §23）：驗證鎖定 archive 的 sha256、乾淨解壓、
# 在鎖定映像裡離線跑 nuclei -tl，寫出 src/secscan/scanners/domain/nuclei/templates.lock.txt。
# 不連任何目標、不出網；映像不在本機時以 digest 拉取。產生後把 lock sha256 填回 policy.py 與 manifest。
nuclei-templates: docker-check
	$(UV_RUN) python tools/freeze_nuclei_templates.py

# 只驗證凍結清單能從鎖定來源逐位元組重現（不覆寫；和 tests/live/test_nuclei_templates_live.py 同一條檢查）。
nuclei-templates-check: docker-check
	$(UV_RUN) python tools/freeze_nuclei_templates.py --check

# 產生 T19 凍結的 OWASP Top 10:2025 官方 CWE 對應表（docs/DECISIONS.md §25.5）：讀手動下載到
# runs/t19-owasp/<commit>/ 的 10 個分類 markdown（鎖定 commit、逐檔驗 sha256），寫出
# src/secscan/findings/taxonomy/owasp_top10_2025.json。不連網、不需要 Docker；下載方式見工具的檔頭。
owasp-top10:
	$(UV_RUN) python tools/freeze_owasp_top10.py

# 只驗證對應表能從鎖定的官方來源逐位元組重現（不覆寫）。
owasp-top10-check:
	$(UV_RUN) python tools/freeze_owasp_top10.py --check

# 建立或檢查一個 internal＋gateway isolated 的網路（NET、SUBNET、IP_RANGE 由呼叫端給定）。
# 已存在時只檢查：舊的網路沒有 ip-range 時會失敗，刪除後重建（README）。
ensure-net: docker-check
	@docker network inspect $(NET) >/dev/null 2>&1 || docker network create --internal --opt com.docker.network.bridge.gateway_mode_ipv4=isolated --subnet $(SUBNET) --ip-range $(IP_RANGE) $(NET) >/dev/null
	@docker network inspect $(NET) --format '{{.Internal}}' | grep -qx true \
		|| { echo "錯誤：$(NET) 不是 internal network"; exit 1; }
	@test "$$(docker network inspect $(NET) --format '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}')" = isolated \
		|| { echo "錯誤：$(NET) 不是 isolated gateway"; exit 1; }
	@test "$$(docker network inspect $(NET) --format '{{range .IPAM.Config}}{{.Subnet}} {{.IPRange}}{{end}}')" = "$(SUBNET) $(IP_RANGE)" \
		|| { echo "錯誤：$(NET) 的網段或 ip-range 不是 $(SUBNET)、$(IP_RANGE)；請刪除後重建（見 README）"; exit 1; }

# 掃描容器的網路（scan_net）與靶機的網路（lab_net）。
scan-net:
	@$(MAKE) --no-print-directory ensure-net NET=$(SCAN_NET) SUBNET=$(SCAN_SUBNET) IP_RANGE=$(SCAN_IP_RANGE)

lab-net:
	@$(MAKE) --no-print-directory ensure-net NET=$(LAB_NET) SUBNET=$(LAB_SUBNET) IP_RANGE=$(LAB_IP_RANGE)

# 啟動 app stack（db、api、runner、worker、socket-proxy、guard，以及一次性的 runs-init）。API 只綁
# 127.0.0.1:$${API_PORT:-8000}。第一次使用先執行 make migrate（db 的 schema）與 create-admin-key。
# runs volume 是舊的 layout 時 runs-init 失敗，runner 與 worker 不啟動：先執行 make runs-layout-migrate。
up: env secrets docker-check scan-net lab-net images build
	$(APP_COMPOSE) up -d --wait

# 停止 app stack 與 db（資料保留在 volume）。
down:
	$(APP_COMPOSE) down

# 既有的 runs volume 搬到新的 layout（docs/DECISIONS.md §30.13）。升級順序：make down → make db-up →
# make migrate → make runs-layout-migrate DRY_RUN=1 → make runs-layout-migrate → make up。
# 1. 以和 make up 相同的設定（APP_COMPOSE）解析實際的 runs volume（cli/runs_volume.py）；解析失敗就
#    拒絕，不退回預設名稱。
# 2. volume 不存在就不需要搬移。存在時：compose 的標籤必須是這個 project 的 runs；api、worker、
#    runner 都沒有在執行；沒有任何容器（含已停止的）使用它。docker 指令失敗視為無法確認，拒絕。
# 3. 在 runner 容器內執行（--no-deps：不啟動 runs-init），容器內再比對一次 volume 的名稱與掛載。
runs-layout-migrate: env secrets docker-check
	@config=$$($(APP_COMPOSE) config runs-init --format json) \
		|| { echo "無法解析 compose 的設定：拒絕搬移"; exit 1; }; \
	parsed=$$(printf '%s' "$$config" | $(UV_RUN) python -m secscan.cli.runs_volume) \
		|| { echo "無法取得 runs volume 的名稱：拒絕搬移"; exit 1; }; \
	project=$${parsed% *}; volume=$${parsed#* }; \
	names=$$(docker volume ls --format '{{.Name}}') \
		|| { echo "無法列出 Docker volume：拒絕搬移"; exit 1; }; \
	if ! printf '%s\n' "$$names" | grep -Fxq "$$volume"; then \
		echo "runs volume $${volume} 不存在：沒有需要搬移的資料，make up 會建立新的 layout"; exit 0; \
	fi; \
	labels=$$(docker volume inspect --format '{{index .Labels "com.docker.compose.project"}} {{index .Labels "com.docker.compose.volume"}}' "$$volume") \
		|| { echo "無法檢查 runs volume：拒絕搬移"; exit 1; }; \
	[ "$$labels" = "$$project runs" ] \
		|| { echo "runs volume $${volume} 不是 compose 專案 $${project} 的 runs（標籤：$${labels}）：拒絕搬移，請人工確認"; exit 1; }; \
	running=$$($(APP_COMPOSE) ps --status running --services) \
		|| { echo "無法列出執行中的服務：拒絕搬移"; exit 1; }; \
	for service in api worker runner; do \
		if printf '%s\n' "$$running" | grep -Fxq "$$service"; then \
			echo "$${service} 還在執行：請先 make down"; exit 1; \
		fi; \
	done; \
	users=$$(docker ps -a --filter "volume=$$volume" --format '{{.Names}} {{.Status}}') \
		|| { echo "無法列出使用 runs volume 的容器：拒絕搬移"; exit 1; }; \
	if [ -n "$$users" ]; then \
		echo "還有容器（含已停止的）使用 runs volume，確認之後刪除再執行："; \
		printf '%s\n' "$$users"; exit 1; \
	fi; \
	$(APP_COMPOSE) run --rm --no-deps runner secscan-admin migrate-runs-layout \
		--expect-volume "$$volume" $(if $(DRY_RUN),--dry-run,)

# live 測試：真的 Docker、socket-proxy、egress guard 與 fake 容器；guard 的測試在 live 自己的 lab 網路
# 上啟動接收端（不啟動 Juice Shop、VAmPI）。需要自己設定 ENABLE_LIVE_LAB_TESTS=1；在獨立的 compose
# 專案建立、測試、一律拆除：先刪掉接在這兩個網路上的容器（測試的接收端、探針與孤兒的掃描容器，
# 否則 volume 還在使用中刪不掉；-v 一併刪掉它們的匿名 volume），再刪 compose 的服務、volume 與網路。
# 會中斷 stack 的測試（停掉 guard、kill runner）放在最後執行。
# Live 的隔離（T23b-b2；docs/DECISIONS.md §32；計畫 §3.1）：
# - 不讀、不用開發環境的任何秘密：每次以 generate-secret-files 在新的拋棄式目錄（mktemp）產生秘密；
#   compose 不讀專案目錄的 .env（COMPOSE_DISABLE_ENV_FILE=1）；alembic 以 -x dotenv=off 執行、秘密只以
#   *_FILE 傳入。不依賴 env、secrets、docker-check、images、build：不碰開發的 .env 與 secrets/。
# - 所有呼叫都經由 LIVE_PROC_ENV（白名單）；Live 專用的 pull、build 與網路也在 recipe 內。
# - recipe 是一個邏輯行，開頭先檢查 ENABLE_LIVE_LAB_TESTS 與 LIVE_PYTEST_ENV，之後才有任何副作用；
#   不含 $(MAKE)（直接或經由變數）：GNU make 對含 $(MAKE) 的行在 -n、-q、-t 下仍會執行（安全審查
#   H1）。所以 make -n／-q／-t 這些 Live 目標不會執行任何一步；網路由 env_guard 建立，不呼叫子 make。
# - up 之前以 tests/live/env_guard.py 驗證 compose 解析出來的設定（允許清單）；up 之後核對映像 ID；
#   開始時、up 之前、結束時確認同一個 Engine。開始之前拒絕上一次留下的資源、拋棄式目錄與清理失敗的
#   診斷檔。
# - 所有權與清理（G1 審查 M2、MEDIUM-1、2）：engine、preflight、快照都通過、拋棄式目錄建立之後才安裝
#   trap，接著立刻以這次的識別（拋棄式目錄的名稱）標記並建立兩個網路：網路已存在就停止（另一次 Live
#   正在執行），不清理別人的資源。清理（含失敗與中斷）由 env_guard cleanup 執行，只處理標記屬於這次
#   執行的資源；down -v 之前核對專案、volume 與網路的名稱；失敗時回報並在 TMPDIR 留下診斷檔（下一次
#   的 preflight 看到它就拒絕執行）。最後比對開發環境的前後快照，有差異就失敗。
LIVE_TESTS := tests/live/test_runner_live.py tests/live/test_guard_live.py \
	tests/live/test_budget_live.py tests/live/test_revocation_live.py \
	tests/live/test_guard_failover_live.py
test-live-runner:
	@[ "$$ENABLE_LIVE_LAB_TESTS" = 1 ] || { echo "需要設定 ENABLE_LIVE_LAB_TESTS=1"; exit 1; }; \
	for assignment in $(LIVE_PYTEST_ENV); do \
		case " $(LIVE_PASS_ENV) " in \
			*" $${assignment%%=*} "*) ;; \
			*) echo "LIVE_PYTEST_ENV 只接受這些變數：$(LIVE_PASS_ENV)"; exit 1 ;; \
		esac; \
	done; \
	base="$${TMPDIR:-/tmp}"; base="$${base%/}"; secrets_dir=""; snapshot=""; \
	live_cleanup() { \
		code=$$1; trap - EXIT INT TERM HUP; \
		$(LIVE_GUARD) cleanup --base "$$base" --secrets-dir "$$secrets_dir" || code=1; \
		printf '%s' "$$snapshot" | $(LIVE_GUARD) compare --root "$(CURDIR)" || code=1; \
		exit $$code; \
	}; \
	engine=$$($(LIVE_GUARD) engine) || exit 1; \
	$(LIVE_GUARD) preflight --base "$$base" || exit 1; \
	snapshot=$$($(LIVE_GUARD) snapshot --root "$(CURDIR)") || exit 1; \
	secrets_dir=$$(mktemp -d "$$base/$(LIVE_SECRETS_PREFIX)XXXXXX") || exit 1; \
	trap 'live_cleanup $$?' EXIT; trap 'live_cleanup 130' INT TERM HUP; \
	$(LIVE_GUARD) networks --secrets-dir "$$secrets_dir" \
		--network $(LIVE_SCAN_NET) $(LIVE_SCAN_SUBNET) $(LIVE_SCAN_IP_RANGE) \
		--network $(LIVE_LAB_NET) $(LIVE_LAB_SUBNET) $(LIVE_LAB_IP_RANGE) || exit 1; \
	$(LIVE_PROC_ENV) $(UV_RUN) secscan-admin generate-secret-files "$$secrets_dir" || exit 1; \
	for image in $(SCANNER_IMAGES); do \
		$(LIVE_PROC_ENV) docker pull --quiet "$$image" >/dev/null || exit 1; \
	done; \
	$(LIVE_COMPOSE) pull --quiet socket-proxy || exit 1; \
	$(LIVE_COMPOSE) build api guard || exit 1; \
	app_image=$$($(LIVE_PROC_ENV) docker image inspect --format '{{.Id}}' secscan:dev) || exit 1; \
	guard_image=$$($(LIVE_PROC_ENV) docker image inspect --format '{{.Id}}' secscan-guard:dev) \
		|| exit 1; \
	$(LIVE_COMPOSE) config --format json \
		| $(LIVE_GUARD) check-config --secrets-dir "$$secrets_dir" --root "$(CURDIR)" || exit 1; \
	$(LIVE_COMPOSE) config --no-env-resolution --format json \
		| $(LIVE_GUARD) check-unresolved || exit 1; \
	$(LIVE_COMPOSE) config --environment \
		| $(LIVE_GUARD) check-environment --allow $(LIVE_ALLOWED_NAMES) || exit 1; \
	$(LIVE_GUARD) engine --expect "$$engine" >/dev/null || exit 1; \
	$(LIVE_COMPOSE) up -d --wait db || exit 1; \
	$(LIVE_PROC_ENV) $(LIVE_SECRET_FILES) $(UV_RUN) alembic -x dotenv=off upgrade head \
		>/dev/null || exit 1; \
	$(LIVE_COMPOSE) up -d --wait || exit 1; \
	$(LIVE_GUARD) check-images --app-image "$$app_image" --guard-image "$$guard_image" || exit 1; \
	$(LIVE_BASE_ENV) $(LIVE_PYTEST_ENV) $(LIVE_FIXED_ENV) $(UV_RUN) pytest -m live \
		-p no:cacheprovider $(LIVE_PYTEST_ARGS) $(LIVE_TESTS) || exit 1; \
	$(LIVE_GUARD) engine --expect "$$engine" >/dev/null || exit 1

# ZAP 的 live 測試（docs/DECISIONS.md §18.10、§19）：同一個獨立的 secscan-live 專案與流程。runner
# 啟動時以真的 ZAP 映像執行 capability probe；掃描的是 live 自己 lab 網路上的小型網站
# （tests/live/zap_site.py），不啟動 Juice Shop、VAmPI。
test-live-zap: LIVE_TESTS := tests/live/test_zap_live.py
test-live-zap: test-live-runner

# DDL／DML 分權的 live 驗收（T23b-b1；docs/DECISIONS.md §31）：同一個獨立的 secscan-live 專案與流程。
# 在真的 stack 上確認 initdb 建立了兩個角色、migration 以 owner 執行、api／runner／worker 都以應用程式
# 角色連線、應用程式角色的 DDL 被拒，三個服務的環境變數名稱中沒有 owner 的密碼。
test-live-db-roles: LIVE_TESTS := tests/live/test_db_roles_live.py
test-live-db-roles: test-live-runner

# compose secrets 與 Live 隔離的 live 驗收（T23b-b2；docs/DECISIONS.md §32）：同一個獨立的 secscan-live
# 專案與流程（拋棄式的秘密）。容器的設定、服務程序的環境、/run/secrets 的掛載與內容、db 經由 wrapper 的
# 初始化、compose 的設定、遷移不退回 .env、有效的 log 設定（CSEC-L1 到 L6）。
test-live-secrets: LIVE_TESTS := tests/live/test_secrets_live.py
test-live-secrets: test-live-runner

# 錄製 ZAP 的真實輸出（docs/DECISIONS.md §19.9）：同一個 live 流程，只執行錄製的情境（anonymous），
# 輸出到 recordings/zap/<情境>/（gitignore）。人工審查之後才搬進 tests/fixtures/zap/。約 15 分鐘。
record-fixtures: LIVE_TESTS := tests/live/test_zap_record_live.py
record-fixtures: LIVE_PYTEST_ENV := SECSCAN_RECORD_DIR=$(CURDIR)/recordings/zap
record-fixtures: test-live-runner

# T16（docs/DECISIONS.md §20）：同一個 live 流程，以真的 ZAP 掃描 Juice Shop 與 VAmPI（弱點版與安全版），
# 加上 token 失效、工具超時與取消。靶機由測試在 live 自己的 lab 網路上逐一啟動（一次一個：記憶體）。
# 量測印在輸出（-s），輸出錄製到 recordings/lab/<情境>/（gitignore）。約 27 分鐘。
test-live-lab: LIVE_TESTS := tests/live/test_lab_zap_live.py
test-live-lab: LIVE_PYTEST_ENV := SECSCAN_RECORD_DIR=$(CURDIR)/recordings/lab
test-live-lab: LIVE_PYTEST_ARGS := -s
test-live-lab: lab-images test-live-runner

# T30（docs/SECURITY_AND_TESTING.md §5）：以真的 ZAP 掃描自製的 fixture app（弱點版與修補版），
# 量測 ground truth。fixture app 跑在 guard 映像的 python（stdlib），由測試在 live 自己的 lab 網路上
# 啟動（一次一個；不需要 Juice Shop／VAmPI 映像）。strict-1 下被 guard 擋下的案例另記為平台阻擋
# （DECISIONS.md §21.5）。量測印在輸出（-s），錄製到 recordings/fixture/<情境>/（gitignore）。
test-live-fixture: LIVE_TESTS := tests/live/test_fixture_zap_live.py
test-live-fixture: LIVE_PYTEST_ENV := SECSCAN_RECORD_DIR=$(CURDIR)/recordings/fixture
test-live-fixture: LIVE_PYTEST_ARGS := -s
test-live-fixture: test-live-runner

# T18（docs/SECURITY_AND_TESTING.md §5）：以真的 Nuclei 掃描同一個 fixture app（弱點版與修補版）。
# insecure 反射 CORS → cors-misconfig 命中；secure 補安全 header → 不命中。同樣跑在 guard 映像的
# python，不需要 Juice Shop／VAmPI 映像。量測印在輸出（-s），錄製到 recordings/fixture-nuclei/。
test-live-fixture-nuclei: LIVE_TESTS := tests/live/test_fixture_nuclei_live.py
test-live-fixture-nuclei: LIVE_PYTEST_ENV := SECSCAN_RECORD_DIR=$(CURDIR)/recordings/fixture-nuclei
test-live-fixture-nuclei: LIVE_PYTEST_ARGS := -s
test-live-fixture-nuclei: test-live-runner

# T19（docs/DECISIONS.md §25）：同一個 scan 以真的 ZAP 與 Nuclei 掃 fixture app 的弱點版與修補版，
# worker 連結 finding；以 GET /scans/{id}/findings 驗證跨引擎合併、最高等級與衝突、每個觀察連結一次。
# T20（§26）：以追溯 API 驗證每個觀察追到報告與 run、去重的不變式；另跑小時間預算的部分失敗情境
# （SECSCAN_PARTIAL_BUDGET_SECONDS，預設 240）。量測印在輸出（-s），錄製到 recordings/fixture-findings/。
# 約 25 分鐘。
test-live-fixture-findings: LIVE_TESTS := tests/live/test_fixture_findings_live.py
test-live-fixture-findings: LIVE_PYTEST_ENV := SECSCAN_RECORD_DIR=$(CURDIR)/recordings/fixture-findings
test-live-fixture-findings: LIVE_PYTEST_ARGS := -s
test-live-fixture-findings: test-live-runner

# T22：同一個 target 依序跑弱點版、未修補對照、修補版、小預算複掃，再建立不可變比較快照。
# host/IP/port 與 grant 不變；只掃自己的 fixture，依既有 live 流程建立並清理隔離環境。
test-live-fixture-rescan: LIVE_TESTS := tests/live/test_fixture_rescan_live.py
test-live-fixture-rescan: LIVE_PYTEST_ENV := SECSCAN_RECORD_DIR=$(CURDIR)/recordings/fixture-rescan
test-live-fixture-rescan: LIVE_PYTEST_ARGS := -s
test-live-fixture-rescan: test-live-runner

# T31（docs/DECISIONS.md §29）：benchmark harness。BENCH_SPEC 是實驗規格，BENCH_NAME 是新的結果目錄
# （benchmarks/results/<BENCH_NAME>/，只收英數字、- 與 _，已存在就停止，不覆寫）。
# 這些值以環境變數交給 recipe、由 shell 展開（"$$BENCH_SPEC"），不嵌進 shell 的文字：路徑中的引號或
# 反引號不會變成指令。
# bench-check 離線檢查規格與名稱（不連網、不碰 Docker）；bench 先做這兩項檢查（以及
# ENABLE_LIVE_LAB_TESTS），都通過之後才遞迴執行 test-live-runner：即使以 make -j 執行，stack 也不會在
# 檢查完成之前啟動。建立、測試與清理完全沿用 test-live-runner 的同一個隔離 stack 與範圍，不另外清理
# 任何東西。不自動重試；環境故障就整批作廢、換新的 BENCH_NAME 重跑。Juice Shop、VAmPI 的映像要先以
# make lab-images 取得（harness 不 pull）。
# bench-evaluate 離線、只讀結果目錄，評估以 JSON 寫到 stdout；BENCH_TRUTH、BENCH_ADJUDICATIONS、
# BENCH_PAIR_LABELS 是選填的檔案，BENCH_INCLUDE_HOLDOUT 設成任何非空的值就納入 holdout。
# T23a（docs/DECISIONS.md §30.7）：結果檔以本機的 bench 金鑰加密（BENCH_KEY_FILE，預設
# ~/.config/secscan/bench-keys；不可放在 repo 中）。bench-key 以 O_EXCL 建立新的金鑰檔，已經存在就
# 失敗、不覆寫，也不輸出金鑰；金鑰遺失之後結果無法復原，請另外備份。bench-seal 把 T23a 之前的明文
# 結果目錄（BENCH_SOURCE）轉成新的加密結果目錄（BENCH_NAME），原目錄不修改也不刪除。三者都離線。
BENCH_RESULTS := $(CURDIR)/benchmarks/results
export BENCH_SPEC BENCH_NAME BENCH_TRUTH BENCH_ADJUDICATIONS BENCH_PAIR_LABELS BENCH_INCLUDE_HOLDOUT BENCH_SOURCE BENCH_KEY_FILE
bench-check:
	@[ -n "$$BENCH_SPEC" ] && [ -n "$$BENCH_NAME" ] || { echo "需要設定 BENCH_SPEC 與 BENCH_NAME"; exit 1; }
	@$(UV_RUN) python -m benchmarks.cli check-spec "$$BENCH_SPEC" "$$BENCH_NAME" \
		--results-root "$(BENCH_RESULTS)"

bench-live-check:
	@[ "$$ENABLE_LIVE_LAB_TESTS" = 1 ] || { echo "需要設定 ENABLE_LIVE_LAB_TESTS=1"; exit 1; }

bench: bench-live-check bench-check
	@$(MAKE) --no-print-directory test-live-runner LIVE_TESTS=tests/live/test_bench_live.py \
		LIVE_PYTEST_ARGS=-s

bench-evaluate:
	@[ -n "$$BENCH_NAME" ] || { echo "需要設定 BENCH_NAME"; exit 1; }
	@$(UV_RUN) python -m benchmarks.cli evaluate "$$BENCH_NAME" --results-root "$(BENCH_RESULTS)" \
		$${BENCH_TRUTH:+--truth "$$BENCH_TRUTH"} \
		$${BENCH_ADJUDICATIONS:+--adjudications "$$BENCH_ADJUDICATIONS"} \
		$${BENCH_PAIR_LABELS:+--pair-labels "$$BENCH_PAIR_LABELS"} \
		$${BENCH_INCLUDE_HOLDOUT:+--include-holdout}

bench-key:
	@$(UV_RUN) python -m benchmarks.cli create-key

bench-seal:
	@[ -n "$$BENCH_SOURCE" ] && [ -n "$$BENCH_NAME" ] || { echo "需要設定 BENCH_SOURCE 與 BENCH_NAME"; exit 1; }
	@$(UV_RUN) python -m benchmarks.cli seal-results "$$BENCH_SOURCE" "$$BENCH_NAME" \
		--results-root "$(BENCH_RESULTS)"
