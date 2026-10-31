# 開發命令，依 docs/START_HERE.md §7 的約定建立。
# 一律使用 uv.lock 鎖定的依賴（--locked）；lock 與 pyproject.toml 不一致時直接失敗，不會默默更新。
UV_RUN := uv run --locked

# OrbStack 目前沒有 compose 外掛，`docker compose` 不可用時改用 docker-compose。
# 用遞延指派（=）：只有 lab 目標才會求值，避免每次 make test/lint 都 fork docker。
COMPOSE = $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)
DB_FILE := compose.yaml
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
LOCAL_SECRET_KEYS := DB_PASSWORD DB_ADMIN_PASSWORD TEST_DB_PASSWORD
# 加密目標 secret 的金鑰（docs/DECISIONS.md §12.1）：Fernet 金鑰，url-safe base64 的 32 bytes（44 個字元）。
ENCRYPTION_KEYS_VAR := SECRET_ENCRYPTION_KEYS
# .env 中一行的開頭：dotenv 也接受 `export ` 前綴與等號前後的空白，比對時要一樣寬，
# 否則會再附加一行，而後面的那一行會默默取代原本的值（對加密金鑰而言，舊的 secret 就解不開了）。
ENV_LINE := ^[[:space:]]*(export[[:space:]]+)?

# app stack（docs/DECISIONS.md §14.8）。掃描容器的網路由這裡建立，compose 只引用（external）。
SCAN_NET ?= secscan_scan_net
SCAN_SUBNET ?= 10.89.8.0/24
SCAN_IP_RANGE ?= 10.89.8.0/25
# runner 不 pull 映像：核准的掃描器映像由這裡以 digest pull（和 runner/domain/policy.py 一致，
# tests/unit/test_deployment.py 會核對）。
SCANNER_IMAGES := busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e zaproxy/zap-stable:20261016@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6
# live 測試用的獨立 stack：自己的 DB volume、網路與 volume 名稱；API 只綁 127.0.0.1:8765。
LIVE_PROJECT := secscan-live
LIVE_SCAN_NET := secscan_live_scan_net
LIVE_SCAN_SUBNET := 10.89.9.0/24
LIVE_SCAN_IP_RANGE := 10.89.9.0/25
LIVE_LAB_NET := secscan_live_lab_net
LIVE_LAB_SUBNET := 10.89.10.0/24
LIVE_LAB_IP_RANGE := 10.89.10.0/25
LIVE_ENV := SECSCAN_SCAN_NET=$(LIVE_SCAN_NET) SECSCAN_RUNS_VOLUME=secscan_live_runs \
	SECSCAN_SECRETS_VOLUME=secscan_live_run_secrets API_PORT=8765 DB_PORT=55434 \
	RUNNER_FAKE_HOLD_SECONDS=15 SECSCAN_LAB_NET=$(LIVE_LAB_NET) LAB_CIDR=$(LIVE_LAB_SUBNET) \
	SECSCAN_SCAN_SUBNET=$(LIVE_SCAN_SUBNET) SECSCAN_GUARD_IP=10.89.9.254 \
	SECSCAN_GUARD_LAB_IP=10.89.10.254 SECSCAN_GUARD_POLICIES_VOLUME=secscan_live_guard_policies \
	SECSCAN_GUARD_STATUS_VOLUME=secscan_live_guard_status \
	SECSCAN_GUARD_TELEMETRY_VOLUME=secscan_live_guard_telemetry
LIVE_COMPOSE = $(LIVE_ENV) $(COMPOSE) -p $(LIVE_PROJECT) -f $(DB_FILE) --profile app

.PHONY: bootstrap dev test lint typecheck env docker-check db-up db-down test-db-up migrate \
	lab-net lab-up lab-down lab-verify build images ensure-net scan-net up down test-live-runner \
	test-live-zap record-fixtures

# 安裝鎖定的依賴（含開發工具）並啟用 pre-commit hook。
bootstrap:
	uv sync --locked
	$(UV_RUN) pre-commit install

# 啟動 API 開發程序：只綁 127.0.0.1，APP_ENV=dev 才開啟 API 文件。API 需要 .env 中的加密金鑰，
# 所以先執行 make env（只補上缺少的值）。
dev: env
	APP_ENV=dev $(UV_RUN) uvicorn --factory secscan.main:create_app \
		--host 127.0.0.1 --port 8000 --reload --reload-dir src

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

# 建立或補齊本機 .env（權限 600）：只新增缺少的秘密，不修改既有的值。
env:
	@umask 077; touch .env; chmod 600 .env
	@for key in $(LOCAL_SECRET_KEYS); do \
		if grep -Eq "$(ENV_LINE)$$key[[:space:]]*=[[:space:]]*$$" .env; then \
			echo "錯誤：.env 的 $$key 是空值；請刪除那一行再執行 make env（不會覆寫既有的值）"; exit 1; \
		fi; \
		if ! grep -Eq "$(ENV_LINE)$$key[[:space:]]*=" .env; then \
			secret=$$(openssl rand -hex 24) || exit 1; \
			[ "$${#secret}" -eq 48 ] || { echo "錯誤：openssl 沒有產生有效的隨機值"; exit 1; }; \
			if [ -s .env ] && [ -n "$$(tail -c1 .env)" ]; then echo >> .env; fi; \
			echo "$$key=$$secret" >> .env; \
			echo "已在 .env 產生 $$key（隨機值，只供本機使用）"; \
		fi; \
	done
	@if grep -Eq "$(ENV_LINE)$(ENCRYPTION_KEYS_VAR)[[:space:]]*=[[:space:]]*$$" .env; then \
		echo "錯誤：.env 的 $(ENCRYPTION_KEYS_VAR) 是空值；請刪除那一行再執行 make env（不會覆寫既有的值）"; exit 1; \
	fi
	@if ! grep -Eq "$(ENV_LINE)$(ENCRYPTION_KEYS_VAR)[[:space:]]*=" .env; then \
		key=$$(openssl rand -base64 32 | tr '+/' '-_') || exit 1; \
		[ "$${#key}" -eq 44 ] || { echo "錯誤：openssl 沒有產生有效的金鑰"; exit 1; }; \
		if [ -s .env ] && [ -n "$$(tail -c1 .env)" ]; then echo >> .env; fi; \
		echo "$(ENCRYPTION_KEYS_VAR)=$$key" >> .env; \
		echo "已在 .env 產生 $(ENCRYPTION_KEYS_VAR)（加密目標 secret 的金鑰；遺失後已保存的 secret 都解不開，請備份這一行）"; \
	fi

docker-check:
	@docker version >/dev/null 2>&1 || { echo "Docker daemon 未執行，請先啟動 OrbStack（orb start）"; exit 1; }

# 開發用 PostgreSQL（只綁 127.0.0.1，預設 port 55432）。
db-up: env docker-check
	$(COMPOSE) -f $(DB_FILE) up -d --wait db

# 整合測試用 PostgreSQL（tmpfs，只綁 127.0.0.1，預設 port 55433）。
test-db-up: env docker-check
	$(COMPOSE) -f $(DB_FILE) --profile test up -d --wait db-test

# 停止 db 與 db-test；開發資料保存在 volume，不會刪除。
db-down:
	$(COMPOSE) -f $(DB_FILE) --profile test down

# 把開發資料庫升級到最新 schema（Alembic upgrade head）；不做任何破壞性重置。
# 最後印出目前版本（例如 0001 (head)），確認實際升級到哪裡。
migrate:
	$(UV_RUN) alembic upgrade head
	@$(UV_RUN) alembic current

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

# 建立 secscan 的應用程式映像（api、runner、worker 共用）與 egress guard 的映像。
build: docker-check
	$(COMPOSE) -f $(DB_FILE) --profile app build api guard

# 以 digest pull 核准的掃描器映像與 socket-proxy（runner 本身不 pull）。
images: docker-check
	@for image in $(SCANNER_IMAGES); do docker pull --quiet "$$image" >/dev/null || exit 1; done
	$(COMPOSE) -f $(DB_FILE) --profile app pull --quiet socket-proxy

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

# 啟動 app stack（db、api、runner、worker、socket-proxy、guard）。API 只綁 127.0.0.1:$${API_PORT:-8000}。
# 第一次使用先執行 make migrate（db 的 schema）與 create-admin-key。
up: env docker-check scan-net lab-net images build
	$(COMPOSE) -f $(DB_FILE) --profile app up -d --wait

# 停止 app stack 與 db（資料保留在 volume）。
down:
	$(COMPOSE) -f $(DB_FILE) --profile app down

# live 測試：真的 Docker、socket-proxy、egress guard 與 fake 容器；guard 的測試在 live 自己的 lab 網路
# 上啟動接收端（不啟動 Juice Shop、VAmPI）。需要自己設定 ENABLE_LIVE_LAB_TESTS=1；在獨立的 compose
# 專案建立、測試、一律拆除：先刪掉接在這兩個網路上的容器（測試的接收端、探針與孤兒的掃描容器，
# 否則 volume 還在使用中刪不掉），再刪 compose 的服務、volume 與網路。
# 會中斷 stack 的測試（停掉 guard、kill runner）放在最後執行。
LIVE_TESTS := tests/live/test_runner_live.py tests/live/test_guard_live.py \
	tests/live/test_budget_live.py tests/live/test_revocation_live.py \
	tests/live/test_guard_failover_live.py
test-live-runner: env docker-check images build
	@[ "$$ENABLE_LIVE_LAB_TESTS" = 1 ] || { echo "需要設定 ENABLE_LIVE_LAB_TESTS=1"; exit 1; }
	@$(MAKE) --no-print-directory scan-net SCAN_NET=$(LIVE_SCAN_NET) SCAN_SUBNET=$(LIVE_SCAN_SUBNET) \
		SCAN_IP_RANGE=$(LIVE_SCAN_IP_RANGE)
	@$(MAKE) --no-print-directory lab-net LAB_NET=$(LIVE_LAB_NET) LAB_SUBNET=$(LIVE_LAB_SUBNET) \
		LAB_IP_RANGE=$(LIVE_LAB_IP_RANGE)
	@status=0; \
		$(LIVE_COMPOSE) up -d --wait db \
		&& DB_PORT=55434 $(UV_RUN) alembic upgrade head >/dev/null \
		&& $(LIVE_COMPOSE) up -d --wait \
		&& SECSCAN_LIVE_PROJECT=$(LIVE_PROJECT) $(LIVE_PYTEST_ENV) $(UV_RUN) pytest -m live \
			-p no:cacheprovider $(LIVE_TESTS) \
		|| status=$$?; \
		for net in $(LIVE_SCAN_NET) $(LIVE_LAB_NET); do \
			ids=$$(docker ps -aq --filter "network=$$net"); \
			[ -z "$$ids" ] || docker rm -f $$ids >/dev/null; \
		done; \
		$(LIVE_COMPOSE) down -v --remove-orphans; \
		docker network rm $(LIVE_SCAN_NET) $(LIVE_LAB_NET) >/dev/null 2>&1; \
		exit $$status

# ZAP 的 live 測試（docs/DECISIONS.md §18.10、§19）：同一個獨立的 secscan-live 專案與流程。runner
# 啟動時以真的 ZAP 映像執行 capability probe；掃描的是 live 自己 lab 網路上的小型網站
# （tests/live/zap_site.py），不啟動 Juice Shop、VAmPI。
test-live-zap: LIVE_TESTS := tests/live/test_zap_live.py
test-live-zap: test-live-runner

# 錄製 ZAP 的真實輸出（docs/DECISIONS.md §19.9）：同一個 live 流程，只執行錄製的情境（anonymous），
# 輸出到 recordings/zap/<情境>/（gitignore）。人工審查之後才搬進 tests/fixtures/zap/。約 15 分鐘。
record-fixtures: LIVE_TESTS := tests/live/test_zap_record_live.py
record-fixtures: LIVE_PYTEST_ENV := SECSCAN_RECORD_DIR=$(CURDIR)/recordings/zap
record-fixtures: test-live-runner
