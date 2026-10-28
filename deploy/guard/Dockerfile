# egress guard（docs/DECISIONS.md §15.1）：官方 mitmproxy 映像（digest 鎖定）加上我們的 addon。
# mitmproxy 的相依套件和 uv.lock 衝突（§15 的依據），所以不共用 app 的映像：這裡只 COPY guard 載入的
# 模組（標準函式庫與純 domain；tests/unit/guard/test_image.py 核對清單正好等於 import 的封閉集合）。
# 檔案屬於 root、guard 以 10001 執行：執行時改不到自己的程式。
#   make build   建立 secscan-guard:dev

FROM mitmproxy/mitmproxy:12.2.3@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f

COPY deploy/guard/run_guard.py /opt/secscan-guard/run_guard.py
COPY src/secscan/__init__.py /opt/secscan-guard/secscan/__init__.py
COPY src/secscan/core/__init__.py /opt/secscan-guard/secscan/core/__init__.py
COPY src/secscan/core/network.py /opt/secscan-guard/secscan/core/network.py
COPY src/secscan/core/text.py /opt/secscan-guard/secscan/core/text.py
COPY src/secscan/grants/__init__.py /opt/secscan-guard/secscan/grants/__init__.py
COPY src/secscan/grants/domain/__init__.py /opt/secscan-guard/secscan/grants/domain/__init__.py
COPY src/secscan/grants/domain/matching.py /opt/secscan-guard/secscan/grants/domain/matching.py
COPY src/secscan/grants/domain/scope.py /opt/secscan-guard/secscan/grants/domain/scope.py
COPY src/secscan/guard/__init__.py /opt/secscan-guard/secscan/guard/__init__.py
COPY src/secscan/guard/addon.py /opt/secscan-guard/secscan/guard/addon.py
COPY src/secscan/guard/bootstrap.py /opt/secscan-guard/secscan/guard/bootstrap.py
COPY src/secscan/guard/config.py /opt/secscan-guard/secscan/guard/config.py
COPY src/secscan/guard/domain/__init__.py /opt/secscan-guard/secscan/guard/domain/__init__.py
COPY src/secscan/guard/domain/addresses.py /opt/secscan-guard/secscan/guard/domain/addresses.py
COPY src/secscan/guard/domain/credentials.py /opt/secscan-guard/secscan/guard/domain/credentials.py
COPY src/secscan/guard/domain/policy.py /opt/secscan-guard/secscan/guard/domain/policy.py
COPY src/secscan/guard/domain/requests.py /opt/secscan-guard/secscan/guard/domain/requests.py
COPY src/secscan/guard/domain/routes.py /opt/secscan-guard/secscan/guard/domain/routes.py
COPY src/secscan/guard/domain/status.py /opt/secscan-guard/secscan/guard/domain/status.py
COPY src/secscan/guard/domain/strict.py /opt/secscan-guard/secscan/guard/domain/strict.py
COPY src/secscan/guard/events.py /opt/secscan-guard/secscan/guard/events.py
COPY src/secscan/guard/files.py /opt/secscan-guard/secscan/guard/files.py
COPY src/secscan/guard/flows.py /opt/secscan-guard/secscan/guard/flows.py
COPY src/secscan/guard/heartbeat.py /opt/secscan-guard/secscan/guard/heartbeat.py
COPY src/secscan/guard/resolver.py /opt/secscan-guard/secscan/guard/resolver.py
COPY src/secscan/guard/store.py /opt/secscan-guard/secscan/guard/store.py
COPY src/secscan/targets/__init__.py /opt/secscan-guard/secscan/targets/__init__.py
COPY src/secscan/targets/domain.py /opt/secscan-guard/secscan/targets/domain.py

USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["python3", "-I", "-B", "/opt/secscan-guard/run_guard.py"]
