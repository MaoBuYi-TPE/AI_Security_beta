-- 開發用 db 的初始化（docker-entrypoint-initdb.d，只在第一次建立資料目錄時執行）。
-- 兩個非 superuser 的角色（T23b-b1；docs/DECISIONS.md §31）：
-- - owner：擁有資料庫與所有物件，只用於 migration（make migrate；api、worker、runner 沒有它的密碼）。
-- - 應用程式角色：api、worker、runner 與主機的 admin CLI 共用；只有 v0025 授予的逐表 DML。
-- 都不是 superuser，避免一旦遭 SQL 注入就能用 COPY ... PROGRAM、讀取伺服器檔案或建立角色。
-- 秘密從容器環境變數讀取（psql \getenv），不會出現在命令列或這個檔案裡。
-- 已經存在的資料目錄不會重跑這個檔案：既有的開發 DB 以 make db-roles-migrate 移轉（README）。
\getenv owner_user SECSCAN_OWNER_DB_USER
\getenv owner_password SECSCAN_OWNER_DB_PASSWORD
\getenv app_user SECSCAN_APP_DB_USER
\getenv app_password SECSCAN_APP_DB_PASSWORD
\getenv app_db SECSCAN_APP_DB_NAME

-- CREATE ROLE 失敗時（例如角色已存在），預設會把整句（含密碼）寫進伺服器日誌；只對這個 session 關閉。
SET log_min_error_statement = panic;
CREATE ROLE :"owner_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'owner_password';
CREATE ROLE :"app_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'app_password';
RESET log_min_error_statement;
CREATE DATABASE :"app_db" OWNER :"owner_user";

-- 新資料庫預設允許 PUBLIC 連線與建立暫存表；只留給擁有者。應用程式角色只能連線（migration 之前
-- readiness 才能回報「schema 不是目前版本」）；資料表的權限由 v0025 授予。
REVOKE ALL ON DATABASE :"app_db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"app_db" TO :"app_user";
-- 兩個角色都不需要連到維運用的資料庫（superuser 不受影響）。
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
