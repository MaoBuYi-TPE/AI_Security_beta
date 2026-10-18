-- 開發用 db 的初始化（docker-entrypoint-initdb.d，只在第一次建立資料目錄時執行）。
-- 建立非 superuser 的應用程式角色，以及由它擁有的資料庫。應用程式與 migration 都用這個角色，
-- 不使用 superuser，避免一旦遭 SQL 注入就能用 COPY ... PROGRAM、讀取伺服器檔案或建立角色。
-- 秘密從容器環境變數讀取（psql \getenv），不會出現在命令列或這個檔案裡。
\getenv app_user SECSCAN_APP_DB_USER
\getenv app_password SECSCAN_APP_DB_PASSWORD
\getenv app_db SECSCAN_APP_DB_NAME

-- CREATE ROLE 失敗時（例如角色已存在），預設會把整句（含密碼）寫進伺服器日誌；只對這個 session 關閉。
SET log_min_error_statement = panic;
CREATE ROLE :"app_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'app_password';
RESET log_min_error_statement;
CREATE DATABASE :"app_db" OWNER :"app_user";

-- 新資料庫預設允許 PUBLIC 連線與建立暫存表；只留給擁有者。
REVOKE ALL ON DATABASE :"app_db" FROM PUBLIC;
-- 應用程式角色不需要連到維運用的資料庫（superuser 不受影響）。
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
