-- T23b-b2 G0b candidate (plan §2.5, D18, D19): the two role passwords are read from files mounted
-- by compose secrets. Only the *_FILE paths come from the environment; the passwords never do.
-- psql errors are terse and show no statement text or context.
\set VERBOSITY terse
\set SHOW_CONTEXT never
\getenv owner_user SECSCAN_OWNER_DB_USER
\getenv app_user SECSCAN_APP_DB_USER
\getenv app_db SECSCAN_APP_DB_NAME
\getenv owner_file SECSCAN_OWNER_DB_PASSWORD_FILE
\getenv app_file SECSCAN_APP_DB_PASSWORD_FILE

\if :{?owner_user}
\else
DO $$ BEGIN RAISE EXCEPTION 'secscan initdb: SECSCAN_OWNER_DB_USER is not set'; END $$;
\endif
\if :{?app_user}
\else
DO $$ BEGIN RAISE EXCEPTION 'secscan initdb: SECSCAN_APP_DB_USER is not set'; END $$;
\endif
\if :{?app_db}
\else
DO $$ BEGIN RAISE EXCEPTION 'secscan initdb: SECSCAN_APP_DB_NAME is not set'; END $$;
\endif
\if :{?owner_file}
\else
DO $$ BEGIN RAISE EXCEPTION 'secscan initdb: SECSCAN_OWNER_DB_PASSWORD_FILE is not set'; END $$;
\endif
\if :{?app_file}
\else
DO $$ BEGIN RAISE EXCEPTION 'secscan initdb: SECSCAN_APP_DB_PASSWORD_FILE is not set'; END $$;
\endif

-- Client-side check before reading: a regular file (not a symlink) holding exactly one line of
-- 32-4095 printable ASCII characters (no CR, no second line). The shell command only ever sees
-- the path variables, never a password variable.
\set owner_file_ok `if [ -f :'owner_file' ] && [ ! -L :'owner_file' ]; then LC_ALL=C awk 'NR == 1 && length($0) >= 32 && length($0) <= 4095 && $0 ~ /^[!-~]+$/ { ok = 1 } END { if (NR == 1 && ok) print "true"; else print "false" }' :'owner_file'; else echo false; fi`
-- SHELL_ERROR exists only in psql 16 and later; without it a failed cat would go unnoticed.
\if :{?SHELL_ERROR}
\else
DO $$ BEGIN RAISE EXCEPTION 'secscan initdb: psql 16 or later is required'; END $$;
\endif
\if :owner_file_ok
\else
DO $$ BEGIN RAISE EXCEPTION 'secscan initdb: the owner password file must be one line of 32-4095 printable ASCII characters'; END $$;
\endif
\set app_file_ok `if [ -f :'app_file' ] && [ ! -L :'app_file' ]; then LC_ALL=C awk 'NR == 1 && length($0) >= 32 && length($0) <= 4095 && $0 ~ /^[!-~]+$/ { ok = 1 } END { if (NR == 1 && ok) print "true"; else print "false" }' :'app_file'; else echo false; fi`
\if :app_file_ok
\else
DO $$ BEGIN RAISE EXCEPTION 'secscan initdb: the app password file must be one line of 32-4095 printable ASCII characters'; END $$;
\endif

-- A failed cat only yields an empty string, which ON_ERROR_STOP cannot catch: check SHELL_ERROR.
\set owner_password `cat :'owner_file'`
\if :SHELL_ERROR
DO $$ BEGIN RAISE EXCEPTION 'secscan initdb: cannot read the owner password file'; END $$;
\endif
\set app_password `cat :'app_file'`
\if :SHELL_ERROR
DO $$ BEGIN RAISE EXCEPTION 'secscan initdb: cannot read the app password file'; END $$;
\endif

-- The two CREATE ROLE statements carry the passwords. Nothing in this session may log statement
-- text or parse trees while they run, whatever the server configuration says (D19). Error
-- messages themselves are still logged; only the statement text is not.
SET log_statement = 'none';
SET log_min_duration_statement = -1;
SET log_min_duration_sample = -1;
SET log_transaction_sample_rate = 0;
SET log_min_error_statement = panic;
SET debug_print_parse = off;
SET debug_print_rewritten = off;
SET debug_print_plan = off;
SET password_encryption = 'scram-sha-256';
CREATE ROLE :"owner_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'owner_password';
CREATE ROLE :"app_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'app_password';
RESET password_encryption;
RESET debug_print_plan;
RESET debug_print_rewritten;
RESET debug_print_parse;
RESET log_min_error_statement;
RESET log_transaction_sample_rate;
RESET log_min_duration_sample;
RESET log_min_duration_statement;
RESET log_statement;
\unset owner_password
\unset app_password
CREATE DATABASE :"app_db" OWNER :"owner_user";

REVOKE ALL ON DATABASE :"app_db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"app_db" TO :"app_user";
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
