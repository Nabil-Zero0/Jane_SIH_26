import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

def validate_select_query(sql: str) -> tuple[bool, Optional[str]]:
    """Validate that query is a single, clean SELECT statement."""
    cleaned = sql.strip()
    if not cleaned:
        return False, "Query cannot be empty"

    # Reject multi-statements
    # Remove trailing semicolon
    no_trailing = re.sub(r";\s*$", "", cleaned)
    if ";" in no_trailing:
        return False, "Multiple SQL statements are not permitted"

    # Reject forbidden DDL/DML keywords as whole words
    forbidden = [
        "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
        "ATTACH", "DETACH", "PRAGMA", "VACUUM", "REINDEX", "REPLACE",
        "TRUNCATE", "GRANT", "REVOKE"
    ]
    pattern = r"\b(" + "|".join(forbidden) + r")\b"
    match = re.search(pattern, cleaned, re.IGNORECASE)
    if match:
        return False, f"Forbidden SQL operation: '{match.group(1).upper()}' is not allowed in read-only mode"

    # Must start with SELECT or WITH
    first_word = cleaned.split()[0].upper()
    if first_word not in ("SELECT", "WITH", "EXPLAIN"):
        return False, f"Only SELECT queries are allowed (found '{first_word}')"

    return True, None


def inject_default_limit(sql: str, default_limit: int = 500) -> str:
    """Inject default LIMIT clause if query does not already specify one."""
    cleaned = sql.strip().rstrip(";")
    if not re.search(r"\bLIMIT\s+\d+", cleaned, re.IGNORECASE):
        return f"{cleaned} LIMIT {default_limit};"
    return f"{cleaned};"


def execute_query_readonly(
    db_path: Path,
    sql: str,
    session_id: Optional[str] = None,
    question: Optional[str] = None,
    default_limit: int = 500,
) -> Dict[str, Any]:
    """Execute SQL query against SQLite database in enforced read-only mode."""
    start_time = time.perf_counter()
    now_iso = datetime.now(timezone.utc).isoformat()
    query_id = f"qry_{uuid.uuid4().hex[:12]}"
    
    # 1. Validation check
    is_valid, error_msg = validate_select_query(sql)
    if not is_valid:
        latency = (time.perf_counter() - start_time) * 1000.0
        # Log rejected query
        _log_query(db_path, query_id, session_id, question, sql, executed=False, row_count=0, error_message=error_msg, ran_at=now_iso)
        return {
            "success": False,
            "query_id": query_id,
            "sql": sql,
            "columns": [],
            "rows": [],
            "row_count": 0,
            "latency_ms": round(latency, 2),
            "error": error_msg,
        }

    # 2. Inject LIMIT if missing
    final_sql = inject_default_limit(sql, default_limit)

    # 3. Execute via URI mode=ro
    ro_uri = f"file:{db_path.as_posix()}?mode=ro"
    try:
        ro_conn = sqlite3.connect(ro_uri, uri=True, timeout=10.0)
        ro_cur = ro_conn.cursor()
        ro_cur.execute(final_sql)
        
        columns = [d[0] for d in ro_cur.description] if ro_cur.description else []
        rows = ro_cur.fetchall()
        row_count = len(rows)
        latency = (time.perf_counter() - start_time) * 1000.0
        ro_conn.close()

        # Log successful query
        _log_query(db_path, query_id, session_id, question, final_sql, executed=True, row_count=row_count, error_message=None, ran_at=now_iso)

        return {
            "success": True,
            "query_id": query_id,
            "sql": final_sql,
            "columns": columns,
            "rows": rows,
            "row_count": row_count,
            "latency_ms": round(latency, 2),
            "error": None,
        }
    except Exception as exc:
        latency = (time.perf_counter() - start_time) * 1000.0
        err = str(exc)
        # Log error query
        _log_query(db_path, query_id, session_id, question, final_sql, executed=False, row_count=0, error_message=err, ran_at=now_iso)
        return {
            "success": False,
            "query_id": query_id,
            "sql": final_sql,
            "columns": [],
            "rows": [],
            "row_count": 0,
            "latency_ms": round(latency, 2),
            "error": err,
        }


def _log_query(
    db_path: Path,
    query_id: str,
    session_id: Optional[str],
    question: Optional[str],
    sql: str,
    executed: bool,
    row_count: int,
    error_message: Optional[str],
    ran_at: str,
) -> None:
    """Log query execution or rejection to query_log table using a writable connection."""
    try:
        # Create session if none
        conn = sqlite3.connect(db_path)
        with conn:
            if session_id:
                # Ensure session exists
                s_row = conn.execute("SELECT id FROM query_sessions WHERE id = ?", (session_id,)).fetchone()
                if not s_row:
                    conn.execute("INSERT INTO query_sessions (id, label, created_at) VALUES (?, ?, ?)", (session_id, "Default Session", ran_at))
            else:
                session_id = "default_session"
                conn.execute("INSERT OR IGNORE INTO query_sessions (id, label, created_at) VALUES (?, ?, ?)", (session_id, "General Queries", ran_at))

            conn.execute(
                """
                INSERT INTO query_log (id, session_id, natural_language_question, generated_sql, executed, row_count, error_message, ran_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (query_id, session_id, question, sql, 1 if executed else 0, row_count, error_message, ran_at)
            )
        conn.close()
    except Exception as log_err:
        print(f"Warning: Failed to log to query_log: {log_err}")

# Test on test_migration_jane.db
db_file = Path(r'c:\Users\thang\Downloads\Jane_SIH_26\jane\data\test_migration_jane.db')

# Test 1: Valid SELECT
res1 = execute_query_readonly(db_file, "SELECT * FROM v_actor_summary")
print("Test 1 (SELECT):", res1["success"], "| Rows:", res1["row_count"], "| SQL:", res1["sql"])

# Test 2: Multi-statement attack
res2 = execute_query_readonly(db_file, "SELECT 1; DROP TABLE actors;")
print("Test 2 (Multi-statement):", res2["success"], "| Error:", res2["error"])

# Test 3: Write statement
res3 = execute_query_readonly(db_file, "INSERT INTO actors (id) VALUES ('fail')")
print("Test 3 (INSERT):", res3["success"], "| Error:", res3["error"])

# Check query_log
conn = sqlite3.connect(db_file)
cur = conn.cursor()
cur.execute("SELECT id, executed, row_count, error_message, generated_sql FROM query_log")
print("\nquery_log entries:")
for r in cur.fetchall():
    print(" ", r)
