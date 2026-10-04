#!/usr/bin/env python3
"""
db/cleanup_contamination.py — Guarded database cleanup script.

Identifies and removes test and development contamination from data/jane.db:
1. Threat actors with designated_id = 'TA-TEST-01' and their dependent rows.
2. Investigations with query in ('weapon sales', 'sanctions hunt test') that are
   PENDING and have zero onion_pages, plus dependent graph/identifier rows.
3. Seed rows from migrate_initial.py (reported separately, ONLY deleted if --include-seed).

Safety Guardrails:
- Default mode is --dry-run (NEVER deletes anything without --apply).
- Refuses to run unless a valid backup exists in data/backups/jane_*.db.
- Prints exact row counts and sample rows before modifying anything.
- Executes all deletions in a single SQLite transaction.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import Any, Dict, List, Set, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = REPO_ROOT / "data" / "jane.db"
DEFAULT_BACKUP_DIR = REPO_ROOT / "data" / "backups"


def check_backup_exists(backup_dir: Path) -> Tuple[bool, str]:
    """Check that at least one non-empty sqlite backup file exists."""
    if not backup_dir.exists():
        return False, f"Backup directory '{backup_dir}' does not exist."
    backups = sorted(backup_dir.glob("jane_*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not backups:
        return False, f"No backup files matching 'jane_*.db' found in '{backup_dir}'."
    latest = backups[0]
    if latest.stat().st_size < 1000:
        return False, f"Latest backup '{latest.name}' is too small ({latest.stat().st_size} bytes)."
    return True, str(latest)


def format_rows(rows: List[sqlite3.Row], limit: int = 5) -> str:
    """Format sample rows as readable JSON strings."""
    if not rows:
        return "  (None)"
    sample = [dict(r) for r in rows[:limit]]
    lines = []
    for idx, item in enumerate(sample, 1):
        lines.append(f"  [{idx}] {json.dumps(item, default=str)}")
    if len(rows) > limit:
        lines.append(f"  ... and {len(rows) - limit} more rows")
    return "\n".join(lines)


def get_table_counts(conn: sqlite3.Connection) -> Dict[str, int]:
    """Return row counts for major database tables."""
    tables = [
        "investigations",
        "onion_pages",
        "threat_actors",
        "identifiers",
        "graph_nodes",
        "graph_edges",
        "graph_node_investigations",
        "graph_edge_investigations",
    ]
    counts = {}
    for tbl in tables:
        try:
            val = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
            counts[tbl] = val
        except Exception:
            counts[tbl] = -1
    return counts


def run_cleanup(
    db_path: Path,
    dry_run: bool = True,
    include_seed: bool = False,
    include_fallbacks: bool = False,
    backup_dir: Path = DEFAULT_BACKUP_DIR,
) -> int:
    print("=" * 72)
    print("JANE DATABASE CONTAMINATION CLEANUP")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"Database:  {db_path.resolve()}")
    print(f"Mode:      {'DRY RUN (no changes will be written)' if dry_run else 'APPLY (modifications active)'}")
    print(f"Seed Data: {'INCLUDE in cleanup' if include_seed else 'EXCLUDE (preserved)'}")
    print(f"Fallbacks: {'INCLUDE in cleanup (lead_vendor, carding, wire: transfer fallbacks)' if include_fallbacks else 'EXCLUDE (TA-TEST-01 only)'}")
    print("=" * 72)

    # 1. Guard: Check backup exists
    has_backup, backup_info = check_backup_exists(backup_dir)
    if not has_backup:
        print(f"\n[ERROR] Safety guard failure: {backup_info}")
        print("A backup of the database is MANDATORY before running cleanup.")
        print(f"Please copy {db_path.name} to data/backups/jane_<timestamp>.db first.\n")
        return 1

    print(f"\n[+] Verified backup present: {backup_info}")

    if not db_path.exists():
        print(f"\n[ERROR] Target database '{db_path}' does not exist.")
        return 1

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    initial_counts = get_table_counts(conn)
    print("\n--- Current Database Counts ---")
    for tbl, cnt in initial_counts.items():
        print(f"  {tbl:26}: {cnt}")

    # 2. Identify Contamination
    # 2a. Test Actors (TA-TEST-01) and optional fabricated fallbacks
    if include_fallbacks:
        test_actors = conn.execute("""
            SELECT id, investigation_id, designated_id, primary_handle, created_at 
            FROM threat_actors 
            WHERE designated_id = 'TA-TEST-01'
               OR primary_handle = 'lead_vendor'
               OR designated_id = 'TA-ALPHA'
               OR (primary_handle = 'wire: transfer' AND designated_id != 'TA-ORION-ALPHA')
               OR primary_handle = 'carding'
               OR designated_id LIKE 'TA-SUSPECT-%'
        """).fetchall()
    else:
        test_actors = conn.execute(
            "SELECT id, investigation_id, designated_id, primary_handle, created_at FROM threat_actors WHERE designated_id = 'TA-TEST-01'"
        ).fetchall()
    test_actor_ids = [r["id"] for r in test_actors]

    # 2b. Contaminated investigations (test runs without pages)
    test_invs = conn.execute("""
        SELECT id, query, status, page_count, created_at 
        FROM investigations 
        WHERE query IN ('weapon sales', 'sanctions hunt test')
          AND status = 'PENDING'
          AND id NOT IN (SELECT DISTINCT investigation_id FROM onion_pages WHERE investigation_id IS NOT NULL)
    """).fetchall()
    test_inv_ids = [r["id"] for r in test_invs]

    # Investigations to delete: ONLY zero-page test investigations
    all_target_inv_ids = test_inv_ids

    # 2c. Dependent rows
    # Identifiers linked to test actors OR test investigations
    placeholders_act = ",".join("?" for _ in test_actor_ids) if test_actor_ids else "''"
    placeholders_inv = ",".join("?" for _ in all_target_inv_ids) if all_target_inv_ids else "''"

    query_idents = f"""
        SELECT id, investigation_id, actor_id, type, value, evidence_quote 
        FROM identifiers 
        WHERE (actor_id IN ({placeholders_act}))
           OR (investigation_id IN ({placeholders_inv}))
    """
    params_idents = list(test_actor_ids) + list(all_target_inv_ids)
    test_idents = conn.execute(query_idents, params_idents).fetchall()
    test_ident_ids = [r["id"] for r in test_idents]

    # Graph elements linked to target investigations
    query_nodes = f"SELECT id, investigation_id, label, node_type FROM graph_nodes WHERE investigation_id IN ({placeholders_inv})"
    test_nodes = conn.execute(query_nodes, all_target_inv_ids).fetchall() if all_target_inv_ids else []
    test_node_ids = [r["id"] for r in test_nodes]

    query_edges = f"SELECT id, investigation_id, source, target, edge_type FROM graph_edges WHERE investigation_id IN ({placeholders_inv})"
    test_edges = conn.execute(query_edges, all_target_inv_ids).fetchall() if all_target_inv_ids else []
    test_edge_ids = [r["id"] for r in test_edges]

    query_gni = f"SELECT node_id, investigation_id FROM graph_node_investigations WHERE investigation_id IN ({placeholders_inv})"
    test_gni = conn.execute(query_gni, all_target_inv_ids).fetchall() if all_target_inv_ids else []

    query_gei = f"SELECT edge_id, investigation_id FROM graph_edge_investigations WHERE investigation_id IN ({placeholders_inv})"
    test_gei = conn.execute(query_gei, all_target_inv_ids).fetchall() if all_target_inv_ids else []

    # 2d. Seed Data from migrate_initial.py (Reported separately)
    seed_actors = conn.execute(
        "SELECT id, investigation_id, designated_id, primary_handle FROM threat_actors WHERE designated_id = 'TA-ORION-ALPHA' OR primary_handle = 'wire: transfer'"
    ).fetchall()
    seed_invs = conn.execute(
        "SELECT id, query, status, created_at FROM investigations WHERE id = 'inv_seed_demo' OR query = 'Hydra Market vendor identity'"
    ).fetchall()
    seed_actor_ids = [r["id"] for r in seed_actors]
    seed_inv_ids = [r["id"] for r in seed_invs]

    print("\n" + "=" * 72)
    print("CONTAMINATION AUDIT FINDINGS")
    print("=" * 72)

    print(f"\n1. Test Actors (designated_id = 'TA-TEST-01'): {len(test_actors)} rows")
    print(format_rows(test_actors))

    print(f"\n2. Test Investigations ('weapon sales' / 'sanctions hunt test' PENDING, 0 pages): {len(test_invs)} rows")
    print(format_rows(test_invs))

    print(f"\n3. Dependent Identifiers (linked to test actors or test investigations): {len(test_idents)} rows")
    print(format_rows(test_idents))

    print(f"\n4. Dependent Graph Nodes: {len(test_nodes)} rows")
    print(format_rows(test_nodes))

    print(f"\n5. Dependent Graph Edges: {len(test_edges)} rows")
    print(format_rows(test_edges))

    print(f"\n6. Dependent Graph Node Investigation Links: {len(test_gni)} rows")
    print(f"7. Dependent Graph Edge Investigation Links: {len(test_gei)} rows")

    print("\n" + "-" * 72)
    print("SEED DATA REPORT (migrate_initial.py rows - preserved by default)")
    print("-" * 72)
    print(f"Seed Actors (TA-ORION-ALPHA / 'wire: transfer'): {len(seed_actors)} rows")
    print(format_rows(seed_actors))
    print(f"Seed Investigations ('inv_seed_demo'): {len(seed_invs)} rows")
    print(format_rows(seed_invs))
    if not include_seed:
        print(">> NOTE: Seed rows will NOT be deleted. (Pass --include-seed to delete them).")
    else:
        print(">> ATTENTION: --include-seed flag active. Seed rows WILL be deleted.")

    # 3. Execution / Dry Run Report
    total_deletions = (
        len(test_actors)
        + len(test_invs)
        + len(test_idents)
        + len(test_nodes)
        + len(test_edges)
        + len(test_gni)
        + len(test_gei)
    )
    if include_seed:
        total_deletions += len(seed_actors) + len(seed_invs)

    print("\n" + "=" * 72)
    print("PLANNED DELETION SUMMARY")
    print("=" * 72)
    print(f"  threat_actors:             {len(test_actors) + (len(seed_actors) if include_seed else 0)}")
    print(f"  investigations:            {len(test_invs) + (len(seed_invs) if include_seed else 0)}")
    print(f"  identifiers:               {len(test_idents)}")
    print(f"  graph_nodes:               {len(test_nodes)}")
    print(f"  graph_edges:               {len(test_edges)}")
    print(f"  graph_node_investigations: {len(test_gni)}")
    print(f"  graph_edge_investigations: {len(test_gei)}")
    print(f"  TOTAL ROWS TO DELETE:      {total_deletions}")

    if dry_run:
        print("\n[DRY RUN COMPLETE] Zero modifications made to the database.")
        print("To apply these changes, re-run with: python db/cleanup_contamination.py --apply")
        conn.close()
        return 0

    # 4. Single-Transaction Deletion with --apply
    print("\n[APPLYING CLEANUP IN A SINGLE TRANSACTION...]")
    try:
        with conn:
            # Delete dependent graph links
            if test_gei:
                conn.execute(f"DELETE FROM graph_edge_investigations WHERE investigation_id IN ({placeholders_inv})", all_target_inv_ids)
            if test_gni:
                conn.execute(f"DELETE FROM graph_node_investigations WHERE investigation_id IN ({placeholders_inv})", all_target_inv_ids)

            # Delete graph edges and nodes
            if test_edge_ids:
                conn.execute(f"DELETE FROM graph_edges WHERE investigation_id IN ({placeholders_inv})", all_target_inv_ids)
            if test_node_ids:
                conn.execute(f"DELETE FROM graph_nodes WHERE investigation_id IN ({placeholders_inv})", all_target_inv_ids)

            # Delete identifiers
            if test_ident_ids:
                conn.execute(query_idents.replace("SELECT id, investigation_id, actor_id, type, value, evidence_quote", "DELETE"), params_idents)

            # Delete threat actors
            if test_actor_ids:
                ph_tact = ",".join("?" for _ in test_actor_ids)
                conn.execute(f"DELETE FROM threat_actors WHERE id IN ({ph_tact})", test_actor_ids)

            # Delete investigations
            if test_inv_ids:
                ph_tinv = ",".join("?" for _ in test_inv_ids)
                conn.execute(f"DELETE FROM investigations WHERE id IN ({ph_tinv})", test_inv_ids)

            # Optional: Delete seed rows
            if include_seed:
                if seed_actor_ids:
                    conn.execute("DELETE FROM threat_actors WHERE designated_id = 'TA-ORION-ALPHA'")
                if seed_inv_ids:
                    conn.execute("DELETE FROM investigations WHERE id = 'inv_seed_demo'")

        print("[+] Transaction committed successfully.")
    except Exception as exc:
        print(f"[ERROR] Transaction rolled back due to error: {exc}")
        conn.close()
        return 1

    post_counts = get_table_counts(conn)
    print("\n--- Post-Cleanup Database Counts ---")
    for tbl, cnt in post_counts.items():
        diff = cnt - initial_counts.get(tbl, 0)
        print(f"  {tbl:26}: {cnt:5d} ({diff:+d})")

    conn.close()
    return 0


def main():
    parser = argparse.ArgumentParser(description="Jane Database Contamination Cleanup Tool")
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH, help="Path to sqlite database file")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Dry run only (default: True)")
    parser.add_argument("--apply", action="store_true", help="Apply deletions (disables dry-run)")
    parser.add_argument("--include-seed", action="store_true", help="Also delete demo seed rows from migrate_initial.py")
    parser.add_argument("--include-fallbacks", action="store_true", help="Also delete fabricated fallbacks (lead_vendor, carding, wire: transfer fallbacks)")
    parser.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR, help="Path to backups directory")

    args = parser.parse_args()
    is_dry_run = not args.apply

    exit_code = run_cleanup(
        db_path=args.db_path,
        dry_run=is_dry_run,
        include_seed=args.include_seed,
        include_fallbacks=args.include_fallbacks,
        backup_dir=args.backup_dir,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
