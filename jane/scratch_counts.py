import sqlite3
import os
import json

db_path = "data/jane.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

cursor = conn.cursor()
tables = [r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

table_counts = {}
for t in tables:
    count = cursor.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
    table_counts[t] = count

print("=== TABLE COUNTS ===")
for t, c in sorted(table_counts.items()):
    print(f"{t}: {c}")

# Check investigation directories and files
inv_dir = "data/investigations"
inv_folders = [f for f in os.listdir(inv_dir) if os.path.isdir(os.path.join(inv_dir, f))] if os.path.exists(inv_dir) else []

file_types = [
    "stylometry/profile.json",
    "locksmith/findings.json",
    "osint/clearnet_summary.json",
    "opencode/attribution_report.json",
    "graph/threat_graph.json",
    "analysis/site_profiles.json",
    "extracted/indicators.json",
    "logs/investigation.log",
    "logs/events.jsonl"
]

file_counts = {ft: 0 for ft in file_types}
for inv in inv_folders:
    for ft in file_types:
        fpath = os.path.join(inv_dir, inv, ft.replace("/", os.sep))
        if os.path.exists(fpath):
            file_counts[ft] += 1

print("\n=== INVESTIGATION FILE COUNTS (Total folders: {}) ===".format(len(inv_folders)))
for ft, c in file_counts.items():
    print(f"{ft}: {c}")
