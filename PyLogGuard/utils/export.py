"""
CSV export utilities for PyLogGuard.

Usage examples (from project root):
    python -m utils.export logs_export.csv
    python -m utils.export incidents_export.csv --incidents
    # with a custom WHERE and params (advanced):
    python -m utils.export recent_bruteforce.csv --where "l.attack_id=%s AND l.created_at >= NOW() - INTERVAL 1 DAY" --params 2

Functions:
- export_logs_to_csv(filename, where_clause=None, params=())
- export_incidents_to_csv(filename, where_clause=None, params=())
"""

import csv
import sys
import locale
import os
from db.connection import get_connection

EXPORT_DIR = "exports"

def detect_delimiter():
    """Detect proper delimiter based on locale (comma vs semicolon)."""
    loc = locale.getlocale()
    if loc and any(l in str(loc).lower() for l in ["de", "fr", "es", "id", "it", "nl", "pl"]):
        return ";"
    return ","

def ensure_export_path(filename):
    """Ensure filename has .csv extension and is inside EXPORT_DIR."""
    if not filename.endswith(".csv"):
        filename += ".csv"
    os.makedirs(EXPORT_DIR, exist_ok=True)
    return os.path.join(EXPORT_DIR, filename)

def export_table(filename="logs.csv", table="logs", where=None, params=None):
    conn = get_connection()
    cur = conn.cursor()

    query = f"SELECT * FROM {table}"
    if where:
        query += f" WHERE {where}"

    cur.execute(query, params or [])
    rows = cur.fetchall()
    headers = [desc[0] for desc in cur.description]

    delimiter = detect_delimiter()
    filepath = ensure_export_path(filename)

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=delimiter)
        writer.writerow(headers)
        writer.writerows(rows)

    print(f"✅ Exported {len(rows)} rows from {table} to {filepath} (delimiter='{delimiter}')")

    cur.close()
    conn.close()

if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) > 1 else "logs.csv"
    export_table(filename=filename, table="logs")