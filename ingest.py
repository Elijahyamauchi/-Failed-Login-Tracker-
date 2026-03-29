"""
ingest.py
Inserts parsed login events into the SQLite database.
Skips duplicates based on (timestamp, source_ip, username, status).
"""

import sqlite3
from db import get_connection


def ingest_events(events: list[dict]) -> int:
    """
    Bulk-insert events into login_events table.
    Returns the number of rows actually inserted.
    """
    if not events:
        print("[!] No events to ingest.")
        return 0

    conn = get_connection()
    cursor = conn.cursor()

    inserted = 0
    for ev in events:
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO login_events
                    (timestamp, hostname, username, source_ip, port, status)
                VALUES
                    (:timestamp, :hostname, :username, :source_ip, :port, :status)
            """, ev)
            inserted += cursor.rowcount
        except sqlite3.Error as e:
            print(f"[!] DB error on event {ev}: {e}")

    conn.commit()
    conn.close()
    print(f"[+] Ingested {inserted} new events (of {len(events)} parsed).")
    return inserted
