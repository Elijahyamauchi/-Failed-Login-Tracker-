"""
db.py
Database initialization and schema for the Failed Login Tracker.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path("login_events.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS login_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            hostname    TEXT,
            username    TEXT NOT NULL,
            source_ip   TEXT NOT NULL,
            port        INTEGER,
            status      TEXT NOT NULL CHECK(status IN ('failed', 'accepted')),
            ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_source_ip   ON login_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_username    ON login_events(username);
        CREATE INDEX IF NOT EXISTS idx_status      ON login_events(status);
        CREATE INDEX IF NOT EXISTS idx_timestamp   ON login_events(timestamp);

        CREATE TABLE IF NOT EXISTS alerts (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type     TEXT NOT NULL,
            source_ip      TEXT,
            username       TEXT,
            event_count    INTEGER,
            window_minutes INTEGER,
            first_seen     TEXT,
            last_seen      TEXT,
            created_at     TEXT NOT NULL DEFAULT (datetime('now'))
        );
    """)

    conn.commit()
    conn.close()
    print("[+] Database initialized.")
