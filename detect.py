"""
detect.py
Detection rules for brute-force and suspicious login patterns.
All detection logic runs as SQL queries against the login_events table.
"""

from db import get_connection

# ── Thresholds (tune as needed) ──────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD  = 10   # failed attempts from one IP within the window
BRUTE_FORCE_WINDOW_MIN = 10   # minutes
USER_SPRAY_THRESHOLD   = 5    # distinct usernames targeted by one IP
DISTRIBUTED_THRESHOLD  = 3    # distinct IPs failing against same user


def detect_brute_force() -> list[dict]:
    """
    Rule: Single IP exceeds BRUTE_FORCE_THRESHOLD failed logins
    within BRUTE_FORCE_WINDOW_MIN minutes.

    SQLite doesn't have native interval arithmetic on ISO strings,
    so we use a self-join with strftime to bucket events into 10-min windows.
    """
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        SELECT
            source_ip,
            COUNT(*)                        AS attempt_count,
            MIN(timestamp)                  AS first_seen,
            MAX(timestamp)                  AS last_seen,
            COUNT(DISTINCT username)        AS users_targeted,
            -- 10-minute bucket: floor the minute to nearest 10
            strftime('%Y-%m-%dT%H:', timestamp) ||
                printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) / :window) * :window)
                                            AS time_bucket
        FROM login_events
        WHERE status = 'failed'
        GROUP BY source_ip, time_bucket
        HAVING attempt_count >= :threshold
        ORDER BY attempt_count DESC
    """

    rows = cursor.execute(query, {
        "window":    BRUTE_FORCE_WINDOW_MIN,
        "threshold": BRUTE_FORCE_THRESHOLD,
    }).fetchall()

    conn.close()
    return [dict(r) for r in rows]


def detect_password_spray() -> list[dict]:
    """
    Rule: Single IP targets many distinct usernames — classic password spray.
    """
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        SELECT
            source_ip,
            COUNT(DISTINCT username)    AS unique_users,
            COUNT(*)                    AS total_attempts,
            MIN(timestamp)              AS first_seen,
            MAX(timestamp)              AS last_seen
        FROM login_events
        WHERE status = 'failed'
        GROUP BY source_ip
        HAVING unique_users >= :threshold
        ORDER BY unique_users DESC
    """

    rows = cursor.execute(query, {"threshold": USER_SPRAY_THRESHOLD}).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def detect_distributed_attack() -> list[dict]:
    """
    Rule: Many distinct IPs failing against the same username —
    could indicate a distributed credential stuffing campaign.
    """
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        SELECT
            username,
            COUNT(DISTINCT source_ip)   AS unique_ips,
            COUNT(*)                    AS total_attempts,
            MIN(timestamp)              AS first_seen,
            MAX(timestamp)              AS last_seen
        FROM login_events
        WHERE status = 'failed'
        GROUP BY username
        HAVING unique_ips >= :threshold
        ORDER BY unique_ips DESC
    """

    rows = cursor.execute(query, {"threshold": DISTRIBUTED_THRESHOLD}).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def save_alerts(brute_force: list, spray: list, distributed: list):
    """Persist detected alerts to the alerts table."""
    conn = get_connection()
    cursor = conn.cursor()

    for hit in brute_force:
        cursor.execute("""
            INSERT INTO alerts
                (alert_type, source_ip, event_count, window_minutes, first_seen, last_seen)
            VALUES
                ('BRUTE_FORCE', :source_ip, :attempt_count, :window, :first_seen, :last_seen)
        """, {**hit, "window": BRUTE_FORCE_WINDOW_MIN})

    for hit in spray:
        cursor.execute("""
            INSERT INTO alerts
                (alert_type, source_ip, event_count, window_minutes, first_seen, last_seen)
            VALUES
                ('PASSWORD_SPRAY', :source_ip, :total_attempts, NULL, :first_seen, :last_seen)
        """, hit)

    for hit in distributed:
        cursor.execute("""
            INSERT INTO alerts
                (alert_type, username, event_count, window_minutes, first_seen, last_seen)
            VALUES
                ('DISTRIBUTED_ATTACK', :username, :total_attempts, NULL, :first_seen, :last_seen)
        """, hit)

    conn.commit()
    conn.close()
