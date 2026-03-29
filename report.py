"""
report.py
Generates a terminal-friendly summary report from the database.
"""

from db import get_connection


def print_divider(char="─", width=60):
    print(char * width)


def summary_stats() -> dict:
    conn = get_connection()
    cursor = conn.cursor()

    stats = {}

    stats["total_events"] = cursor.execute(
        "SELECT COUNT(*) FROM login_events"
    ).fetchone()[0]

    stats["failed"] = cursor.execute(
        "SELECT COUNT(*) FROM login_events WHERE status = 'failed'"
    ).fetchone()[0]

    stats["accepted"] = cursor.execute(
        "SELECT COUNT(*) FROM login_events WHERE status = 'accepted'"
    ).fetchone()[0]

    stats["unique_ips"] = cursor.execute(
        "SELECT COUNT(DISTINCT source_ip) FROM login_events WHERE status = 'failed'"
    ).fetchone()[0]

    stats["unique_users"] = cursor.execute(
        "SELECT COUNT(DISTINCT username) FROM login_events WHERE status = 'failed'"
    ).fetchone()[0]

    conn.close()
    return stats


def top_offenders(limit: int = 10) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()

    rows = cursor.execute("""
        SELECT
            source_ip,
            COUNT(*)                 AS failed_attempts,
            COUNT(DISTINCT username) AS users_targeted,
            MIN(timestamp)           AS first_seen,
            MAX(timestamp)           AS last_seen
        FROM login_events
        WHERE status = 'failed'
        GROUP BY source_ip
        ORDER BY failed_attempts DESC
        LIMIT :limit
    """, {"limit": limit}).fetchall()

    conn.close()
    return [dict(r) for r in rows]


def top_targeted_users(limit: int = 10) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()

    rows = cursor.execute("""
        SELECT
            username,
            COUNT(*)                 AS failed_attempts,
            COUNT(DISTINCT source_ip) AS attacking_ips
        FROM login_events
        WHERE status = 'failed'
        GROUP BY username
        ORDER BY failed_attempts DESC
        LIMIT :limit
    """, {"limit": limit}).fetchall()

    conn.close()
    return [dict(r) for r in rows]


def recent_alerts(limit: int = 20) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()

    rows = cursor.execute("""
        SELECT alert_type, source_ip, username, event_count,
               window_minutes, first_seen, last_seen, created_at
        FROM alerts
        ORDER BY created_at DESC
        LIMIT :limit
    """, {"limit": limit}).fetchall()

    conn.close()
    return [dict(r) for r in rows]


def print_report():
    print("\n")
    print_divider("═")
    print("  FAILED LOGIN TRACKER  |  SOC Report")
    print_divider("═")

    stats = summary_stats()
    print(f"\n  Total Events    : {stats['total_events']}")
    print(f"  Failed Logins   : {stats['failed']}")
    print(f"  Accepted Logins : {stats['accepted']}")
    print(f"  Unique Attacker IPs : {stats['unique_ips']}")
    print(f"  Unique Targeted Users : {stats['unique_users']}")

    # ── Top Offenders ──
    print("\n")
    print_divider()
    print("  TOP OFFENDING IPs")
    print_divider()
    offenders = top_offenders()
    if offenders:
        print(f"  {'IP':<20} {'Failures':>8}  {'Users Targeted':>14}  First Seen")
        print_divider("·")
        for o in offenders:
            print(f"  {o['source_ip']:<20} {o['failed_attempts']:>8}  {o['users_targeted']:>14}  {o['first_seen']}")
    else:
        print("  No failed login data.")

    # ── Top Targeted Users ──
    print("\n")
    print_divider()
    print("  TOP TARGETED USERNAMES")
    print_divider()
    users = top_targeted_users()
    if users:
        print(f"  {'Username':<20} {'Failures':>8}  {'Attacking IPs':>13}")
        print_divider("·")
        for u in users:
            print(f"  {u['username']:<20} {u['failed_attempts']:>8}  {u['attacking_ips']:>13}")
    else:
        print("  No data.")

    # ── Alerts ──
    print("\n")
    print_divider()
    print("  ACTIVE ALERTS")
    print_divider()
    alerts = recent_alerts()
    if alerts:
        for a in alerts:
            target = a["source_ip"] or a["username"] or "N/A"
            window = f" (within {a['window_minutes']}m)" if a["window_minutes"] else ""
            print(f"  [{a['alert_type']}] {target} — {a['event_count']} events{window}")
            print(f"    First: {a['first_seen']}  |  Last: {a['last_seen']}")
    else:
        print("  No alerts generated.")

    print("\n")
    print_divider("═")
    print()
