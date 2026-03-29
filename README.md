# Failed Login Tracker

A lightweight SOC tool that parses Linux SSH auth logs, ingests events into a SQLite database, and runs SQL-based detection rules to flag brute-force and credential attack patterns.

Built to demonstrate Python + SQL skills in a security context.

---

## Features

- **Log parsing** — regex-based parser for `/var/log/auth.log` SSH entries
- **SQLite ingestion** — structured storage with indexed schema for fast querying
- **SQL detection rules**:
  - `BRUTE_FORCE` — single IP exceeds N failed logins within a time window
  - `PASSWORD_SPRAY` — single IP targets many distinct usernames
  - `DISTRIBUTED_ATTACK` — many IPs targeting the same username (credential stuffing)
- **Terminal report** — top offending IPs, targeted users, and active alerts
- **Sample log generator** — built-in test data with realistic attack patterns

---

## Quickstart

```bash
# 1. Clone and enter the repo
git clone https://github.com/YOUR_USERNAME/failed-login-tracker.git
cd failed-login-tracker

# 2. No dependencies beyond the standard library — just run it
#    Generate sample logs, ingest, detect, and report in one shot:
python main.py --generate-sample
python main.py --log sample_auth.log
```

### Use with a real log file

```bash
# Point it at your system's auth log (read access required)
python main.py --log /var/log/auth.log
```

### Report only (from existing database)

```bash
python main.py --report-only
```

---

## Project Structure

```
failed_login_tracker/
├── main.py                 # CLI entry point and pipeline orchestration
├── db.py                   # SQLite schema and connection management
├── parser.py               # Regex log parser (auth.log → dicts)
├── ingest.py               # Bulk insert events into DB
├── detect.py               # SQL-based detection rules
├── report.py               # Terminal report generator
└── generate_sample_logs.py # Test data generator
```

---

## Database Schema

### `login_events`

| Column       | Type    | Description                        |
|--------------|---------|------------------------------------|
| id           | INTEGER | Primary key                        |
| timestamp    | TEXT    | ISO-format event time              |
| hostname     | TEXT    | Source hostname from log           |
| username     | TEXT    | Login target username              |
| source_ip    | TEXT    | Attacker/client IP                 |
| port         | INTEGER | Source port                        |
| status       | TEXT    | `failed` or `accepted`             |
| ingested_at  | TEXT    | When this row was inserted         |

### `alerts`

| Column         | Type    | Description                          |
|----------------|---------|--------------------------------------|
| id             | INTEGER | Primary key                          |
| alert_type     | TEXT    | `BRUTE_FORCE`, `PASSWORD_SPRAY`, etc.|
| source_ip      | TEXT    | Offending IP (if applicable)         |
| username       | TEXT    | Targeted user (if applicable)        |
| event_count    | INTEGER | Number of events that triggered rule |
| window_minutes | INTEGER | Detection window used                |
| first_seen     | TEXT    | Earliest event timestamp             |
| last_seen      | TEXT    | Latest event timestamp               |
| created_at     | TEXT    | Alert generation time                |

---

## Detection Thresholds

Tunable in `detect.py`:

```python
BRUTE_FORCE_THRESHOLD  = 10   # failed attempts from one IP within window
BRUTE_FORCE_WINDOW_MIN = 10   # minutes
USER_SPRAY_THRESHOLD   = 5    # distinct usernames from one IP
DISTRIBUTED_THRESHOLD  = 3    # distinct IPs against same username
```

---

## Sample Report Output

```
════════════════════════════════════════════════════════════
  FAILED LOGIN TRACKER  |  SOC Report
════════════════════════════════════════════════════════════

  Total Events        : 200
  Failed Logins       : 163
  Accepted Logins     : 37
  Unique Attacker IPs : 5
  Unique Targeted Users : 7

────────────────────────────────────────────────────────────
  TOP OFFENDING IPs
────────────────────────────────────────────────────────────
  IP                   Failures  Users Targeted  First Seen
  ···········································
  45.33.32.156               61               7  2026-03-25T08:14:03
  185.220.101.42             48               6  2026-03-25T08:15:11
  203.0.113.77               40               5  2026-03-25T09:01:44

────────────────────────────────────────────────────────────
  ACTIVE ALERTS
────────────────────────────────────────────────────────────
  [BRUTE_FORCE] 45.33.32.156 — 18 events (within 10m)
    First: 2026-03-25T08:14:03  |  Last: 2026-03-25T08:23:51
  [PASSWORD_SPRAY] 45.33.32.156 — 61 events
  [DISTRIBUTED_ATTACK] root — 45 events
```

---

## Why This Exists

This project demonstrates:
- **Python** — regex parsing, modular design, CLI with argparse, file I/O
- **SQL** — schema design, indexing, aggregation queries, window-based detection logic
- **Security fundamentals** — brute-force detection, password spray, distributed attacks

Useful as a starting point for more complex SIEM-style tooling or integration with platforms like Wazuh.

---

## Requirements

- Python 3.10+
- No third-party packages — uses only `sqlite3`, `re`, `argparse`, `datetime`, `pathlib`
