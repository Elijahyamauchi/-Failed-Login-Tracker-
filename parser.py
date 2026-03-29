"""
parser.py
Parses Linux auth.log / syslog SSH entries into structured dicts.
Handles both 'Failed password' and 'Accepted password' lines.
"""

import re
from datetime import datetime
from typing import Optional

# Matches lines like:
#   Mar 25 14:22:01 server01 sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2
#   Mar 25 14:22:01 server01 sshd[1234]: Accepted password for elijah from 192.168.1.1 port 22 ssh2
LOG_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<hostname>\S+)"
    r"\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+(?P<username>\S+)"
    r"\s+from\s+(?P<source_ip>[\d.]+)"
    r"\s+port\s+(?P<port>\d+)"
)

CURRENT_YEAR = datetime.now().year


def parse_line(line: str) -> Optional[dict]:
    """
    Parse a single log line. Returns a dict or None if not a match.
    """
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    d = match.groupdict()

    # Build an ISO-ish timestamp (year is inferred since syslog omits it)
    raw_ts = f"{d['month']} {d['day'].zfill(2)} {CURRENT_YEAR} {d['time']}"
    try:
        ts = datetime.strptime(raw_ts, "%b %d %Y %H:%M:%S").isoformat()
    except ValueError:
        ts = raw_ts  # fallback — keep as-is

    return {
        "timestamp": ts,
        "hostname":  d["hostname"],
        "username":  d["username"],
        "source_ip": d["source_ip"],
        "port":      int(d["port"]),
        "status":    d["status"].lower(),  # 'failed' | 'accepted'
    }


def parse_log_file(filepath: str) -> list[dict]:
    """
    Parse all matching lines from a log file.
    Returns a list of event dicts.
    """
    events = []
    skipped = 0

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            event = parse_line(line.strip())
            if event:
                events.append(event)
            else:
                skipped += 1

    print(f"[+] Parsed {len(events)} events ({skipped} lines skipped).")
    return events
