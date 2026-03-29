"""
main.py
Entry point for the Failed Login Tracker.

Usage:
    python main.py --log sample_auth.log        # ingest + detect + report
    python main.py --log /var/log/auth.log       # use real system log
    python main.py --report-only                 # report from existing DB
    python main.py --generate-sample             # generate a test log file
"""

import argparse
import sys
from pathlib import Path

from db      import init_db
from parser  import parse_log_file
from ingest  import ingest_events
from detect  import (
    detect_brute_force,
    detect_password_spray,
    detect_distributed_attack,
    save_alerts,
)
from report  import print_report


def run_pipeline(log_path: str):
    print(f"\n[*] Starting pipeline on: {log_path}")

    if not Path(log_path).exists():
        print(f"[!] Log file not found: {log_path}")
        sys.exit(1)

    # 1. Parse
    events = parse_log_file(log_path)

    # 2. Ingest
    ingest_events(events)

    # 3. Detect
    print("[*] Running detection rules...")
    bf   = detect_brute_force()
    spray = detect_password_spray()
    dist  = detect_distributed_attack()

    print(f"    Brute Force hits    : {len(bf)}")
    print(f"    Password Spray hits : {len(spray)}")
    print(f"    Distributed hits    : {len(dist)}")

    save_alerts(bf, spray, dist)

    # 4. Report
    print_report()


def main():
    parser = argparse.ArgumentParser(
        description="Failed Login Tracker — SOC log analysis tool"
    )
    parser.add_argument("--log",             metavar="FILE", help="Path to auth.log file to ingest")
    parser.add_argument("--report-only",     action="store_true", help="Print report from existing DB, skip ingestion")
    parser.add_argument("--generate-sample", action="store_true", help="Generate a sample auth.log for testing")
    args = parser.parse_args()

    # Always init DB first
    init_db()

    if args.generate_sample:
        from generate_sample_logs import generate_logs
        generate_logs()
        print("[*] Run: python main.py --log sample_auth.log")
        return

    if args.report_only:
        print_report()
        return

    if args.log:
        run_pipeline(args.log)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
