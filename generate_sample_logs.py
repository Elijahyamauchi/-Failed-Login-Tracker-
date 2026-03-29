"""
generate_sample_logs.py
Generates a realistic sample auth.log file for testing the Failed Login Tracker.
"""

import random
from datetime import datetime, timedelta

USERNAMES = ["root", "admin", "ubuntu", "elijah", "guest", "deploy", "www-data"]
IPS = [
    "192.168.1.105",   # internal - normal
    "192.168.1.200",   # internal - normal
    "45.33.32.156",    # external - brute force
    "185.220.101.42",  # Tor exit node sim
    "203.0.113.77",    # external - brute force
    "10.0.0.55",       # internal - occasional fail
]

def generate_logs(output_file="sample_auth.log", num_entries=200):
    lines = []
    base_time = datetime.now() - timedelta(hours=6)

    for i in range(num_entries):
        ts = base_time + timedelta(seconds=random.randint(0, 21600))
        ts_str = ts.strftime("%b %d %H:%M:%S")
        pid = random.randint(1000, 9999)
        hostname = "server01"

        # Simulate brute force: attacker IPs fail repeatedly
        if random.random() < 0.55:
            ip = random.choice(["45.33.32.156", "185.220.101.42", "203.0.113.77"])
            user = random.choice(["root", "admin", "ubuntu"])
            lines.append(
                f"{ts_str} {hostname} sshd[{pid}]: Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
            )
        elif random.random() < 0.2:
            ip = random.choice(["192.168.1.105", "192.168.1.200", "10.0.0.55"])
            user = random.choice(USERNAMES)
            lines.append(
                f"{ts_str} {hostname} sshd[{pid}]: Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
            )
        else:
            ip = random.choice(["192.168.1.105", "192.168.1.200"])
            user = random.choice(["elijah", "deploy"])
            lines.append(
                f"{ts_str} {hostname} sshd[{pid}]: Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
            )

    lines.sort()  # approximate chronological order

    with open(output_file, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Generated {len(lines)} log entries -> {output_file}")

if __name__ == "__main__":
    generate_logs()
