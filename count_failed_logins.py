"""Count failed OpenSSH password logins by source IPv4 address."""

import argparse
import ipaddress
import re
import sys
from collections import Counter
from pathlib import Path

FAILED_PASSWORD = "Failed password"
SOURCE_IP = re.compile(r"\bfrom\s+(\S+)")
UNKNOWN_IP = "unknown"


def get_source_ip(line):
    """Return the valid IPv4 address in a log line, or "unknown"."""
    matches = SOURCE_IP.findall(line)
    if not matches:
        return UNKNOWN_IP

    try:
        return str(ipaddress.IPv4Address(matches[-1]))
    except ipaddress.AddressValueError:
        return UNKNOWN_IP


def count_failed_logins(lines):
    """Count failed-password log entries by source IPv4 address."""
    counts = Counter()
    for line in lines:
        if FAILED_PASSWORD in line:
            counts[get_source_ip(line)] += 1
    return counts


def main():
    """Read the requested log file, print counts, and return an exit code."""
    parser = argparse.ArgumentParser(
        description="Count failed OpenSSH password logins by source IPv4 address."
    )
    parser.add_argument("log_file", type=Path, help="path to the auth.log file")
    parser.add_argument(
        "--threshold",
        type=int,
        help="mark source IPs with at least this many failed logins as suspicious",
    )
    args = parser.parse_args()

    try:
        with args.log_file.open(encoding="utf-8") as log_file:
            counts = count_failed_logins(log_file)
    except (OSError, UnicodeError) as error:
        print(f"Error reading {args.log_file}: {error}", file=sys.stderr)
        return 1

    if not counts:
        print("No failed logins found.")
        return 0

    def sort_key(item):
        """Sort by count, then IPv4 address, with unknown addresses last."""
        ip, count = item
        if ip == UNKNOWN_IP:
            return (-count, 1, 0)
        return (-count, 0, int(ipaddress.IPv4Address(ip)))

    for ip, count in sorted(counts.items(), key=sort_key):
        suspicious = (
            " SUSPICIOUS"
            if args.threshold is not None and count >= args.threshold
            else ""
        )
        print(f"{ip}: {count}{suspicious}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
