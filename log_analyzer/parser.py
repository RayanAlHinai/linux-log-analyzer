"""Parse common SSH authentication messages from Linux auth.log samples."""

import re
from datetime import datetime

TIMESTAMP_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
)
IP_RE = re.compile(r"(?:from\s+\S+\s+from\s+|from\s+|rhost=)(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")

EVENT_PATTERNS = [
    ("failed", re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+)")),
    ("invalid_user", re.compile(r"Invalid user (?P<user>\S+)")),
    ("success", re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+)")),
]


def parse_auth_line(line: str, year: int = 2026) -> dict | None:
    """Return a normalized event for supported SSH auth log lines."""
    timestamp_match = TIMESTAMP_RE.match(line)
    if not timestamp_match:
        return None

    event_type = None
    username = None
    for candidate_type, pattern in EVENT_PATTERNS:
        match = pattern.search(line)
        if match:
            event_type = candidate_type
            username = match.groupdict().get("user")
            break

    if event_type is None:
        return None

    ip_match = IP_RE.search(line)
    source_ip = ip_match.group("ip") if ip_match else "unknown"

    timestamp_text = timestamp_match.group("timestamp")
    try:
        timestamp = datetime.strptime(
            f"{year} {timestamp_text}", "%Y %b %d %H:%M:%S"
        ).isoformat(sep=" ")
    except ValueError:
        timestamp = timestamp_text

    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "username": username or "unknown",
        "source_ip": source_ip,
        "raw": line.rstrip("\n"),
    }
