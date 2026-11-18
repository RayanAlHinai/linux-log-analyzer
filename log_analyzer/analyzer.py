"""Aggregate authentication events and identify simple alert conditions."""

from collections import Counter, defaultdict


def analyze_events(events: list[dict], threshold: int = 5) -> dict:
    """Summarize events and flag IPs with failed attempts at/above threshold."""
    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    counts = Counter(event["event_type"] for event in events)
    failures_by_ip = Counter(
        event["source_ip"] for event in events
        if event["event_type"] in {"failed", "invalid_user"}
    )
    users_by_ip = defaultdict(set)
    for event in events:
        if event["event_type"] in {"failed", "invalid_user"}:
            users_by_ip[event["source_ip"]].add(event["username"])

    alerts = []
    for ip, failures in sorted(failures_by_ip.items()):
        if ip != "unknown" and failures >= threshold:
            alerts.append({
                "source_ip": ip,
                "failed_attempts": failures,
                "targeted_users": sorted(users_by_ip[ip]),
                "severity": "high" if failures >= threshold * 2 else "medium",
                "rule": f"Failed authentication attempts >= {threshold}",
            })

    return {
        "total_events": len(events),
        "failed_events": counts["failed"],
        "invalid_user_events": counts["invalid_user"],
        "successful_events": counts["success"],
        "unique_source_ips": len({e["source_ip"] for e in events if e["source_ip"] != "unknown"}),
        "alerts": alerts,
    }
