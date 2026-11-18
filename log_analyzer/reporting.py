"""Export analyzer results to JSON and CSV."""

import csv
import json
from pathlib import Path


def write_json(report: dict, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=4), encoding="utf-8")


def write_alerts_csv(report: dict, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["source_ip", "failed_attempts", "targeted_users", "severity", "rule"]
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        for alert in report["alerts"]:
            row = dict(alert)
            row["targeted_users"] = ", ".join(row["targeted_users"])
            writer.writerow(row)
