"""Command-line entry point."""

import argparse
from pathlib import Path

from log_analyzer.analyzer import analyze_events
from log_analyzer.parser import parse_auth_line
from log_analyzer.reporting import write_alerts_csv, write_json


def build_parser():
    parser = argparse.ArgumentParser(
        description="Analyze Linux SSH authentication logs for repeated failures."
    )
    parser.add_argument("--input", default="samples/auth.log",
                        help="Path to auth.log (default: samples/auth.log)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts per IP required for an alert.")
    parser.add_argument("--year", type=int, default=2026,
                        help="Year to attach to syslog timestamps.")
    parser.add_argument("--output-dir", default="reports",
                        help="Directory for generated reports.")
    return parser


def run(args):
    input_path = Path(args.input)
    if not input_path.is_file():
        raise FileNotFoundError(f"Input log not found: {input_path}")
    if args.threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    events = []
    ignored_lines = 0
    with input_path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            event = parse_auth_line(line, year=args.year)
            if event is None:
                ignored_lines += 1
            else:
                events.append(event)

    report = analyze_events(events, threshold=args.threshold)
    report["input_file"] = str(input_path)
    report["ignored_lines"] = ignored_lines
    output_dir = Path(args.output_dir)
    json_path = output_dir / "security_report.json"
    csv_path = output_dir / "alerts.csv"
    write_json(report, str(json_path))
    write_alerts_csv(report, str(csv_path))

    print("=== Linux Log Analyzer ===")
    print(f"Input file: {input_path}")
    print(f"Parsed events: {report['total_events']}")
    print(f"Failed logins: {report['failed_events']}")
    print(f"Invalid-user events: {report['invalid_user_events']}")
    print(f"Successful logins: {report['successful_events']}")
    print(f"Alerts: {len(report['alerts'])}")
    for alert in report["alerts"]:
        print(
            f"[{alert['severity'].upper()}] {alert['source_ip']}: "
            f"{alert['failed_attempts']} failed attempts"
        )
    print(f"JSON report: {json_path}")
    print(f"CSV report: {csv_path}")
    return report


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        run(args)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Error: {error}\n")
