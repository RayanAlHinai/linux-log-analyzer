import tempfile
import unittest
from pathlib import Path

from log_analyzer.analyzer import analyze_events
from log_analyzer.parser import parse_auth_line
from log_analyzer.reporting import write_alerts_csv, write_json


class ParserTests(unittest.TestCase):
    def test_parse_failed_login(self):
        line = ("Nov 16 09:02:11 host sshd[123]: Failed password for root "
                "from 198.51.100.44 port 22 ssh2")
        event = parse_auth_line(line)
        self.assertEqual(event["event_type"], "failed")
        self.assertEqual(event["username"], "root")
        self.assertEqual(event["source_ip"], "198.51.100.44")

    def test_parse_successful_login(self):
        line = ("Nov 16 09:00:01 host sshd[123]: Accepted password for alice "
                "from 192.0.2.20 port 22 ssh2")
        self.assertEqual(parse_auth_line(line)["event_type"], "success")

    def test_ignore_unrecognized_line(self):
        self.assertIsNone(parse_auth_line("Nov 16 09:00:01 host systemd: Started service"))


class AnalyzerTests(unittest.TestCase):
    def test_alert_at_threshold(self):
        events = [
            {"event_type": "failed", "source_ip": "198.51.100.1", "username": "root"}
            for _ in range(5)
        ]
        report = analyze_events(events, threshold=5)
        self.assertEqual(len(report["alerts"]), 1)
        self.assertEqual(report["alerts"][0]["severity"], "medium")

    def test_no_alert_below_threshold(self):
        events = [
            {"event_type": "failed", "source_ip": "198.51.100.1", "username": "root"}
            for _ in range(2)
        ]
        self.assertEqual(analyze_events(events, threshold=5)["alerts"], [])

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze_events([], threshold=0)


class ReportingTests(unittest.TestCase):
    def test_exports_reports(self):
        report = {"total_events": 0, "alerts": []}
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / "report.json"
            csv_path = Path(temp_dir) / "alerts.csv"
            write_json(report, str(json_path))
            write_alerts_csv(report, str(csv_path))
            self.assertTrue(json_path.exists())
            self.assertTrue(csv_path.exists())


if __name__ == "__main__":
    unittest.main()
