# Linux Log Analyzer

A lightweight Python command-line tool that parses sample Linux SSH authentication
logs, summarizes events, flags repeated failed authentication attempts by source IP,
and exports JSON and CSV reports.

## Features

- Parses common SSH messages: failed password, invalid user, accepted password/public key.
- Counts authentication events and unique source IP addresses.
- Flags source IPs at or above a configurable failed-attempt threshold.
- Exports a JSON summary and CSV alert list.
- Includes unit tests using Python's built-in `unittest`.

## Requirements

- Python 3.10 or newer.
- Windows, Linux, or macOS.
- No third-party packages.

## Run on Windows

```powershell
python main.py --help
python main.py
```

Analyze another log file:

```powershell
python main.py --input samples/auth.log --threshold 5 --output-dir reports
```

Run tests:

```powershell
python -m unittest discover -s tests -v
```

## Sample Output

The included sample log is synthetic training data. With the default threshold,
the analyzer should flag `198.51.100.44` for repeated failed authentication events.

## Output Files

- `reports/security_report.json`: event counts and alert details.
- `reports/alerts.csv`: one row per flagged source IP.

## Project Structure

```text
linux-log-analyzer/
├── main.py
├── log_analyzer/
│   ├── __init__.py
│   ├── parser.py
│   ├── analyzer.py
│   ├── reporting.py
│   └── cli.py
├── samples/
│   └── auth.log
├── tests/
│   ├── __init__.py
│   └── test_analyzer.py
├── reports/
│   └── .gitkeep
├── .gitignore
├── requirements.txt
└── README.md
```

## Detection Logic and Limitations

- This project detects repeated failed SSH authentication events based on a simple count threshold.
- It does not prove malicious intent. Legitimate users can mistype passwords.
- It parses a limited set of common OpenSSH log message formats; distributions and versions may differ.
- Traditional syslog timestamps do not include a year, so `--year` supplies one for normalized timestamps.
- The sample IP ranges are documentation-only ranges, not real attacker infrastructure.
- Do not upload private logs containing usernames, public IPs, hostnames, or other sensitive data to a public repository.

## Safe Use

Use synthetic logs or logs from systems you own or are explicitly authorized to monitor.
Review and sanitize logs before sharing them.

## Future Improvements

- Correlate failed attempts followed by successful login for the same IP/account.
- Add time-window-based thresholds.
- Support additional Linux authentication log formats.
- Add HTML reports and severity tuning.

## License

MIT.
