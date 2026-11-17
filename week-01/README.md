# Python Security Log Analyzer

## Overview
A Python-based security log analysis project developed as part of a 24-week AI Cybersecurity Engineering program.

## Features
- Parse JSONL security events
- Count successful and failed logins
- Detect repeated failures by IP address
- Detect repeated failures by username
- Detect brute-force patterns within a time window
- Validate detection logic with automated unit tests

## Requirements
- Python 3.14+
- No external dependencies

## Usage

Run the basic analyzer:

```bash
python analyzer.py
```

Run the time-window detector:

```bash
python time_detector.py
```

Run automated tests:

```bash
python -m unittest -v test_detection.py
```

## Detection limitations
- Thresholds are manually configured
- Alerts may include false positives
- Distributed attacks may evade IP-only detection
- Alert deduplication is basic
- Production log validation and error handling are not implemented

## Future Improvements
- Configurable detection rules
- Alert cooldowns
- Structured alert output
- Anomaly detection using machine learning
