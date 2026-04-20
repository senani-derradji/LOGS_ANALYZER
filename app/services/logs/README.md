# Log Parser

Multi-format log parser for analyzing system, application, web, and security logs.

## Supported Log Types

| Type | Description | Patterns Detected |
|------|-------------|------------------|
| `system` | System daemon logs (syslog, journald) | Timestamps, service names, PIDs |
| `application` | Application logs (JSON, custom) | JSON objects, level markers |
| `web` | HTTP access logs (Apache, nginx) | IP, method, URL, status codes |
| `security` | Auth logs (SSH, sudo, fail2ban) | Login events, failures, bans |

## Key Features

- **Type Detection**: Scores log lines against pattern libraries to identify log type with confidence level
- **Timestamp Normalization**: Converts 11 different timestamp formats to ISO 8601
- **Correlation ID Extraction**: Extracts request_id, trace_id, session_id, user_id from various formats
- **Template Generation**: Replaces PII (IPs, emails, UUIDs, paths) with `<PLACEHOLDER>` tokens for grouping
- **Signature Generation**: Creates short hash for log deduplication across similar events
- **Anomaly Detection**: Identifies brute force attempts, slow requests, repeated errors, high unknown ratios

## Usage

```python
from app.services.logs.parser import LogParser

parser = LogParser()

# Parse single line
result = parser.parse_line("2024-01-15 10:30:45 ERROR Connection failed", line_no=1)

# Parse entire file
result = parser.parse_file("/path/to/logfile.log")
```

## Output Structure

Each parsed line returns:

```python
{
    "timestamp": "2024-01-15 10:30:45",
    "normalized_timestamp": "2024-01-15T10:30:45",
    "type": "application",
    "level": "ERROR",
    "message": "Connection failed",
    "detected_type": "application",
    "confidence": 0.85,
    "extra": {"ip": None, "user": None, ...},
    "template": "<TIMESTAMP> ERROR <MESSAGE>",
    "signature": "a1b2c3d4e5f6",
    "correlation": {"request_id": None, ...},
    "event_category": "app_error",
    "epoch": 1705317045.0,
}
```

## Limits

### Parsing Limitations

- **Regex-based**: Only recognizes patterns defined in code; non-standard formats may be misclassified
- **Single-line**: Does not handle multiline log entries (stack traces, JSON blocks)
- **Fixed Timestamp Formats**: Only supports 11 predefined formats; custom formats ignored
- **No Encoding Negotiation**: Assumes UTF-8, uses `errors="ignore"` for other encodings
- **Fixed Thresholds**: Anomaly detection uses hardcoded values (5+ failures, 2000ms+ slow, 20% unknown)

### Detection Limitations

- **Confidence Scoring**: May misclassify when log contains mixed patterns from multiple types
- **PII Extraction**: Limited to IPv4/IPv6, emails, UUIDs - misses phone numbers, addresses
- **Web Log Format**: Expects Apache/NCSA combined log format - other formats less reliable
- **Security Events**: Only recognizes explicitly listed patterns (sshd, sudo, fail2ban, pam_unix)

### Functional Limitations

- **No Streaming**: Loads entire file into memory before processing
- **No Incremental Correlation**: Correlates only at file-level, not across files
- **No Parsing Statistics**: Does not track per-parser success rates
- **No Custom Pattern Support**: Cannot add patterns at runtime without code changes
- **No Error Recovery**: Partial parse failures result in UNKNOWN type rather than best-effort