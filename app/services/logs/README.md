# Logs Service

Log parsing and AI analysis services for the Logs Analyzer application.

## Components

- [Parser](./parser.py) - Multi-format log parsing engine
- [AI](./ai.py) - HuggingFace router AI analyzer for log insights

---

## Parser

Multi-format log parser for analyzing system, application, web, and security logs.

### Supported Log Types

| Type | Description | Patterns Detected |
|------|-------------|----------------|
| `system` | System daemon logs (syslog, journald) | Timestamps, service names, PIDs |
| `application` | Application logs (JSON, custom) | JSON objects, level markers |
| `web` | HTTP access logs (Apache, nginx) | IP, method, URL, status codes |
| `security` | Auth logs (SSH, sudo, fail2ban) | Login events, failures, bans |
| `database` | DB logs (PostgreSQL, MySQL) | Query, errors, slow queries |
| `queue` | Queue logs (RabbitMQ, Kafka) | Messages, offsets, lag |
| `network_device` | Router/switch logs (Cisco) | Interface states, protocols |
| `firewall` | Firewall logs (iptables, ufw) | ACCEPT/DROP, protocols |
| `container` | Docker/Kubernetes logs | Container events, OOM |
| `windows_ad` | Windows/AD Event logs | EventIDs, logon types |
| `camera` | NVR/Camera logs | Motion, recording |
| `printer` | Printer logs (CUPS) | Jobs, supplies |

### Key Features

- **Type Detection**: Scores log lines against pattern libraries to identify log type with confidence level
- **Timestamp Normalization**: Converts 11 different timestamp formats to ISO 8601
- **Correlation ID Extraction**: Extracts request_id, trace_id, session_id, user_id from various formats
- **Template Generation**: Replaces PII (IPs, emails, UUIDs, paths) with `<PLACEHOLDER>` tokens for grouping
- **Signature Generation**: Creates short hash for log deduplication across similar events
- **Anomaly Detection**: Identifies brute force attempts, slow requests, repeated errors, high unknown ratios

### Usage

```python
from app.services.logs.parser import LogParser

parser = LogParser()

# Parse single line
result = parser.parse_line("2024-01-15 10:30:45 ERROR Connection failed", line_no=1)

# Parse entire file
result = parser.parse_file("/path/to/logfile.log")
```

### Output Structure

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

### Field Mapping to Models

| Parser Field | Model Column | Description |
|------------|-----------|-----------|------------|
| `level` | `Result.level` | Log severity level |
| `message` | `Result.message` | Raw log message |
| `extra` | `Result.details` | Extracted metadata |
| `type` | `Result.detected_type` | Log category |
| `event_category` | `Result.event_category` | Event classification |
| `template` | `Result.template` | Anonymized pattern |
| `signature` | `Result.signature` | Hash for deduplication |

### Integration in Operations

**File Processing Flow** (`app/core/process.py`):

```
LogParser.parse_file()
    ↓
result["result"]["logs"]  ← List of parsed log dictionaries
    ↓
For each log:
  - Extract: log["level"]
  - Extract: log["message"]
  - Extract: log["extra"]
    ↓
ai_analyzer(message) → AI note
    ↓
ResultOperations.create_result({
    "log_id": ...,
    "user_id": ...,
    "level": level,
    "message": message,
    "details": json.dumps(extra),
    "ai_note": note,
})
```

### Limits

| Category | Limitation |
|----------|-----------|
| **Regex-based** | Non-standard formats may be misclassified |
| **Single-line** | Does not handle multiline entries |
| **Timestamps** | Only 11 predefined formats |
| **Encoding** | Assumes UTF-8 |
| **PII Extraction** | Limited to IPv4/IPv6, emails, UUIDs |
| **Web Format** | Expects Apache/NCSA combined format |
| **No Streaming** | Loads entire file into memory |
| **No Incremental** | Correlates only at file-level |

---

## AI Analyzer

AI-powered log analysis using HuggingFace router (OpenAI-compatible API).

### Setup

Set the `HF_TOKEN` environment variable:

```bash
export HF_TOKEN="your-huggingface-token"
```

### Usage

```python
from app.services.logs.ai import ai_analyzer

result = ai_analyzer("2024-01-15 10:30:45 ERROR Connection failed from 192.168.1.100")

if result:
    notes = result.get("AI", [])
    for item in notes:
        print(item["index"], item["note"])
```

### Output Format

```python
{
    "AI": [
        {"index": 0, "note": "Connection failed - possible authentication issue..."},
        {"index": 1, "note": "..."}
    ]
}
```

### System Prompt Rules

The AI engine follows these detection rules:

| Rule | Description |
|------|------------|
| HTTP 5xx | Server failure (critical) |
| HTTP 4xx | Client error or malicious request |
| Repeated failures | Possible brute-force attack |
| Auth errors | Security risk |
| Unknown patterns | Anomaly |

### Error Handling

- Returns `None` on API failure
- Logs errors via `app.utils.logger`
- Requires valid `HF_TOKEN` to function

### Dependencies

- `openai` package (OpenAI-compatible client)
- HuggingFace router endpoint (configured in `ai.py`)

---

## Processing Flow

```
Upload Log File
    ↓
process_logs(file_path, log_id, user_id)
    ↓
LogParser.parse_file() → parsed logs
    ↓
For each log line:
  ├─ LogParser.parse_line()
  ├─ detect_log_type() → type detection
  ├─ enrich_record() → template/signature
  └─ ai_analyzer() → AI note (errors only)
    ↓
ResultOperations.create_result() → DB
    ↓
Log completed
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `openai` | OpenAI-compatible client for AI analyzer |
| `python-dateutil` | Date parsing |
| `fastapi` | API framework |
| `sqlalchemy` | Database ORM |