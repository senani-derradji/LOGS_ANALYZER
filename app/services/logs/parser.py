import re
import json
import hashlib
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict


# =========================
# 🔧 COMMON PATTERNS
# =========================
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){2,}[a-fA-F0-9:]+\b")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
PATH_RE = re.compile(r"(\/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)+")
NUMBER_RE = re.compile(r"\b\d+\b")
HEX_RE = re.compile(r"\b0x[a-fA-F0-9]+\b")

LEVEL_RE = re.compile(
    r"\b(INFO|ERROR|WARNING|WARN|CRITICAL|DEBUG|TRACE|FATAL)\b",
    re.IGNORECASE
)

SECURITY_PATTERNS = [
    r"failed password",
    r"invalid user",
    r"authentication failure",
    r"fail2ban",
    r"unauthorized",
    r"access denied",
    r"sudo:",
    r"pam_unix",
    r"sshd",
    r"accepted password",
    r"session opened",
    r"session closed",
    r"permission denied",
    r"token expired",
    r"jwt",
]

WEB_PATTERNS = [
    r'"\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+',
    r"\bHTTP/\d\.\d\b",
    r"\bstatus\b",
    r"\bresponse_time\b",
    r"\brequest_time\b",
    r"\buser_agent\b",
]

SYSTEM_PATTERNS = [
    r"^\d{4}-\d{2}-\d{2}",
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
    r"\bkernel\b",
    r"\bsystemd\b",
    r"\bservice\b",
    r"\bdaemon\b",
]

TIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
    "%b  %d %H:%M:%S",
]

CORRELATION_PATTERNS = {
    "request_id": [
        r"\brequest[_-]?id[=:]\s*([A-Za-z0-9._-]+)",
        r"\bx-request-id[=:]\s*([A-Za-z0-9._-]+)",
    ],
    "trace_id": [
        r"\btrace[_-]?id[=:]\s*([A-Za-z0-9._-]+)",
        r"\bx-trace-id[=:]\s*([A-Za-z0-9._-]+)",
    ],
    "correlation_id": [
        r"\bcorrelation[_-]?id[=:]\s*([A-Za-z0-9._-]+)",
        r"\bx-correlation-id[=:]\s*([A-Za-z0-9._-]+)",
        r"\bcid[=:]\s*([A-Za-z0-9._-]+)",
    ],
    "session_id": [
        r"\bsession[_-]?id[=:]\s*([A-Za-z0-9._-]+)",
        r"\bx-session-id[=:]\s*([A-Za-z0-9._-]+)",
    ],
    "user_id": [
        r"\buser[_-]?id[=:]\s*([A-Za-z0-9._-]+)",
        r"\buid[=:]\s*([A-Za-z0-9._-]+)",
    ],
}


# =========================
# 🧰 HELPERS
# =========================
def normalize_level(level: str | None) -> str:
    if not level:
        return "UNKNOWN"
    level = level.upper().strip()
    mapping = {"WARN": "WARNING", "FATAL": "CRITICAL"}
    return mapping.get(level, level)


def normalize_timestamp(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    for fmt in TIME_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.isoformat()
        except ValueError:
            continue
    return value


def to_epoch(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except Exception:
        return None


def extract_ip(text: str) -> str | None:
    m = IPV4_RE.search(text)
    if m:
        return m.group(0)
    m = IPV6_RE.search(text)
    return m.group(0) if m else None


def extract_user(text: str) -> str | None:
    patterns = [
        r"(?:invalid user|for user|user|for)\s+([a-zA-Z0-9._@-]+)",
        r"user=([a-zA-Z0-9._@-]+)",
        r"username=([a-zA-Z0-9._@-]+)",
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def extract_port(text: str) -> int | None:
    m = re.search(r"\bport\s+(\d+)\b", text, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


def detect_embedded_timestamp(line: str) -> str | None:
    candidates = [
        r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b",
        r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
        r"\b\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?\b",
        r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b",
    ]
    for p in candidates:
        m = re.search(p, line)
        if m:
            return m.group(0)
    return None


def make_template(message: str) -> str:
    if not message:
        return ""
    text = message
    text = UUID_RE.sub("<UUID>", text)
    text = EMAIL_RE.sub("<EMAIL>", text)
    text = IPV4_RE.sub("<IP>", text)
    text = IPV6_RE.sub("<IPV6>", text)
    text = HEX_RE.sub("<HEX>", text)
    text = PATH_RE.sub("<PATH>", text)
    text = NUMBER_RE.sub("<NUM>", text)
    return text


def make_signature(log_type: str, level: str, template: str) -> str:
    base = f"{log_type}|{level}|{template}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:16]


def extract_correlation_fields(text: str, extra: dict | None = None) -> dict:
    result = {
        "request_id": None,
        "trace_id": None,
        "correlation_id": None,
        "session_id": None,
        "user_id": None,
    }

    if isinstance(extra, dict):
        for key in result:
            if extra.get(key):
                result[key] = str(extra.get(key))

    for key, patterns in CORRELATION_PATTERNS.items():
        if result[key]:
            continue
        for p in patterns:
            m = re.search(p, text, re.IGNORECASE)
            if m:
                result[key] = m.group(1)
                break

    return result


def build_unified_extra(base: dict | None = None) -> dict:
    fields = {
        "ip": None,
        "user": None,
        "user_id": None,
        "port": None,
        "method": None,
        "url": None,
        "protocol": None,
        "status": None,
        "size": None,
        "referrer": None,
        "user_agent": None,
        "event": None,
        "service": None,
        "host": None,
        "pid": None,
        "duration_ms": None,
        "duration_s": None,
    }
    if isinstance(base, dict):
        fields.update(base)
    return fields


# =========================
# 🔍 DETECTION ENGINE
# =========================
def detect_log_type(line: str) -> dict:
    line = line.strip()
    scores = {"application": 0, "web": 0, "security": 0, "system": 0}
    signals = []

    if not line:
        return {"detected_type": "unknown", "confidence": 0.0, "signals": []}

    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
            scores["application"] += 4
            signals.append("json_object")
            if any(k in data for k in ("timestamp", "level", "message", "service")):
                scores["application"] += 2
                signals.append("app_keys_present")

            msg = str(data.get("message", ""))
            for p in SECURITY_PATTERNS:
                if re.search(p, msg, re.IGNORECASE):
                    scores["security"] += 2
                    signals.append(f"security_in_json:{p}")
        except Exception:
            pass

    for p in SECURITY_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            scores["security"] += 2
            signals.append(f"security:{p}")

    for p in WEB_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            scores["web"] += 2
            signals.append(f"web:{p}")

    for p in SYSTEM_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            scores["system"] += 1
            signals.append(f"system:{p}")

    if re.search(r'^\S+ \S+ \S+ \[[^\]]+\] "(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) ', line, re.IGNORECASE):
        scores["web"] += 3
        signals.append("combined_access_log")

    if LEVEL_RE.search(line) and detect_embedded_timestamp(line):
        scores["system"] += 2
        scores["application"] += 1
        signals.append("timestamp_and_level")

    best_type = max(scores, key=scores.get)
    best_score = scores[best_type]
    total = sum(scores.values()) or 1

    if best_score == 0:
        return {"detected_type": "unknown", "confidence": 0.0, "signals": []}

    return {
        "detected_type": best_type,
        "confidence": round(best_score / total, 2),
        "signals": signals,
    }


# =========================
# 🧱 BASE PARSER
# =========================
class BaseParser:
    def parse(self, line: str) -> dict:
        detected_ts = detect_embedded_timestamp(line)
        level_match = LEVEL_RE.search(line)

        extra = build_unified_extra({
            "ip": extract_ip(line),
            "user": extract_user(line),
            "port": extract_port(line),
        })

        return {
            "timestamp": detected_ts,
            "normalized_timestamp": normalize_timestamp(detected_ts),
            "type": "unknown",
            "level": normalize_level(level_match.group(1) if level_match else "UNKNOWN"),
            "message": line.strip(),
            "extra": extra,
        }


# =========================
# 🖥 SYSTEM LOG PARSER
# =========================
class SystemLogParser(BaseParser):
    patterns = [
        re.compile(
            r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+"
            r"(?P<level>INFO|ERROR|WARNING|WARN|CRITICAL|DEBUG|TRACE|FATAL)\s+"
            r"(?P<message>.*)",
            re.IGNORECASE
        ),
        re.compile(
            r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
            r"(?P<host>\S+)\s+"
            r"(?P<service>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*"
            r"(?P<message>.*)"
        ),
    ]

    def parse(self, line: str) -> dict:
        for pattern in self.patterns:
            match = pattern.match(line)
            if match:
                data = match.groupdict()
                level = normalize_level(data.get("level"))
                if level == "UNKNOWN":
                    inferred = LEVEL_RE.search(data.get("message", ""))
                    level = normalize_level(inferred.group(1) if inferred else "INFO")

                extra = build_unified_extra({
                    "host": data.get("host"),
                    "service": data.get("service"),
                    "pid": int(data["pid"]) if data.get("pid") else None,
                    "ip": extract_ip(line),
                    "user": extract_user(line),
                })

                return {
                    "timestamp": data.get("timestamp"),
                    "normalized_timestamp": normalize_timestamp(data.get("timestamp")),
                    "type": "system",
                    "level": level,
                    "message": data.get("message", "").strip(),
                    "extra": extra,
                }

        return BaseParser().parse(line)


# =========================
# 📦 APPLICATION LOG PARSER
# =========================
class ApplicationLogParser(BaseParser):
    patterns = [
        re.compile(
            r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+"
            r"(?:\[(?P<level>INFO|ERROR|WARNING|WARN|CRITICAL|DEBUG|TRACE|FATAL)\]|(?P<level2>INFO|ERROR|WARNING|WARN|CRITICAL|DEBUG|TRACE|FATAL))\s+"
            r"(?P<message>.*)",
            re.IGNORECASE
        )
    ]

    def parse(self, line: str) -> dict:
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                message = str(data.get("message", "")).strip()

                extra = {
                    k: v for k, v in data.items()
                    if k not in {"timestamp", "level", "message", "type"}
                }
                extra = build_unified_extra(extra)
                extra["ip"] = extra.get("ip") or extract_ip(message)
                extra["user"] = extra.get("user") or extract_user(message)
                extra["port"] = extra.get("port") or extract_port(message)

                if extra.get("request_time") and not extra.get("duration_s"):
                    try:
                        extra["duration_s"] = float(extra["request_time"])
                        extra["duration_ms"] = round(extra["duration_s"] * 1000, 2)
                    except Exception:
                        pass

                return {
                    "timestamp": data.get("timestamp"),
                    "normalized_timestamp": normalize_timestamp(data.get("timestamp")),
                    "type": "application",
                    "level": normalize_level(data.get("level", "INFO")),
                    "message": message,
                    "extra": extra,
                }
            except Exception:
                pass

        for pattern in self.patterns:
            match = pattern.match(line)
            if match:
                data = match.groupdict()
                message = data.get("message", "").strip()

                extra = build_unified_extra({
                    "ip": extract_ip(message),
                    "user": extract_user(message),
                    "port": extract_port(message),
                })

                return {
                    "timestamp": data.get("timestamp"),
                    "normalized_timestamp": normalize_timestamp(data.get("timestamp")),
                    "type": "application",
                    "level": normalize_level(data.get("level") or data.get("level2")),
                    "message": message,
                    "extra": extra,
                }

        return BaseParser().parse(line)


# =========================
# 🌐 WEB LOG PARSER
# =========================
class WebLogParser(BaseParser):
    patterns = [
        re.compile(
            r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
            r'"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<url>\S+)\s+(?P<protocol>HTTP/\d\.\d)"\s+'
            r'(?P<status>\d{3})\s+(?P<size>\S+)'
            r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
            r'(?:\s+(?P<trailing_time>\d+(?:\.\d+)?))?$',
            re.IGNORECASE
        )
    ]

    def parse(self, line: str) -> dict:
        for pattern in self.patterns:
            match = pattern.match(line)
            if match:
                data = match.groupdict()
                status = int(data["status"])

                if 200 <= status < 300:
                    level = "INFO"
                elif 300 <= status < 400:
                    level = "INFO"
                elif 400 <= status < 500:
                    level = "ERROR"
                else:
                    level = "CRITICAL"

                size_raw = data.get("size")
                size = None if size_raw in (None, "-", "") else int(size_raw)

                duration_ms = None
                duration_s = None
                trailing = data.get("trailing_time")
                if trailing is not None:
                    try:
                        duration_ms = float(trailing)
                        duration_s = round(duration_ms / 1000.0, 6)
                    except Exception:
                        pass

                extra = build_unified_extra({
                    "ip": data.get("ip"),
                    "method": data.get("method"),
                    "url": data.get("url"),
                    "protocol": data.get("protocol"),
                    "status": status,
                    "size": size,
                    "referrer": data.get("referrer"),
                    "user_agent": data.get("user_agent"),
                    "duration_ms": duration_ms,
                    "duration_s": duration_s,
                })

                return {
                    "timestamp": data.get("time"),
                    "normalized_timestamp": normalize_timestamp(data.get("time")),
                    "type": "web",
                    "level": level,
                    "message": f"{data['method']} {data['url']} {status}",
                    "extra": extra,
                }

        return BaseParser().parse(line)


# =========================
# 🔐 SECURITY LOG PARSER
# =========================
class SecurityLogParser(BaseParser):
    def parse(self, line: str) -> dict:
        lower = line.lower()
        ip = extract_ip(line)
        user = extract_user(line)
        port = extract_port(line)

        if "failed password" in lower or "invalid user" in lower:
            level = "WARNING"
            event = "failed_login"
        elif "accepted password" in lower:
            level = "INFO"
            event = "successful_login"
        elif "fail2ban" in lower:
            level = "INFO"
            event = "ip_blocked"
        elif "authentication failure" in lower:
            level = "WARNING"
            event = "auth_failure"
        elif "permission denied" in lower or "access denied" in lower:
            level = "ERROR"
            event = "access_denied"
        elif "jwt" in lower or "token expired" in lower:
            level = "WARNING"
            event = "token_issue"
        else:
            level = "INFO"
            event = "security_event"

        service = None
        for svc in ("sshd", "sudo", "pam_unix", "fail2ban"):
            if svc in lower:
                service = svc
                break

        extra = build_unified_extra({
            "event": event,
            "ip": ip,
            "user": user,
            "port": port,
            "service": service,
        })

        return {
            "timestamp": detect_embedded_timestamp(line),
            "normalized_timestamp": normalize_timestamp(detect_embedded_timestamp(line)),
            "type": "security",
            "level": level,
            "message": line.strip(),
            "extra": extra,
        }


# =========================
# 🧠 MAIN ENGINE
# =========================
class LogParser:
    def __init__(self):
        self.parsers = {
            "system": SystemLogParser(),
            "application": ApplicationLogParser(),
            "web": WebLogParser(),
            "security": SecurityLogParser(),
        }

    def enrich_record(self, raw_line: str, parsed: dict, line_no: int) -> dict:
        parsed["type"] = parsed.get("type", "unknown")
        parsed["detected_type"] = parsed.get("type", "unknown")
        parsed["level"] = normalize_level(parsed.get("level"))
        parsed["timestamp"] = parsed.get("timestamp")
        parsed["normalized_timestamp"] = normalize_timestamp(parsed.get("normalized_timestamp") or parsed.get("timestamp"))

        if "extra" not in parsed or not isinstance(parsed["extra"], dict):
            parsed["extra"] = build_unified_extra()
        else:
            parsed["extra"] = build_unified_extra(parsed["extra"])

        parsed["extra"]["ip"] = parsed["extra"].get("ip") or extract_ip(raw_line)
        parsed["extra"]["user"] = parsed["extra"].get("user") or extract_user(raw_line)
        parsed["extra"]["port"] = parsed["extra"].get("port") or extract_port(raw_line)

        parsed["template"] = make_template(parsed.get("message", ""))
        parsed["signature"] = make_signature(parsed["type"], parsed["level"], parsed["template"])
        parsed["line_number"] = line_no

        corr = extract_correlation_fields(raw_line, parsed["extra"])
        parsed["correlation"] = corr

        parsed["event_category"] = self.classify_event_category(parsed)
        parsed["epoch"] = to_epoch(parsed.get("normalized_timestamp"))

        return parsed

    def classify_event_category(self, record: dict) -> str:
        log_type = record.get("type")
        level = record.get("level")
        extra = record.get("extra", {}) or {}

        if log_type == "security":
            return extra.get("event") or "security_event"
        if log_type == "web":
            status = extra.get("status")
            if status is not None:
                if 500 <= status < 600:
                    return "server_error"
                if 400 <= status < 500:
                    return "client_error"
                if 300 <= status < 400:
                    return "redirect"
                return "request"
        if log_type == "application":
            if level in {"ERROR", "CRITICAL"}:
                return "app_error"
            return "app_event"
        if log_type == "system":
            if level in {"ERROR", "CRITICAL"}:
                return "system_error"
            return "system_event"
        return "unknown_event"

    def parse_line(self, line: str, line_no: int = 0) -> dict:
        detection = detect_log_type(line)
        detected_type = detection["detected_type"]
        parser = self.parsers.get(detected_type, BaseParser())

        parsed = parser.parse(line)
        parsed["type"] = detected_type
        parsed["confidence"] = detection["confidence"]
        parsed["signals"] = detection["signals"]

        return self.enrich_record(line, parsed, line_no)

    def correlate_logs(self, logs: list[dict]) -> dict:
        groups = {
            "request_id": defaultdict(list),
            "trace_id": defaultdict(list),
            "correlation_id": defaultdict(list),
            "session_id": defaultdict(list),
            "user_id": defaultdict(list),
            "ip": defaultdict(list),
            "user": defaultdict(list),
        }

        for log in logs:
            corr = log.get("correlation", {}) or {}
            extra = log.get("extra", {}) or {}

            for key in ("request_id", "trace_id", "correlation_id", "session_id", "user_id"):
                value = corr.get(key)
                if value:
                    groups[key][value].append(log["line_number"])

            if extra.get("ip"):
                groups["ip"][extra["ip"]].append(log["line_number"])
            if extra.get("user"):
                groups["user"][extra["user"]].append(log["line_number"])

        compact = {}
        for key, bucket in groups.items():
            compact[key] = {
                k: v for k, v in bucket.items()
                if len(v) >= 2
            }
        return compact

    def detect_anomalies(self, logs: list[dict], result: dict) -> list[dict]:
        anomalies = []

        ip_failures = Counter()
        signature_counts = Counter()
        signature_errors = Counter()
        slow_requests = []
        five_xx_by_url = Counter()
        rare_error_signatures = Counter()

        for log in logs:
            extra = log.get("extra", {}) or {}
            sig = log.get("signature")
            level = log.get("level")
            event_category = log.get("event_category")

            if sig:
                signature_counts[sig] += 1

            if level in {"ERROR", "CRITICAL"} and sig:
                signature_errors[sig] += 1
                rare_error_signatures[sig] += 1

            if log.get("type") == "security" and extra.get("event") == "failed_login" and extra.get("ip"):
                ip_failures[extra["ip"]] += 1

            if log.get("type") == "web":
                status = extra.get("status")
                url = extra.get("url") or "<unknown>"
                duration_ms = extra.get("duration_ms")

                if status and 500 <= status < 600:
                    five_xx_by_url[url] += 1

                if duration_ms is not None and duration_ms >= 2000:
                    slow_requests.append({
                        "line_number": log["line_number"],
                        "url": url,
                        "duration_ms": duration_ms,
                        "status": status,
                    })

        for ip, count in ip_failures.items():
            if count >= 5:
                anomalies.append({
                    "type": "bruteforce_suspected",
                    "ip": ip,
                    "count": count,
                    "severity": "high" if count >= 10 else "medium"
                })

        for url, count in five_xx_by_url.items():
            if count >= 3:
                anomalies.append({
                    "type": "repeated_server_errors",
                    "url": url,
                    "count": count,
                    "severity": "high" if count >= 5 else "medium"
                })

        if slow_requests:
            anomalies.append({
                "type": "slow_requests_detected",
                "count": len(slow_requests),
                "examples": slow_requests[:10],
                "severity": "medium"
            })

        for sig, count in signature_errors.items():
            if count >= 3:
                anomalies.append({
                    "type": "repeated_error_signature",
                    "signature": sig,
                    "count": count,
                    "severity": "high" if count >= 5 else "medium"
                })

        if result["parsed_lines"] > 0:
            unknown_ratio = result["unknown_lines"] / result["parsed_lines"]
            if unknown_ratio >= 0.2:
                anomalies.append({
                    "type": "high_unknown_ratio",
                    "ratio": round(unknown_ratio, 2),
                    "severity": "medium"
                })

        anomalies.sort(
            key=lambda x: (
                {"high": 0, "medium": 1, "low": 2}.get(x.get("severity", "low"), 3),
                -x.get("count", 0)
            )
        )
        return anomalies

    def parse_file(self, file_path: str | Path) -> dict:
        file_path = Path(file_path)

        result = {
            "file": str(file_path),
            "total_lines": 0,
            "parsed_lines": 0,
            "unknown_lines": 0,
            "logs": [],
            "summary": {
                "system": 0,
                "application": 0,
                "web": 0,
                "security": 0,
                "unknown": 0
            },
            "levels_summary": {
                "INFO": 0,
                "WARNING": 0,
                "ERROR": 0,
                "CRITICAL": 0,
                "DEBUG": 0,
                "TRACE": 0,
                "UNKNOWN": 0
            },
            "templates_summary": {},
            "signatures_summary": {},
            "event_category_summary": {},
            "top_ips": {},
            "top_users": {},
            "top_urls": {},
            "correlations": {},
            "anomalies": []
        }

        template_counter = Counter()
        signature_counter = Counter()
        category_counter = Counter()
        ip_counter = Counter()
        user_counter = Counter()
        url_counter = Counter()

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, raw_line in enumerate(f, start=1):
                result["total_lines"] += 1
                line = raw_line.strip()

                if not line:
                    continue

                parsed = self.parse_line(line, line_no=line_no)
                result["logs"].append(parsed)
                result["parsed_lines"] += 1

                log_type = parsed.get("type", "unknown")
                result["summary"][log_type] = result["summary"].get(log_type, 0) + 1

                level = normalize_level(parsed.get("level", "UNKNOWN"))
                result["levels_summary"][level] = result["levels_summary"].get(level, 0) + 1

                template = parsed.get("template")
                signature = parsed.get("signature")
                category = parsed.get("event_category")
                extra = parsed.get("extra", {}) or {}

                if template:
                    template_counter[template] += 1
                if signature:
                    signature_counter[signature] += 1
                if category:
                    category_counter[category] += 1
                if extra.get("ip"):
                    ip_counter[extra["ip"]] += 1
                if extra.get("user"):
                    user_counter[extra["user"]] += 1
                if extra.get("url"):
                    url_counter[extra["url"]] += 1

                if log_type == "unknown":
                    result["unknown_lines"] += 1

        result["templates_summary"] = dict(template_counter.most_common(20))
        result["signatures_summary"] = dict(signature_counter.most_common(20))
        result["event_category_summary"] = dict(category_counter.most_common(20))
        result["top_ips"] = dict(ip_counter.most_common(20))
        result["top_users"] = dict(user_counter.most_common(20))
        result["top_urls"] = dict(url_counter.most_common(20))
        result["correlations"] = self.correlate_logs(result["logs"])
        result["anomalies"] = self.detect_anomalies(result["logs"], result)

        return {"result": result}


if __name__ == "__main__":
    parser = LogParser()
    print(json.dumps(
        parser.parse_file(r"C:\Users\DERRADJI\Desktop\LOGS_ANALYZER\tests\server.log"),
        indent=2
    ))