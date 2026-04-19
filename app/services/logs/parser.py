import re
import json
from pathlib import Path
from datetime import datetime
from collections import Counter


# =========================
# 🔧 COMMON PATTERNS
# =========================
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
UUID_RE = re.compile(r"\b[0-9a-fA-F-]{32,36}\b")
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
    r"permission denied",
    r"token expired",
    r"jwt",
]

WEB_PATTERNS = [
    r'"\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+',
    r"\bHTTP/\d\.\d\b",
    r"\bstatus\b",
    r"\bresponse_time\b",
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


# =========================
# 🧰 HELPERS
# =========================
def normalize_level(level: str | None) -> str:
    if not level:
        return "UNKNOWN"

    level = level.upper().strip()
    mapping = {
        "WARN": "WARNING",
        "FATAL": "CRITICAL",
    }
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


def extract_ip(text: str) -> str | None:
    m = IPV4_RE.search(text)
    return m.group(0) if m else None


def extract_user(text: str) -> str | None:
    patterns = [
        r"(?:invalid user|user|for user|for)\s+([a-zA-Z0-9._@-]+)",
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
    text = HEX_RE.sub("<HEX>", text)
    text = PATH_RE.sub("<PATH>", text)
    text = NUMBER_RE.sub("<NUM>", text)
    return text


# =========================
# 🔍 DETECTION ENGINE
# =========================
def detect_log_type(line: str) -> dict:
    line = line.strip()
    scores = {
        "application": 0,
        "web": 0,
        "security": 0,
        "system": 0,
    }
    signals = []

    if not line:
        return {"detected_type": "unknown", "confidence": 0.0, "signals": []}

    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
            scores["application"] += 4
            signals.append("json_object")

            if any(k in data for k in ("timestamp", "level", "message")):
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

        return {
            "timestamp": normalize_timestamp(detected_ts),
            "type": "unknown",
            "level": normalize_level(level_match.group(1) if level_match else "UNKNOWN"),
            "message": line.strip(),
            "extra": {
                "ip": extract_ip(line),
                "user": extract_user(line),
                "port": extract_port(line),
            }
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

                return {
                    "timestamp": normalize_timestamp(data.get("timestamp")),
                    "type": "system",
                    "level": level,
                    "message": data.get("message", "").strip(),
                    "extra": {
                        "host": data.get("host"),
                        "service": data.get("service"),
                        "pid": int(data["pid"]) if data.get("pid") else None,
                        "ip": extract_ip(line),
                        "user": extract_user(line),
                    }
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
                extra.setdefault("ip", extract_ip(message))
                extra.setdefault("user", extract_user(message))
                extra.setdefault("port", extract_port(message))

                return {
                    "timestamp": normalize_timestamp(data.get("timestamp")),
                    "type": "application",
                    "level": normalize_level(data.get("level", "INFO")),
                    "message": message,
                    "extra": extra
                }
            except Exception:
                pass

        for pattern in self.patterns:
            match = pattern.match(line)
            if match:
                data = match.groupdict()
                message = data.get("message", "").strip()

                return {
                    "timestamp": normalize_timestamp(data.get("timestamp")),
                    "type": "application",
                    "level": normalize_level(data.get("level") or data.get("level2")),
                    "message": message,
                    "extra": {
                        "ip": extract_ip(message),
                        "user": extract_user(message),
                        "port": extract_port(message),
                    }
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
            r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?',
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
                    level = "WARNING"
                elif 400 <= status < 500:
                    level = "ERROR"
                else:
                    level = "CRITICAL"

                size_raw = data.get("size")
                size = None if size_raw in (None, "-", "") else int(size_raw)

                return {
                    "timestamp": normalize_timestamp(data.get("time")),
                    "type": "web",
                    "level": level,
                    "message": f"{data['method']} {data['url']} {status}",
                    "extra": {
                        "ip": data.get("ip"),
                        "method": data.get("method"),
                        "url": data.get("url"),
                        "protocol": data.get("protocol"),
                        "status": status,
                        "size": size,
                        "referrer": data.get("referrer"),
                        "user_agent": data.get("user_agent"),
                    }
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

        return {
            "timestamp": normalize_timestamp(detect_embedded_timestamp(line)),
            "type": "security",
            "level": level,
            "message": line.strip(),
            "extra": {
                "event": event,
                "ip": ip,
                "user": user,
                "port": port,
                "service": service,
            }
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

    def parse_line(self, line: str) -> dict:
        detection = detect_log_type(line)
        detected_type = detection["detected_type"]
        parser = self.parsers.get(detected_type, BaseParser())

        result = parser.parse(line)
        result["type"] = detected_type
        result["detected_type"] = detected_type
        result["confidence"] = detection["confidence"]
        result["signals"] = detection["signals"]
        result["template"] = make_template(result.get("message", ""))
        result["level"] = normalize_level(result.get("level"))
        result["timestamp"] = normalize_timestamp(result.get("timestamp"))

        if "extra" not in result or not isinstance(result["extra"], dict):
            result["extra"] = {}

        result["extra"].setdefault("ip", extract_ip(line))
        result["extra"].setdefault("user", extract_user(line))
        result["extra"].setdefault("port", extract_port(line))

        return result

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
            "top_ips": {},
            "top_users": {},
            "anomalies": []
        }

        ip_failures = Counter()
        template_counter = Counter()
        ip_counter = Counter()
        user_counter = Counter()

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                result["total_lines"] += 1
                line = raw_line.strip()

                if not line:
                    continue

                parsed = self.parse_line(line)
                result["logs"].append(parsed)
                result["parsed_lines"] += 1

                log_type = parsed.get("type", "unknown")
                result["summary"][log_type] = result["summary"].get(log_type, 0) + 1

                level = normalize_level(parsed.get("level", "UNKNOWN"))
                result["levels_summary"][level] = result["levels_summary"].get(level, 0) + 1

                template = parsed.get("template")
                if template:
                    template_counter[template] += 1

                extra = parsed.get("extra", {})
                ip = extra.get("ip")
                user = extra.get("user")

                if ip:
                    ip_counter[ip] += 1
                if user:
                    user_counter[user] += 1

                if parsed.get("type") == "security" and extra.get("event") == "failed_login" and ip:
                    ip_failures[ip] += 1

                if log_type == "unknown":
                    result["unknown_lines"] += 1

        result["templates_summary"] = dict(template_counter.most_common(20))
        result["top_ips"] = dict(ip_counter.most_common(20))
        result["top_users"] = dict(user_counter.most_common(20))

        for ip, count in ip_failures.items():
            if count >= 5:
                result["anomalies"].append({
                    "type": "bruteforce_suspected",
                    "ip": ip,
                    "count": count,
                    "severity": "high" if count >= 10 else "medium"
                })

        if result["parsed_lines"] > 0:
            unknown_ratio = result["unknown_lines"] / result["parsed_lines"]
            if unknown_ratio >= 0.2:
                result["anomalies"].append({
                    "type": "high_unknown_ratio",
                    "ratio": round(unknown_ratio, 2),
                    "severity": "medium"
                })

        return {"result": result}
