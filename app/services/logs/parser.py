import re
import json
import hashlib
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict


# =========================
# COMMON PATTERNS
# =========================
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){2,}[a-fA-F0-9:]+\b")
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
PATH_RE = re.compile(r"(\/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)+")
NUMBER_RE = re.compile(r"\b\d+\b")
HEX_RE = re.compile(r"\b0x[a-fA-F0-9]+\b")

LEVEL_RE = re.compile(
    r"\b(INFO|ERROR|WARNING|WARN|CRITICAL|DEBUG|TRACE|FATAL|NOTICE|AUDIT)\b",
    re.IGNORECASE
)

COMMENT_PREFIXES = ("#", "//", ";", "--")

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
    r"ban ",
]

WEB_PATTERNS = [
    r'"\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+',
    r"\bHTTP/\d\.\d\b",
    r"\bstatus[=:]\s*\d{3}\b",
    r"\bresponse_time\b",
    r"\brequest_time\b",
    r"\buser_agent\b",
    r"\blatency_ms[=:]\s*\d+\b",
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
        r"\bcustomer[_-]?id[=:]\s*([A-Za-z0-9._-]+)",
        r"\btarget_user[=:]\s*([A-Za-z0-9._-]+)",
        r"\buid[=:]\s*([A-Za-z0-9._-]+)",
    ],
}


# RFC 5424 syslog
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,3})\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>(?:-|\[.*?\]))"
    r"(?:\s+(?P<message>.*))?$"
)

APACHE_COMBINED_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<url>\S+)\s+(?P<protocol>HTTP/\d\.\d)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    r'(?:\s+(?P<trailing_time>\d+(?:\.\d+)?))?$',
    re.IGNORECASE
)

# ---- DATABASE ----
DATABASE_PATTERNS = [
    r"\bpostgres\b", r"\bmysql\b", r"\bmysqld\b", r"\borgdb\b",
    r"\bmongod\b", r"\bredis\b", r"\bsqlite\b",
    r"\bslow query\b", r"\bdeadlock\b", r"\bconnection pool\b",
    r"\baborted connection\b", r"\bquery\b.*\bexecuted\b",
    r"\bINSERT\b", r"\bUPDATE\b", r"\bDELETE\b", r"\bSELECT\b",
    r"\btransaction\b", r"\brollback\b", r"\bcommit\b",
    r"\bduration:\s*\d+", r"\bstatement:",
]

# ---- QUEUE / MESSAGE BROKER ----
QUEUE_PATTERNS = [
    r"\brabbitmq\b", r"\bkafka\b", r"\bcelery\b", r"\bamqp\b",
    r"\bqueue\b", r"\btopic\b", r"\bpartition\b", r"\boffset\b",
    r"\bconsumer\b", r"\bproducer\b", r"\bbroker\b",
    r"\bmessage published\b", r"\bmessage consumed\b",
    r"\blag\b", r"\bdead.?letter\b", r"\bnack\b", r"\back\b",
    r"\bworker\b.*\b(started|stopped|failed)\b",
]

# ---- NETWORK DEVICE (router / switch) ----
NETWORK_DEVICE_PATTERNS = [
    r"\bcisco\b", r"\bjuniper\b", r"\bfortigate\b", r"\bhuawei\b",
    r"\binterface\b.*\b(up|down)\b",
    r"\blink state changed\b", r"\bospf\b", r"\bbgp\b",
    r"\bvlan\b", r"\bspanning.?tree\b", r"\bstp\b",
    r"\barp\b", r"\bport\s+\d+\b.*\b(up|down)\b",
    r"%[A-Z]+-\d+-\w+:",                  # Cisco IOS syslog message ID
    r"\bconfig\s+(changed|saved|loaded)\b",
]

# ---- FIREWALL ----
FIREWALL_PATTERNS = [
    r"\biptables\b", r"\bnftables\b", r"\bpf\b", r"\bpfsense\b",
    r"\bufw\b", r"\bwindows firewall\b",
    r"\bACCEPT\b.*\bDPT=\d+", r"\bDROP\b.*\bDPT=\d+",
    r"\bBLOCKED\b", r"\bALLOWED\b", r"\bDENIED\b",
    r"\bSRC=\S+\s+DST=\S+",
    r"\bIN=\S*\s+OUT=\S*",
    r"\bproto\s+(tcp|udp|icmp)\b",
    r"\bFW-\d+\b",
]

# ---- DOCKER / CONTAINER ----
DOCKER_PATTERNS = [
    r"\bdocker\b", r"\bcontainer\b", r"\bpodman\b", r"\bkubernetes\b",
    r"\bk8s\b", r"\bpod\b", r"\bnamespace\b",
    r"\bimage\b.*\b(pulled|pushed|built)\b",
    r"\bcontainer\b.*\b(started|stopped|killed|restarted|exited)\b",
    r"\bhealth.*check\b", r"\bOOMKilled\b",
    r"\bCrashLoopBackOff\b", r"\bEvicted\b",
]

# ---- WINDOWS / ACTIVE DIRECTORY ----
WINDOWS_AD_PATTERNS = [
    r"\bEventID\b", r"\bEvent ID\b",
    r"\bwinlogon\b", r"\bLSASS\b", r"\bNTLM\b", r"\bKerberos\b",
    r"\bActive Directory\b", r"\bLDAP\b",
    r"\bGroupPolicy\b", r"\bGPO\b",
    r"\bObject Access\b", r"\bLogon Type\b",
    r"\bSecurity Account Manager\b",
    r"\bAccount Logon\b", r"\bAccount Management\b",
    r"\bPrivilege Use\b", r"\bProcess Creation\b",
    r"\bSysmon\b",
    r"EventID[=:\s]+(?:4624|4625|4634|4647|4648|4720|4722|4723|4724|4725|4726|4728|4740|4756|4771|4776|7045)",
]

# ---- CAMERA / IoT ----
CAMERA_PATTERNS = [
    r"\bonvif\b", r"\brtsp\b", r"\bcamera\b",
    r"\bmotion detected\b", r"\brecording\b.*\b(started|stopped)\b",
    r"\bvideo\b.*\b(stream|loss|feed)\b",
    r"\bNVR\b", r"\bDVR\b",
]

# ---- PRINTER ----
PRINTER_PATTERNS = [
    r"\bcups\b", r"\bprinter\b", r"\bprint job\b",
    r"\bIPP\b", r"\bprint queue\b",
    r"\bpaper\b.*\b(jam|out|low)\b",
    r"\btoner\b", r"\bink\b.*\b(low|empty)\b",
    r"\bjob\b.*\b(completed|failed|cancelled)\b",
]


# =========================
# HELPERS
# =========================
def normalize_level(level: str | None) -> str:
    if not level:
        return "UNKNOWN"
    level = level.upper().strip()
    mapping = {
        "WARN": "WARNING",
        "FATAL": "CRITICAL",
        "NOTICE": "INFO",
        "AUDIT": "INFO",
    }
    return mapping.get(level, level)


def normalize_timestamp(value: str | None) -> str | None:
    if not value:
        return None

    value = value.strip()

    if value.endswith("Z"):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
        except Exception:
            pass

    for fmt in TIME_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.isoformat()
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(value).isoformat()
    except Exception:
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
        r"actor=([a-zA-Z0-9._@-]+)",
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
        "request_id": None,
        "trace_id": None,
        "correlation_id": None,
        "session_id": None,
    }
    if isinstance(base, dict):
        fields.update(base)
    return fields


def should_skip_line(line: str) -> tuple[bool, str | None]:
    s = line.strip()
    if not s:
        return True, "empty"

    if s.startswith(COMMENT_PREFIXES):
        return True, "comment"

    if re.match(r"^(=|-|~|\*){3,}", s):
        return True, "separator"

    if re.match(r"^#?\s*=+\s*.+\s*=+$", s):
        return True, "section_header"

    if re.match(r"^#?\s*-{2,}\s*.+\s*-{2,}$", s):
        return True, "section_header"

    if re.match(r"^#?\s*[A-Z][A-Z0-9 /&._()-]{6,}\s*$", s):
        if not detect_embedded_timestamp(s):
            return True, "banner"

    if s.lower() in {"logs", "results", "statistics", "all logs", "users", "system info"}:
        return True, "ui_noise"

    if s.startswith("[") and s.endswith("]") and len(s) < 100:
        return True, "ui_noise"

    return False, None


def looks_like_log(line: str) -> bool:
    if not line:
        return False
    if line.startswith("{") and line.endswith("}"):
        return True
    if RFC5424_RE.match(line):
        return True
    if APACHE_COMBINED_RE.match(line):
        return True
    if detect_embedded_timestamp(line):
        return True
    if LEVEL_RE.search(line):
        return True
    if re.search(r"\b(sshd|systemd|kernel|cron|mysqld|nginx|sudo|fail2ban)\b", line, re.IGNORECASE):
        return True
    return False


# =========================
# DETECTION ENGINE
# =========================
def detect_log_type(line: str) -> dict:
    line = line.strip()
    scores = {
        "application": 0, "web": 0, "security": 0, "system": 0,
        "database": 0, "queue": 0, "network_device": 0,
        "firewall": 0, "container": 0, "windows_ad": 0,
        "camera": 0, "printer": 0,
    }
    signals = []

    if not line:
        return {"detected_type": "unknown", "confidence": 0.0, "signals": []}

    if RFC5424_RE.match(line):
        scores["system"] += 5
        signals.append("rfc5424_syslog")

    if APACHE_COMBINED_RE.match(line):
        scores["web"] += 6
        signals.append("apache_combined")

    if line.startswith("{") and line.endswith("}"):
        try:
            data = json.loads(line)
            scores["application"] += 6
            signals.append("json_object")
            if any(k in data for k in ("timestamp", "level", "message", "service")):
                scores["application"] += 3
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

    for p in DATABASE_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            scores["database"] += 2
            signals.append(f"database:{p}")

    for p in QUEUE_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            scores["queue"] += 2
            signals.append(f"queue:{p}")

    for p in NETWORK_DEVICE_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            scores["network_device"] += 2
            signals.append(f"network_device:{p}")

    for p in FIREWALL_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            scores["firewall"] += 2
            signals.append(f"firewall:{p}")

    for p in DOCKER_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            scores["container"] += 2
            signals.append(f"container:{p}")

    for p in WINDOWS_AD_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            scores["windows_ad"] += 3
            signals.append(f"windows_ad:{p}")

    for p in CAMERA_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            scores["camera"] += 2
            signals.append(f"camera:{p}")

    for p in PRINTER_PATTERNS:
        if re.search(p, line, re.IGNORECASE):
            scores["printer"] += 2
            signals.append(f"printer:{p}")

    if LEVEL_RE.search(line) and detect_embedded_timestamp(line):
        scores["system"] += 2
        scores["application"] += 1
        signals.append("timestamp_and_level")

    best_type = max(scores, key=scores.get)
    best_score = scores[best_type]
    total = sum(scores.values()) or 1

    if best_score < 2:
        return {"detected_type": "unknown", "confidence": 0.0, "signals": []}

    return {
        "detected_type": best_type,
        "confidence": round(best_score / total, 2),
        "signals": signals,
    }

# =========================
# BASE PARSER
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
# SYSTEM LOG PARSER
# =========================
class SystemLogParser(BaseParser):
    patterns = [
        re.compile(
            r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+"
            r"(?P<level>INFO|ERROR|WARNING|WARN|CRITICAL|DEBUG|TRACE|FATAL|NOTICE|AUDIT)\s+"
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
        m5424 = RFC5424_RE.match(line)
        if m5424:
            data = m5424.groupdict()
            message = (data.get("message") or "").strip()
            level_match = LEVEL_RE.search(message)
            level = normalize_level(level_match.group(1) if level_match else "INFO")

            extra = build_unified_extra({
                "host": None if data.get("host") == "-" else data.get("host"),
                "service": None if data.get("app") == "-" else data.get("app"),
                "pid": None if data.get("procid") in (None, "-") else data.get("procid"),
                "ip": extract_ip(message),
                "user": extract_user(message),
            })

            return {
                "timestamp": data.get("timestamp"),
                "normalized_timestamp": normalize_timestamp(data.get("timestamp")),
                "type": "system",
                "level": level,
                "message": message,
                "extra": extra,
            }

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
# APPLICATION LOG PARSER
# =========================
class ApplicationLogParser(BaseParser):
    patterns = [
        re.compile(
            r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
            r"(?:\[(?P<level>INFO|ERROR|WARNING|WARN|CRITICAL|DEBUG|TRACE|FATAL|NOTICE|AUDIT)\]"
            r"|(?P<level2>INFO|ERROR|WARNING|WARN|CRITICAL|DEBUG|TRACE|FATAL|NOTICE|AUDIT))\s+"
            r"(?P<service>\S+)\s+"
            r"(?P<message>.*)",
            re.IGNORECASE
        ),
        re.compile(
            r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
            r"(?:\[(?P<level>INFO|ERROR|WARNING|WARN|CRITICAL|DEBUG|TRACE|FATAL|NOTICE|AUDIT)\]"
            r"|(?P<level2>INFO|ERROR|WARNING|WARN|CRITICAL|DEBUG|TRACE|FATAL|NOTICE|AUDIT))\s+"
            r"(?P<message>.*)",
            re.IGNORECASE
        ),
    ]

    def parse(self, line: str) -> dict:
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                message = str(data.get("message", "")).strip()

                extra = {k: v for k, v in data.items()
                         if k not in {"timestamp", "level", "message", "type"}}
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

                if extra.get("duration_ms") and not extra.get("duration_s"):
                    try:
                        extra["duration_s"] = round(float(extra["duration_ms"]) / 1000, 6)
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
                    "service": data.get("service"),
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
# WEB LOG PARSER
# =========================
class WebLogParser(BaseParser):
    def parse(self, line: str) -> dict:
        match = APACHE_COMBINED_RE.match(line)
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
# SECURITY LOG PARSER
# =========================
class SecurityLogParser(BaseParser):
    def parse(self, line: str) -> dict:
        lower = line.lower()
        ip = extract_ip(line)
        user = extract_user(line)
        port = extract_port(line)

        if "failed password" in lower or "invalid user" in lower:
            level, event = "WARNING", "failed_login"
        elif "accepted password" in lower or "session opened" in lower:
            level, event = "INFO", "successful_login"
        elif "fail2ban" in lower and ("ban" in lower):
            level, event = "WARNING", "ip_blocked"
        elif "fail2ban" in lower:
            level, event = "INFO", "ip_blocked"
        elif "authentication failure" in lower:
            level, event = "WARNING", "auth_failure"
        elif "permission denied" in lower or "access denied" in lower:
            level, event = "ERROR", "access_denied"
        elif "jwt" in lower or "token expired" in lower:
            level, event = "WARNING", "token_issue"
        elif "session closed" in lower:
            level, event = "INFO", "session_closed"
        elif "sudo:" in lower:
            level, event = "INFO", "sudo_event"
        else:
            level, event = "INFO", "security_event"

        service = None
        for svc in ("sshd", "sudo", "pam_unix", "fail2ban"):
            if svc in lower:
                service = svc
                break

        ts = detect_embedded_timestamp(line)
        extra = build_unified_extra({
            "event": event,
            "ip": ip,
            "user": user,
            "port": port,
            "service": service,
        })

        return {
            "timestamp": ts,
            "normalized_timestamp": normalize_timestamp(ts),
            "type": "security",
            "level": level,
            "message": line.strip(),
            "extra": extra,
        }


# =========================
# 🗄 DATABASE LOG PARSER
# =========================
class DatabaseLogParser(BaseParser):
    # PostgreSQL: 2026-04-20 06:00:01.123 UTC [1234] user@db ERROR: ...
    PG_RE = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+\w+\s+"
        r"\[(?P<pid>\d+)\]\s+(?P<user>\S+)@(?P<db>\S+)\s+"
        r"(?P<level>INFO|ERROR|WARNING|WARN|CRITICAL|DEBUG|FATAL|NOTICE|LOG):\s+"
        r"(?P<message>.*)",
        re.IGNORECASE
    )

    # MySQL: 2026-04-20T06:00:01.123456Z 5 [ERROR] [MY-000000] [Server] message
    MYSQL_RE = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
        r"(?P<thread>\d+)\s+"
        r"\[(?P<level>ERROR|Warning|Note|System)\]\s+"
        r"(?:\[[\w-]+\]\s+){0,2}"
        r"(?P<message>.*)",
        re.IGNORECASE
    )

    # Generic slow query: # Time: 2026-04-20T06:00:01.000000Z / Query_time: 5.123
    SLOW_QUERY_RE = re.compile(
        r"#\s*(?:Time:\s*(?P<timestamp>\S+))?"
        r"|#\s*Query_time:\s*(?P<qtime>\d+\.\d+)"
        r"|#\s*User@Host:\s*(?P<user>\S+)\s*@\s*(?P<host>\S+)"
    )

    def parse(self, line: str) -> dict:
        for pattern, db_type in [(self.PG_RE, "postgresql"), (self.MYSQL_RE, "mysql")]:
            m = pattern.match(line)
            if m:
                data = m.groupdict()
                extra = build_unified_extra({
                    "service": db_type,
                    "pid": int(data["pid"]) if data.get("pid") else None,
                    "user": data.get("user"),
                    "ip": extract_ip(line),
                })
                return {
                    "timestamp": data.get("timestamp"),
                    "normalized_timestamp": normalize_timestamp(data.get("timestamp")),
                    "type": "database",
                    "level": normalize_level(data.get("level")),
                    "message": data.get("message", "").strip(),
                    "extra": extra,
                }

        # Fallback: base parse for mysqld / generic DB lines
        ts = detect_embedded_timestamp(line)
        level_m = LEVEL_RE.search(line)
        extra = build_unified_extra({
            "ip": extract_ip(line),
            "user": extract_user(line),
        })
        return {
            "timestamp": ts,
            "normalized_timestamp": normalize_timestamp(ts),
            "type": "database",
            "level": normalize_level(level_m.group(1) if level_m else "INFO"),
            "message": line.strip(),
            "extra": extra,
        }


# =========================
# 📨 QUEUE LOG PARSER
# =========================
class QueueLogParser(BaseParser):
    # RabbitMQ: 2026-04-20 06:00:01.123 [info] <0.123.0> message
    RABBIT_RE = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+"
        r"\[(?P<level>info|warning|error|debug|critical)\]\s+"
        r"<(?P<pid>[^>]+)>\s+"
        r"(?P<message>.*)",
        re.IGNORECASE
    )

    # Kafka: [2026-04-20 06:00:01,123] INFO message (kafka.server.KafkaServer)
    KAFKA_RE = re.compile(
        r"\[(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\]\s+"
        r"(?P<level>INFO|ERROR|WARN|DEBUG|FATAL)\s+"
        r"(?P<message>.*?)"
        r"(?:\s+\((?P<component>[^)]+)\))?$",
        re.IGNORECASE
    )

    def parse(self, line: str) -> dict:
        for pattern, svc in [(self.RABBIT_RE, "rabbitmq"), (self.KAFKA_RE, "kafka")]:
            m = pattern.match(line)
            if m:
                data = m.groupdict()
                extra = build_unified_extra({
                    "service": svc,
                    "ip": extract_ip(line),
                    "user": extract_user(line),
                })
                return {
                    "timestamp": data.get("timestamp"),
                    "normalized_timestamp": normalize_timestamp(data.get("timestamp")),
                    "type": "queue",
                    "level": normalize_level(data.get("level")),
                    "message": data.get("message", "").strip(),
                    "extra": extra,
                }

        ts = detect_embedded_timestamp(line)
        level_m = LEVEL_RE.search(line)
        return {
            "timestamp": ts,
            "normalized_timestamp": normalize_timestamp(ts),
            "type": "queue",
            "level": normalize_level(level_m.group(1) if level_m else "INFO"),
            "message": line.strip(),
            "extra": build_unified_extra({"ip": extract_ip(line)}),
        }


# =========================
# 🌐 NETWORK DEVICE LOG PARSER (Router/Switch)
# =========================
class NetworkDeviceLogParser(BaseParser):
    # Cisco IOS: Apr 20 06:00:01: %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to up
    CISCO_RE = re.compile(
        r"(?:(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
        r"(?:\s+\S+)?:\s+)?"
        r"(?P<msgid>%[A-Z0-9]+-\d+-[A-Z0-9_]+):\s*"
        r"(?P<message>.*)"
    )

    def parse(self, line: str) -> dict:
        m = self.CISCO_RE.search(line)
        if m:
            data = m.groupdict()
            msgid = data.get("msgid", "")

            # Derive severity from Cisco severity digit in message ID
            severity_map = {
                "0": "CRITICAL", "1": "CRITICAL", "2": "CRITICAL",
                "3": "ERROR", "4": "WARNING", "5": "NOTICE",
                "6": "INFO", "7": "DEBUG",
            }
            sev_match = re.search(r"%-(\d)-", msgid)
            level = severity_map.get(sev_match.group(1), "INFO") if sev_match else "INFO"

            extra = build_unified_extra({
                "ip": extract_ip(line),
                "service": "cisco-ios",
            })
            return {
                "timestamp": data.get("timestamp"),
                "normalized_timestamp": normalize_timestamp(data.get("timestamp")),
                "type": "network_device",
                "level": level,
                "message": f"{msgid}: {data.get('message', '').strip()}",
                "extra": extra,
            }

        ts = detect_embedded_timestamp(line)
        level_m = LEVEL_RE.search(line)
        return {
            "timestamp": ts,
            "normalized_timestamp": normalize_timestamp(ts),
            "type": "network_device",
            "level": normalize_level(level_m.group(1) if level_m else "INFO"),
            "message": line.strip(),
            "extra": build_unified_extra({"ip": extract_ip(line)}),
        }


# =========================
# 🔥 FIREWALL LOG PARSER
# =========================
class FirewallLogParser(BaseParser):
    # iptables/ufw: Apr 20 06:00:01 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP DPT=22
    IPTABLES_RE = re.compile(
        r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+\S+:\s+"
        r"(?:\[(?P<action>[^\]]+)\]\s+)?"
        r"IN=(?P<in_if>\S*)\s+OUT=(?P<out_if>\S*)\s+"
        r".*?SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+)\s+"
        r".*?PROTO=(?P<proto>\S+)"
        r"(?:.*?DPT=(?P<dpt>\d+))?",
        re.IGNORECASE
    )

    def parse(self, line: str) -> dict:
        m = self.IPTABLES_RE.search(line)
        if m:
            data = m.groupdict()
            action = (data.get("action") or "").upper()

            if any(w in action for w in ("BLOCK", "DROP", "DENY", "REJECT")):
                level = "WARNING"
                event = "packet_blocked"
            elif any(w in action for w in ("ACCEPT", "ALLOW", "PASS")):
                level = "INFO"
                event = "packet_allowed"
            else:
                level = "INFO"
                event = "firewall_event"

            port = int(data["dpt"]) if data.get("dpt") else None
            extra = build_unified_extra({
                "ip": data.get("src"),
                "port": port,
                "protocol": data.get("proto"),
                "event": event,
                "host": data.get("host"),
                "service": "firewall",
            })
            return {
                "timestamp": data.get("timestamp"),
                "normalized_timestamp": normalize_timestamp(data.get("timestamp")),
                "type": "firewall",
                "level": level,
                "message": line.strip(),
                "extra": extra,
            }

        ts = detect_embedded_timestamp(line)
        lower = line.lower()
        if "drop" in lower or "block" in lower or "deny" in lower:
            level, event = "WARNING", "packet_blocked"
        elif "accept" in lower or "allow" in lower:
            level, event = "INFO", "packet_allowed"
        else:
            level, event = "INFO", "firewall_event"

        return {
            "timestamp": ts,
            "normalized_timestamp": normalize_timestamp(ts),
            "type": "firewall",
            "level": level,
            "message": line.strip(),
            "extra": build_unified_extra({
                "ip": extract_ip(line),
                "event": event,
                "service": "firewall",
            }),
        }


# =========================
# 🐳 DOCKER / CONTAINER LOG PARSER
# =========================
class DockerLogParser(BaseParser):
    # Docker JSON log driver: {"log":"message\n","stream":"stdout","time":"2026-04-20T06:00:01.123Z"}
    DOCKER_JSON_RE = re.compile(
        r'^\{"log":"(?P<message>.*?)(?:\\n)?","stream":"(?P<stream>stdout|stderr)",'
        r'"time":"(?P<timestamp>[^"]+)"\}$'
    )

    # Docker daemon: time="2026-04-20T06:00:01Z" level=info msg="message" container=abc123
    DAEMON_RE = re.compile(
        r'time="(?P<timestamp>[^"]+)"\s+level=(?P<level>\w+)\s+msg="(?P<message>[^"]+)"'
        r'(?:\s+container=(?P<container>\S+))?'
        r'(?:\s+image=(?P<image>\S+))?'
    )

    def parse(self, line: str) -> dict:
        # JSON log driver
        m = self.DOCKER_JSON_RE.match(line)
        if m:
            data = m.groupdict()
            stream = data.get("stream", "stdout")
            level = "ERROR" if stream == "stderr" else "INFO"
            return {
                "timestamp": data.get("timestamp"),
                "normalized_timestamp": normalize_timestamp(data.get("timestamp")),
                "type": "container",
                "level": level,
                "message": data.get("message", "").strip(),
                "extra": build_unified_extra({"service": "docker"}),
            }

        # Daemon log format
        m = self.DAEMON_RE.search(line)
        if m:
            data = m.groupdict()
            extra = build_unified_extra({
                "service": data.get("container") or "docker",
                "ip": extract_ip(line),
            })
            return {
                "timestamp": data.get("timestamp"),
                "normalized_timestamp": normalize_timestamp(data.get("timestamp")),
                "type": "container",
                "level": normalize_level(data.get("level")),
                "message": data.get("message", "").strip(),
                "extra": extra,
            }

        ts = detect_embedded_timestamp(line)
        level_m = LEVEL_RE.search(line)
        return {
            "timestamp": ts,
            "normalized_timestamp": normalize_timestamp(ts),
            "type": "container",
            "level": normalize_level(level_m.group(1) if level_m else "INFO"),
            "message": line.strip(),
            "extra": build_unified_extra({"service": "docker"}),
        }



class WindowsADLogParser(BaseParser):
    # Windows Event Log export format:
    # 2026-04-20 06:00:01, Security, EventID 4624, Account Logon, SUCCESS, user=jdoe ip=10.0.0.5
    WINDOWS_RE = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s*,?\s*"
        r"(?P<channel>Security|System|Application|Setup|ForwardedEvents)?\s*,?\s*"
        r"(?:EventID\s*[=:]?\s*(?P<event_id>\d+))?"
        r"(?:\s*,\s*(?P<category>[^,]+))?"
        r"(?:\s*,\s*(?P<result>SUCCESS|FAILURE|AUDIT_SUCCESS|AUDIT_FAILURE))?"
        r"(?P<message>.*)",
        re.IGNORECASE
    )

    # Critical EventIDs for AD security
    CRITICAL_EVENT_IDS = {
        "4625": ("WARNING", "failed_logon"),
        "4624": ("INFO", "successful_logon"),
        "4634": ("INFO", "logoff"),
        "4648": ("WARNING", "explicit_credential_logon"),
        "4720": ("WARNING", "user_account_created"),
        "4722": ("INFO", "user_account_enabled"),
        "4723": ("WARNING", "password_change_attempt"),
        "4724": ("WARNING", "password_reset"),
        "4725": ("WARNING", "user_account_disabled"),
        "4726": ("ERROR", "user_account_deleted"),
        "4728": ("WARNING", "member_added_to_group"),
        "4740": ("ERROR", "account_locked_out"),
        "4756": ("WARNING", "member_added_to_universal_group"),
        "4771": ("WARNING", "kerberos_pre_auth_failed"),
        "4776": ("WARNING", "ntlm_auth_failed"),
        "7045": ("WARNING", "new_service_installed"),
    }

    def parse(self, line: str) -> dict:
        event_id_m = re.search(r"\bEventID[=:\s]+(\d+)", line, re.IGNORECASE)
        event_id = event_id_m.group(1) if event_id_m else None

        level = "INFO"
        event = "windows_event"

        if event_id and event_id in self.CRITICAL_EVENT_IDS:
            level, event = self.CRITICAL_EVENT_IDS[event_id]
        elif "failure" in line.lower() or "failed" in line.lower():
            level = "WARNING"
            event = "auth_failure"
        elif "locked" in line.lower():
            level = "ERROR"
            event = "account_locked"

        m = self.WINDOWS_RE.match(line)
        ts = None
        if m:
            data = m.groupdict()
            ts = data.get("timestamp")

        ts = ts or detect_embedded_timestamp(line)
        extra = build_unified_extra({
            "ip": extract_ip(line),
            "user": extract_user(line),
            "event": event,
            "service": "windows-ad",
        })

        return {
            "timestamp": ts,
            "normalized_timestamp": normalize_timestamp(ts),
            "type": "windows_ad",
            "level": level,
            "message": line.strip(),
            "extra": extra,
        }



class CameraLogParser(BaseParser):
    def parse(self, line: str) -> dict:
        lower = line.lower()
        ts = detect_embedded_timestamp(line)

        if "motion detected" in lower:
            level, event = "WARNING", "motion_detected"
        elif "recording started" in lower:
            level, event = "INFO", "recording_started"
        elif "recording stopped" in lower:
            level, event = "INFO", "recording_stopped"
        elif "video loss" in lower or "stream lost" in lower:
            level, event = "ERROR", "video_loss"
        elif "connection" in lower and ("lost" in lower or "failed" in lower):
            level, event = "ERROR", "connection_lost"
        else:
            level_m = LEVEL_RE.search(line)
            level = normalize_level(level_m.group(1) if level_m else "INFO")
            event = "camera_event"

        return {
            "timestamp": ts,
            "normalized_timestamp": normalize_timestamp(ts),
            "type": "camera",
            "level": level,
            "message": line.strip(),
            "extra": build_unified_extra({
                "ip": extract_ip(line),
                "event": event,
                "service": "camera",
            }),
        }


class PrinterLogParser(BaseParser):
    def parse(self, line: str) -> dict:
        lower = line.lower()
        ts = detect_embedded_timestamp(line)

        if "paper jam" in lower:
            level, event = "ERROR", "paper_jam"
        elif "paper out" in lower or "paper empty" in lower:
            level, event = "ERROR", "paper_out"
        elif "toner low" in lower or "ink low" in lower:
            level, event = "WARNING", "supplies_low"
        elif "toner empty" in lower or "ink empty" in lower:
            level, event = "ERROR", "supplies_empty"
        elif "job completed" in lower:
            level, event = "INFO", "job_completed"
        elif "job failed" in lower or "job cancelled" in lower:
            level, event = "WARNING", "job_failed"
        elif "offline" in lower or "unreachable" in lower:
            level, event = "ERROR", "printer_offline"
        else:
            level_m = LEVEL_RE.search(line)
            level = normalize_level(level_m.group(1) if level_m else "INFO")
            event = "printer_event"

        return {
            "timestamp": ts,
            "normalized_timestamp": normalize_timestamp(ts),
            "type": "printer",
            "level": level,
            "message": line.strip(),
            "extra": build_unified_extra({
                "ip": extract_ip(line),
                "event": event,
                "service": "printer",
            }),
        }


class LogParser:
    def __init__(self):
        self.parsers = {
            "system":         SystemLogParser(),
            "application":    ApplicationLogParser(),
            "web":            WebLogParser(),
            "security":       SecurityLogParser(),
            "database":       DatabaseLogParser(),
            "queue":          QueueLogParser(),
            "network_device": NetworkDeviceLogParser(),
            "firewall":       FirewallLogParser(),
            "container":      DockerLogParser(),
            "windows_ad":     WindowsADLogParser(),
            "camera":         CameraLogParser(),
            "printer":        PrinterLogParser(),
        }

    def enrich_record(self, raw_line: str, parsed: dict, line_no: int) -> dict:
        parsed["type"] = parsed.get("type", "unknown")
        parsed["detected_type"] = parsed.get("type", "unknown")
        parsed["level"] = normalize_level(parsed.get("level"))
        parsed["timestamp"] = parsed.get("timestamp")
        parsed["normalized_timestamp"] = normalize_timestamp(
            parsed.get("normalized_timestamp") or parsed.get("timestamp")
        )

        if "extra" not in parsed or not isinstance(parsed["extra"], dict):
            parsed["extra"] = build_unified_extra()
        else:
            parsed["extra"] = build_unified_extra(parsed["extra"])

        parsed["extra"]["ip"]   = parsed["extra"].get("ip")   or extract_ip(raw_line)
        parsed["extra"]["user"] = parsed["extra"].get("user") or extract_user(raw_line)
        parsed["extra"]["port"] = parsed["extra"].get("port") or extract_port(raw_line)

        parsed["template"]  = make_template(parsed.get("message", ""))
        parsed["signature"] = make_signature(parsed["type"], parsed["level"], parsed["template"])
        parsed["line_number"] = line_no

        corr = extract_correlation_fields(raw_line, parsed["extra"])
        parsed["correlation"] = corr

        parsed["event_category"] = self.classify_event_category(parsed)
        parsed["epoch"] = to_epoch(parsed.get("normalized_timestamp"))

        return parsed

    def classify_event_category(self, record: dict) -> str:
        log_type = record.get("type")
        level    = record.get("level")
        extra    = record.get("extra", {}) or {}

        if log_type == "security":
            return extra.get("event") or "security_event"

        if log_type == "web":
            status = extra.get("status")
            if status is not None:
                if 500 <= status < 600: return "server_error"
                if 400 <= status < 500: return "client_error"
                if 300 <= status < 400: return "redirect"
                return "request"

        if log_type == "application":
            return "app_error" if level in {"ERROR", "CRITICAL"} else "app_event"

        if log_type == "system":
            return "system_error" if level in {"ERROR", "CRITICAL"} else "system_event"

        if log_type == "database":
            return "db_error" if level in {"ERROR", "CRITICAL"} else "db_event"

        if log_type == "queue":
            return "queue_error" if level in {"ERROR", "CRITICAL"} else "queue_event"

        if log_type == "network_device":
            return "network_error" if level in {"ERROR", "CRITICAL"} else "network_event"

        if log_type == "firewall":
            return extra.get("event") or "firewall_event"

        if log_type == "container":
            return "container_error" if level in {"ERROR", "CRITICAL"} else "container_event"

        if log_type == "windows_ad":
            return extra.get("event") or "windows_event"

        if log_type == "camera":
            return extra.get("event") or "camera_event"

        if log_type == "printer":
            return extra.get("event") or "printer_event"

        return "unknown_event"

    def parse_line(self, line: str, line_no: int = 0) -> dict:
        if not looks_like_log(line):
            base = BaseParser().parse(line)
            base["type"]       = "unknown"
            base["confidence"] = 0.0
            base["signals"]    = []
            return self.enrich_record(line, base, line_no)

        detection    = detect_log_type(line)
        detected_type = detection["detected_type"]
        parser       = self.parsers.get(detected_type, BaseParser())

        parsed = parser.parse(line)
        parsed["type"]       = detected_type
        parsed["confidence"] = detection["confidence"]
        parsed["signals"]    = detection["signals"]

        return self.enrich_record(line, parsed, line_no)

    def correlate_logs(self, logs: list[dict]) -> dict:
        groups = {
            "request_id":    defaultdict(list),
            "trace_id":      defaultdict(list),
            "correlation_id":defaultdict(list),
            "session_id":    defaultdict(list),
            "user_id":       defaultdict(list),
            "ip":            defaultdict(list),
            "user":          defaultdict(list),
        }

        for log in logs:
            corr  = log.get("correlation", {}) or {}
            extra = log.get("extra", {}) or {}

            for key in ("request_id", "trace_id", "correlation_id", "session_id", "user_id"):
                value = corr.get(key)
                if value:
                    groups[key][value].append(log["line_number"])

            if extra.get("ip"):
                groups["ip"][extra["ip"]].append(log["line_number"])
            if extra.get("user"):
                groups["user"][extra["user"]].append(log["line_number"])

        return {
            key: {k: v for k, v in bucket.items() if len(v) >= 2}
            for key, bucket in groups.items()
        }

    def detect_anomalies(self, logs: list[dict], result: dict) -> list[dict]:
        anomalies        = []
        ip_failures      = Counter()
        signature_errors = Counter()
        slow_requests    = []
        five_xx_by_url   = Counter()
        fw_blocks_by_ip  = Counter()
        db_slow_queries  = []
        queue_errors     = Counter()
        ad_lockouts      = Counter()
        container_crashes= Counter()

        for log in logs:
            extra     = log.get("extra", {}) or {}
            sig       = log.get("signature")
            level     = log.get("level")
            log_type  = log.get("type")
            event_cat = log.get("event_category", "")

            if level in {"ERROR", "CRITICAL"} and sig:
                signature_errors[sig] += 1

            # Security: brute-force
            if log_type == "security" and extra.get("event") == "failed_login" and extra.get("ip"):
                ip_failures[extra["ip"]] += 1

            # Web: slow + 5xx
            if log_type == "web":
                status      = extra.get("status")
                url         = extra.get("url") or "<unknown>"
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

            # Firewall: repeated blocks per IP
            if log_type == "firewall" and extra.get("event") == "packet_blocked" and extra.get("ip"):
                fw_blocks_by_ip[extra["ip"]] += 1

            # Database: slow queries (duration > 1s)
            if log_type == "database":
                dur = extra.get("duration_ms") or extra.get("duration_s")
                if dur:
                    try:
                        ms = float(dur) if extra.get("duration_ms") else float(dur) * 1000
                        if ms >= 1000:
                            db_slow_queries.append({
                                "line_number": log["line_number"],
                                "duration_ms": ms,
                                "message": log.get("message", "")[:120],
                            })
                    except Exception:
                        pass

            # Queue: repeated errors per signature
            if log_type == "queue" and level in {"ERROR", "CRITICAL"} and sig:
                queue_errors[sig] += 1

            # Windows AD: account lockouts
            if log_type == "windows_ad" and extra.get("event") == "account_locked_out":
                user = extra.get("user") or "unknown"
                ad_lockouts[user] += 1

            # Container: crash loops / OOM
            if log_type == "container" and level in {"ERROR", "CRITICAL"}:
                svc = extra.get("service") or "unknown"
                container_crashes[svc] += 1

        # --- Emit anomalies ---
        for ip, count in ip_failures.items():
            if count >= 5:
                anomalies.append({
                    "type": "bruteforce_suspected",
                    "ip": ip, "count": count,
                    "severity": "high" if count >= 10 else "medium",
                })

        for url, count in five_xx_by_url.items():
            if count >= 3:
                anomalies.append({
                    "type": "repeated_server_errors",
                    "url": url, "count": count,
                    "severity": "high" if count >= 5 else "medium",
                })

        if slow_requests:
            anomalies.append({
                "type": "slow_requests_detected",
                "count": len(slow_requests),
                "examples": slow_requests[:10],
                "severity": "medium",
            })

        for sig, count in signature_errors.items():
            if count >= 3:
                anomalies.append({
                    "type": "repeated_error_signature",
                    "signature": sig, "count": count,
                    "severity": "high" if count >= 5 else "medium",
                })

        for ip, count in fw_blocks_by_ip.items():
            if count >= 5:
                anomalies.append({
                    "type": "firewall_repeated_blocks",
                    "ip": ip, "count": count,
                    "severity": "high" if count >= 10 else "medium",
                })

        if db_slow_queries:
            anomalies.append({
                "type": "slow_db_queries_detected",
                "count": len(db_slow_queries),
                "examples": db_slow_queries[:10],
                "severity": "medium",
            })

        for sig, count in queue_errors.items():
            if count >= 3:
                anomalies.append({
                    "type": "repeated_queue_errors",
                    "signature": sig, "count": count,
                    "severity": "medium",
                })

        for user, count in ad_lockouts.items():
            anomalies.append({
                "type": "ad_account_lockout",
                "user": user, "count": count,
                "severity": "high",
            })

        for svc, count in container_crashes.items():
            if count >= 3:
                anomalies.append({
                    "type": "container_repeated_errors",
                    "service": svc, "count": count,
                    "severity": "high" if count >= 5 else "medium",
                })

        if result["parsed_lines"] > 0:
            unknown_ratio = result["unknown_lines"] / result["parsed_lines"]
            if unknown_ratio >= 0.2:
                anomalies.append({
                    "type": "high_unknown_ratio",
                    "ratio": round(unknown_ratio, 2),
                    "severity": "medium",
                })

        anomalies.sort(key=lambda x: (
            {"high": 0, "medium": 1, "low": 2}.get(x.get("severity", "low"), 3),
            -x.get("count", 0),
        ))
        return anomalies

    def parse_file(self, file_path: str | Path) -> dict:
        file_path = Path(file_path)

        result = {
            "file": str(file_path),
            "total_lines":   0,
            "parsed_lines":  0,
            "unknown_lines": 0,
            "skipped_lines": [],
            "logs":          [],
            "summary": {
                "system": 0, "application": 0, "web": 0, "security": 0,
                "database": 0, "queue": 0, "network_device": 0,
                "firewall": 0, "container": 0, "windows_ad": 0,
                "camera": 0, "printer": 0, "unknown": 0,
            },
            "levels_summary": {
                "INFO": 0, "WARNING": 0, "ERROR": 0,
                "CRITICAL": 0, "DEBUG": 0, "TRACE": 0, "UNKNOWN": 0,
            },
            "templates_summary":     {},
            "signatures_summary":    {},
            "event_category_summary":{},
            "top_ips":     {},
            "top_users":   {},
            "top_urls":    {},
            "correlations":{},
            "anomalies":   [],
        }

        template_counter = Counter()
        signature_counter = Counter()
        category_counter  = Counter()
        ip_counter        = Counter()
        user_counter      = Counter()
        url_counter       = Counter()

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, raw_line in enumerate(f, start=1):
                result["total_lines"] += 1
                line = raw_line.strip()

                if not line:
                    continue

                skip, reason = should_skip_line(line)
                if skip:
                    result["skipped_lines"].append({
                        "line_number": line_no,
                        "reason":  reason,
                        "content": line,
                    })
                    continue

                parsed = self.parse_line(line, line_no=line_no)
                result["logs"].append(parsed)
                result["parsed_lines"] += 1

                log_type = parsed.get("type", "unknown")
                result["summary"][log_type] = result["summary"].get(log_type, 0) + 1

                level = normalize_level(parsed.get("level", "UNKNOWN"))
                result["levels_summary"][level] = result["levels_summary"].get(level, 0) + 1

                template  = parsed.get("template")
                signature = parsed.get("signature")
                category  = parsed.get("event_category")
                extra     = parsed.get("extra", {}) or {}

                if template:   template_counter[template]   += 1
                if signature:  signature_counter[signature] += 1
                if category:   category_counter[category]   += 1
                if extra.get("ip"):   ip_counter[extra["ip"]]     += 1
                if extra.get("user"): user_counter[extra["user"]] += 1
                if extra.get("url"):  url_counter[extra["url"]]   += 1

                if log_type == "unknown":
                    result["unknown_lines"] += 1

        result["templates_summary"]      = dict(template_counter.most_common(20))
        result["signatures_summary"]     = dict(signature_counter.most_common(20))
        result["event_category_summary"] = dict(category_counter.most_common(20))
        result["top_ips"]   = dict(ip_counter.most_common(20))
        result["top_users"] = dict(user_counter.most_common(20))
        result["top_urls"]  = dict(url_counter.most_common(20))
        result["correlations"] = self.correlate_logs(result["logs"])
        result["anomalies"]    = self.detect_anomalies(result["logs"], result)

        return {"result": result}
