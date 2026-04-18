import re
import json
from pathlib import Path


# =========================
# 🔍 DETECTION ENGINE
# =========================
def detect_log_type(line: str) -> str:
    line = line.strip()

    if line.startswith("{") and line.endswith("}"):
        return "application"

    if re.search(r'\"\s*(GET|POST|PUT|DELETE)', line):
        return "web"

    if any(x in line.lower() for x in [
        "failed", "login", "authentication", "ssh", "fail2ban", "invalid user"
    ]):
        return "security"

    if re.match(r"\d{4}-\d{2}-\d{2}", line):
        return "system"

    return "unknown"


# =========================
# 🧱 BASE PARSER
# =========================
class BaseParser:
    def parse(self, line: str) -> dict:
        return {
            "timestamp": None,
            "type": "unknown",
            "level": "INFO",
            "message": line.strip(),
            "extra": {}
        }


# =========================
# 🖥 SYSTEM LOG PARSER
# =========================
class SystemLogParser(BaseParser):
    def parse(self, line: str) -> dict:
        match = re.match(
            r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
            r"(?P<level>INFO|ERROR|WARNING|CRITICAL)\s+(?P<message>.*)",
            line
        )

        if match:
            data = match.groupdict()
            return {
                "timestamp": data["timestamp"],
                "type": "system",
                "level": data["level"],
                "message": data["message"],
                "extra": {}
            }

        return BaseParser().parse(line)


# =========================
# 📦 APPLICATION LOG PARSER
# =========================
class ApplicationLogParser(BaseParser):
    def parse(self, line: str) -> dict:
        try:
            data = json.loads(line)

            return {
                "timestamp": data.get("timestamp"),
                "type": "application",
                "level": data.get("level", "INFO"),
                "message": data.get("message", ""),
                "extra": {
                    k: v for k, v in data.items()
                    if k not in ["timestamp", "level", "message"]
                }
            }
        except:
            return BaseParser().parse(line)


# =========================
# 🌐 WEB LOG PARSER
# =========================
class WebLogParser(BaseParser):
    pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] '
        r'"(?P<method>\S+) (?P<url>\S+) .*?" '
        r'(?P<status>\d+) (?P<size>\d+)'
    )

    def parse(self, line: str) -> dict:
        match = self.pattern.match(line)

        if match:
            data = match.groupdict()
            status = int(data["status"])

            # HTTP → log level mapping
            if 200 <= status < 300:
                level = "INFO"
            elif 300 <= status < 400:
                level = "WARNING"
            elif 400 <= status < 500:
                level = "ERROR"
            else:
                level = "CRITICAL"

            return {
                "timestamp": data["time"],
                "type": "web",
                "level": level,
                "message": f"{data['method']} {data['url']} {data['status']}",
                "extra": data
            }

        return BaseParser().parse(line)


# =========================
# 🔐 SECURITY LOG PARSER
# =========================
class SecurityLogParser(BaseParser):
    def parse(self, line: str) -> dict:
        lower = line.lower()

        if "failed password" in lower or "invalid user" in lower:
            level = "WARNING"
            event = "failed_login"

        elif "fail2ban" in lower:
            level = "INFO"
            event = "ip_blocked"

        elif "authentication failure" in lower:
            level = "WARNING"
            event = "auth_failure"

        else:
            level = "INFO"
            event = "security_event"

        return {
            "timestamp": None,
            "type": "security",
            "level": level,
            "message": line.strip(),
            "extra": {
                "event": event
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
        detected_type = detect_log_type(line)
        parser = self.parsers.get(detected_type, BaseParser())

        result = parser.parse(line)

        # IMPORTANT: keep BOTH values clean
        result["type"] = detected_type
        result["detected_type"] = detected_type

        return result


    def parse_file(self, file_path: str | Path) -> dict:
        file_path = Path(file_path)

        result = {
            "file": str(file_path),
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
                "UNKNOWN": 0
            }
        }

        error_result = []
        critical_result = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                parsed = self.parse_line(line)
                result["logs"].append(parsed)

                log_type = parsed.get("type", "unknown")
                result["summary"][log_type] = result["summary"].get(log_type, 0) + 1

                level = parsed.get("level", "UNKNOWN").upper()
                result["levels_summary"][level] = result["levels_summary"].get(level, 0) + 1

        return {
            "result": result,
        }