"""Optional OTLP/HTTP JSON logs, with no tool input or credential data."""
from __future__ import annotations

import json
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

from .policy import Decision


def emit(endpoint: str | None, tool: str, decision: Decision) -> bool:
    if not endpoint:
        return True
    # Whitelist tool names so arbitrary tool names cannot leak input through telemetry.
    safe_tool = tool if tool in {"Bash", "Read", "Write", "Edit"} else "other"
    attributes = [
        {"key": "tool", "value": {"stringValue": safe_tool}},
        {"key": "decision", "value": {"stringValue": "deny" if decision.denied else "pass"}},
    ]
    # Configurable rule IDs may themselves contain sensitive data; never export them.
    payload = {"resourceLogs": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "claude-security-hook"}}]}, "scopeLogs": [{"scope": {"name": "claude_security"}, "logRecords": [{"timeUnixNano": str(time.time_ns()), "severityNumber": 9, "severityText": "INFO", "body": {"stringValue": "PreToolUse policy decision"}, "attributes": attributes}]}]}]}
    request = Request(endpoint, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=1) as response:
            return 200 <= response.status < 300
    except (URLError, OSError, ValueError):
        return False
