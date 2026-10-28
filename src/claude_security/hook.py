"""Claude Code command hook entry point."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from . import audit
from .policy import evaluate, load_policy


def main() -> int:
    try:
        event: Any = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("expected an object")
        default_policy = Path(__file__).with_name("default_policy.toml")
        policy = load_policy(Path(os.environ.get("CLAUDE_SECURITY_POLICY", str(default_policy))))
        decision = evaluate(event, policy)
    except (ValueError, OSError, re.error, RecursionError):
        # Exit 2 is the documented blocking error for PreToolUse.
        print("Security hook could not evaluate the request.", file=sys.stderr)
        return 2
    try:
        exported = audit.emit(os.environ.get("CLAUDE_SECURITY_OTLP_LOGS_ENDPOINT"), event["tool_name"], decision)
        if not exported:
            print("Security audit export failed.", file=sys.stderr)
    except Exception:
        print("Security audit export failed.", file=sys.stderr)
    if decision.denied:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "Blocked by configured security policy."}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
