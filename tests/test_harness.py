from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
from unittest.mock import patch

import pytest

from claude_security import audit
from claude_security.policy import Decision, evaluate, load_policy
from claude_security.scenarios import run

POLICY = Path(__file__).parents[1] / "src/claude_security/default_policy.toml"


def event(tool: str, inputs: dict[str, str], cwd: Path) -> dict[str, Any]:
    return {"session_id": "test", "transcript_path": str(cwd / "transcript.jsonl"), "cwd": str(cwd), "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": inputs, "tool_use_id": "test"}


def hook(payload: str, **env: str) -> subprocess.CompletedProcess[str]:
    clean = os.environ.copy()
    clean.pop("CLAUDE_SECURITY_POLICY", None)
    clean.pop("CLAUDE_SECURITY_OTLP_LOGS_ENDPOINT", None)
    clean.update(env)
    return subprocess.run([sys.executable, "-m", "claude_security.hook"], input=payload, text=True, capture_output=True, env=clean, check=False)


def test_deny_contract_and_pass(tmp_path: Path) -> None:
    denied = hook(json.dumps(event("Read", {"file_path": ".env"}, tmp_path)))
    assert denied.returncode == 0
    out = json.loads(denied.stdout)["hookSpecificOutput"]
    assert out == {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "Blocked by configured security policy."}
    allowed = hook(json.dumps(event("Bash", {"command": "printf hello"}, tmp_path)))
    assert allowed.returncode == 0 and not allowed.stdout


def test_invalid_input_blocks(tmp_path: Path) -> None:
    for payload in ("not json", "{}", json.dumps(event("Bash", {}, tmp_path))):
        result = hook(payload)
        assert result.returncode == 2 and not result.stdout
    result = hook(json.dumps(event("Bash", {"command": "true"}, tmp_path)), CLAUDE_SECURITY_POLICY=str(tmp_path / "missing"))
    assert result.returncode == 2


def test_paths_and_config(tmp_path: Path) -> None:
    config = tmp_path / "policy.toml"
    config.write_text('protected_names = ["secret"]\nprotected_paths = ["private"]\n[[shell_rules]]\nid = "example"\npattern = "forbidden"\n', encoding="utf-8")
    policy = load_policy(config)
    (tmp_path / "secret").write_text("fake", encoding="utf-8")
    (tmp_path / "link").symlink_to(tmp_path / "secret")
    for name in ("secret", "link", "private/nested"):
        assert evaluate(event("Read", {"file_path": name}, tmp_path), policy).denied
    assert evaluate(event("Edit", {"file_path": "public"}, tmp_path), policy) == Decision(False)
    assert evaluate(event("Bash", {"command": "forbidden"}, tmp_path), policy).rule_id == "example"


def test_report_and_safe_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDE_SECURITY_OTLP_LOGS_ENDPOINT", "http://example.invalid")
    report = run()
    assert report["passed"] and len(report["scenarios"]) == 3
    assert all(x["matched_rule"] == x["expected_rule"] and x["observed"] == "deny" for x in report["scenarios"])


def test_report_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from claude_security import scenarios
    monkeypatch.setattr(scenarios.subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess([], 0, "", ""))
    assert not scenarios.run()["passed"]


def test_audit_redaction_and_failure() -> None:
    captured: list[bytes] = []
    class Response:
        status = 200
        def __enter__(self) -> Response:
            return self
        def __exit__(self, *args: object) -> None:
            pass
    def fake_open(request: Any, timeout: int) -> Response:
        assert timeout == 1
        captured.append(request.data)
        return Response()
    with patch("claude_security.audit.urlopen", fake_open):
        assert audit.emit("http://localhost/otlp/v1/logs", "secret tool", Decision(True, "secret rule"))
    payload = json.loads(captured[0])
    assert payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"][0]["value"]["stringValue"] == "other"
    assert b"secret" not in captured[0]
    with patch("claude_security.audit.urlopen", side_effect=OSError("down")):
        assert not audit.emit("http://localhost/otlp/v1/logs", "Bash", Decision(False))


def test_audit_failure_does_not_change_deny(tmp_path: Path) -> None:
    result = hook(json.dumps(event("Read", {"file_path": ".env"}, tmp_path)), CLAUDE_SECURITY_OTLP_LOGS_ENDPOINT="not-a-url")
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
