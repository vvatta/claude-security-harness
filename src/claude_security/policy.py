"""Pure policy evaluation; proposed commands are never executed."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import tomllib
from typing import Any, Pattern


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: Pattern[str]


@dataclass(frozen=True)
class Policy:
    shell_rules: tuple[Rule, ...]
    protected_names: tuple[str, ...]
    protected_paths: tuple[str, ...]


@dataclass(frozen=True)
class Decision:
    denied: bool
    rule_id: str | None = None


def _strings(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise ValueError(f"{name} must be an array of nonempty strings")
    return tuple(value)


def load_policy(path: Path) -> Policy:
    with path.open("rb") as source:
        data = tomllib.load(source)
    raw_rules = data.get("shell_rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError("shell_rules must be an array of tables")
    rules: list[Rule] = []
    for raw in raw_rules:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"] or not isinstance(raw.get("pattern"), str) or not raw["pattern"]:
            raise ValueError("shell rules require nonempty id and pattern")
        rules.append(Rule(raw["id"], re.compile(raw["pattern"])))
    if len({r.id for r in rules}) != len(rules):
        raise ValueError("shell rule ids must be unique")
    return Policy(tuple(rules), _strings(data.get("protected_names", []), "protected_names"), _strings(data.get("protected_paths", []), "protected_paths"))


def evaluate(event: dict[str, Any], policy: Policy) -> Decision:
    if event.get("hook_event_name") != "PreToolUse" or not isinstance(event.get("tool_name"), str) or not isinstance(event.get("tool_input"), dict) or not isinstance(event.get("cwd"), str) or not event["cwd"]:
        raise ValueError("invalid PreToolUse input")
    name, inputs = event["tool_name"], event["tool_input"]
    if name == "Bash":
        command = inputs.get("command")
        if not isinstance(command, str):
            raise ValueError("Bash input requires command")
        for rule in policy.shell_rules:
            if rule.pattern.search(command):
                return Decision(True, rule.id)
    elif name in {"Read", "Write", "Edit"}:
        raw_path = inputs.get("file_path")
        if not isinstance(raw_path, str) or not raw_path:
            raise ValueError("file tool input requires file_path")
        cwd = Path(event["cwd"]).resolve()
        candidate = Path(raw_path).expanduser()
        candidate = (cwd / candidate).resolve()
        if any(part in policy.protected_names for part in candidate.parts):
            return Decision(True, "protected-name")
        for raw in policy.protected_paths:
            protected = (cwd / Path(raw).expanduser()).resolve()
            if candidate == protected or protected in candidate.parents:
                return Decision(True, "protected-path")
    return Decision(False)
