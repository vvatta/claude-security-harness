# Claude Code security validation harness

A small Python 3.12 experiment for evaluating a `PreToolUse` policy. The runner sends synthetic tool-call JSON to the hook; it does not run the proposed commands, contact attack destinations, or need an LLM, real credentials, Loki, or Claude Code. The JSON report records simulated outcomes, not proof that a real Claude Code session was protected.

## Install and validate

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
python -m mypy src tests
python -m claude_security.scenarios --output validation-report.json
```

The report is deterministic, has `schema_version: 1`, and contains three scenarios, each with its expected and observed decision, expected and independently evaluated matched rule, and pass/fail status. The runner exits 1 if a case fails. The hook subprocess reports only its decision, so `matched_rule` is evaluated separately against the same input and default policy; it is not evidence returned by Claude Code. Custom policy and telemetry environment variables are deliberately ignored by the scenario runner.

## Configure the hook

Install the package into a virtual environment accessible to Claude Code. Add a command hook to your Claude Code settings, replacing the executable path with the absolute path to that environment's executable:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Write|Edit",
        "hooks": [{"type": "command", "command": "/absolute/path/to/.venv/bin/claude-security-hook"}]
      }
    ]
  }
}
```

See the [official hook reference](https://code.claude.com/docs/en/hooks) for current settings and the input/output contract. Claude passes a JSON event via stdin. A match returns the documented `hookSpecificOutput` denial. Non-matches return no decision, leaving normal Claude Code permissions in effect. Invalid input or policy errors exit 2, the documented blocking error for this event. Failures that prevent the hook from starting, crashes, and timeouts may behave differently in Claude Code; see its documentation and test your deployment.

The packaged [default policy](src/claude_security/default_policy.toml) is illustrative. To override it, copy it and set `CLAUDE_SECURITY_POLICY` to the absolute path of the copy in the environment that starts Claude Code. Shell rules are Python regex searches over the literal `Bash` command, in order. `protected_names` match exact path components; `protected_paths` match a canonical path and its descendants. Relative protected paths are resolved against event `cwd`; existing symlinks are resolved. `Read`, `Write`, and `Edit` use `tool_input.file_path` (Claude Code normally supplies an absolute path). The `Bash` rules do not inspect filesystem access or execute commands.

## Optional audit output

Set `CLAUDE_SECURITY_OTLP_LOGS_ENDPOINT` to the **full** OTLP/HTTP logs URL, for example `http://localhost:3100/otlp/v1/logs` for a locally configured Loki endpoint. This sends a minimal OTLP JSON log with timestamp, service name, recognized tool name, and pass/deny outcome. It excludes commands, paths, rule IDs, file contents and credentials. Unrecognized tool names become `other`. Export is synchronous with a one-second timeout and is best effort: failures are noted on stderr and do not alter the decision. This is not durable delivery or tamper-proof auditing. No export occurs by default, including in tests or CI. Configure endpoint access controls and transport independently; this project does not provision services. Loki may require structured metadata enabled; see [Loki OTLP ingestion](https://grafana.com/docs/loki/latest/send-data/otel/).

## Boundaries and limitations

This hook is a demonstration, not a sandbox or complete security control. It observes only configured hook events and literal inputs of the specified tools. It cannot inspect a program's later behavior, shell expansions, encoded or obfuscated commands, scripts, aliases, indirect filesystem or network access, other tools including MCP and PowerShell, or actions outside Claude Code. Claude Code may inject file mentions into context without invoking a file tool; consult the hook reference. Regex matches can have false positives and false negatives. Symlinks and filesystem contents can change between checking and use; nonexistent paths and platform-specific path behavior also limit protection. Hooks can be disabled or modified, may fail to start, and are not an isolation boundary. Use OS-level permissions and isolation for sensitive assets, and do not rely on this harness to prevent exfiltration or destructive actions.
