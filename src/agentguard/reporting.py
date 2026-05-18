from __future__ import annotations

from html import escape
import json
from pathlib import Path
from typing import Any


def session_root(policy_output_dir: str, cwd: str | Path) -> Path:
    root = Path(policy_output_dir)
    if not root.is_absolute():
        root = Path(cwd) / root
    return root


def write_session(session_dir: str | Path, record: dict[str, Any]) -> dict[str, Path]:
    root = Path(session_dir)
    root.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": root / "session.json",
        "markdown": root / "report.md",
        "html": root / "report.html",
    }
    paths["json"].write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    paths["markdown"].write_text(render_markdown(record), encoding="utf-8")
    paths["html"].write_text(render_html(record), encoding="utf-8")
    return paths


def load_session(session_dir: str | Path) -> dict[str, Any]:
    return json.loads((Path(session_dir) / "session.json").read_text(encoding="utf-8"))


def latest_session(root: str | Path) -> Path:
    sessions = sorted(
        [path for path in Path(root).iterdir() if path.is_dir()],
        key=lambda path: path.name,
    )
    if not sessions:
        raise FileNotFoundError(f"no sessions found under {root}")
    return sessions[-1]


def render_markdown(record: dict[str, Any]) -> str:
    lines = [
        f"# AgentGuard Session {record.get('session_id', '')}",
        "",
        f"- Policy: `{record.get('policy', {}).get('name', 'unknown')}`",
        f"- Command: `{record.get('command_string', '')}`",
        f"- Decision: `{record.get('decision', {}).get('action', 'unknown')}`",
        f"- Exit code: `{record.get('exit_code')}`",
        f"- Started: `{record.get('started_at', '')}`",
        f"- Finished: `{record.get('finished_at', '')}`",
        "",
        "## Findings",
        "",
    ]
    for finding in record.get("findings", []):
        path = f" `{finding['path']}`" if finding.get("path") else ""
        lines.append(
            f"- **{finding.get('severity', 'info')}** `{finding.get('code', '')}`{path}: "
            f"{finding.get('message', '')}"
        )
    if not record.get("findings"):
        lines.append("- none")

    lines.extend(["", "## Git", ""])
    before = record.get("git_before", {})
    after = record.get("git_after", {})
    lines.append(f"- Repository: `{before.get('is_repo', False)}`")
    lines.append(f"- Head before: `{before.get('head')}`")
    lines.append(f"- Head after: `{after.get('head')}`")
    lines.append(f"- Changed files: `{len(record.get('changed_files', []))}`")
    rollback = record.get("rollback", {})
    lines.append(f"- Rollback patch: `{rollback.get('patch_path') or 'unavailable'}`")

    if record.get("stdout"):
        lines.extend(["", "## Stdout", "", "```text", record["stdout"].rstrip(), "```"])
    if record.get("stderr"):
        lines.extend(["", "## Stderr", "", "```text", record["stderr"].rstrip(), "```"])
    return "\n".join(lines) + "\n"


def render_html(record: dict[str, Any]) -> str:
    findings = record.get("findings", [])
    finding_rows = "\n".join(
        "<tr>"
        f"<td>{escape(item.get('severity', ''))}</td>"
        f"<td>{escape(item.get('code', ''))}</td>"
        f"<td>{escape(item.get('path') or '')}</td>"
        f"<td>{escape(item.get('message', ''))}</td>"
        "</tr>"
        for item in findings
    )
    if not finding_rows:
        finding_rows = "<tr><td colspan=\"4\">none</td></tr>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentGuard Session {escape(record.get('session_id', ''))}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.5; color: #1f2937; }}
    code, pre {{ background: #f3f4f6; border-radius: 4px; padding: 0.1rem 0.25rem; }}
    pre {{ padding: 1rem; overflow: auto; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
    th, td {{ border: 1px solid #d1d5db; padding: 0.5rem; text-align: left; vertical-align: top; }}
    th {{ background: #f9fafb; }}
  </style>
</head>
<body>
  <h1>AgentGuard Session {escape(record.get('session_id', ''))}</h1>
  <p><strong>Policy:</strong> {escape(record.get('policy', {}).get('name', 'unknown'))}</p>
  <p><strong>Command:</strong> <code>{escape(record.get('command_string', ''))}</code></p>
  <p><strong>Decision:</strong> {escape(record.get('decision', {}).get('action', 'unknown'))}</p>
  <p><strong>Exit code:</strong> {escape(str(record.get('exit_code')))}</p>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Code</th><th>Path</th><th>Message</th></tr></thead>
    <tbody>{finding_rows}</tbody>
  </table>
  <h2>Output</h2>
  <h3>Stdout</h3>
  <pre>{escape(record.get('stdout', ''))}</pre>
  <h3>Stderr</h3>
  <pre>{escape(record.get('stderr', ''))}</pre>
</body>
</html>
"""
