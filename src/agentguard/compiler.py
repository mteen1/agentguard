from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from .policy import Policy


AGENT_OUTPUTS = {
    "codex": "CODEX.md",
    "claude": "CLAUDE.md",
    "cursor": ".cursor/rules/agentguard.mdc",
    "opencode": "OPENCODE.md",
    "cline": "CLINE.md",
}


def supported_agents() -> list[str]:
    return sorted(AGENT_OUTPUTS)


def _bullet(items: list[str], empty: str = "none") -> str:
    if not items:
        return f"- {empty}"
    return "\n".join(f"- `{item}`" for item in items)


def compile_policy(policy: Policy, agent: str) -> str:
    if agent not in AGENT_OUTPUTS:
        raise ValueError(f"unsupported agent '{agent}'")

    agent_data = policy.agents.get(agent, {})
    extra = ""
    if isinstance(agent_data, dict) and agent_data.get("instructions"):
        extra = f"\n## Agent-Specific Notes\n\n{agent_data['instructions']}\n"

    return dedent(
        f"""
        # AgentGuard Policy: {policy.name}

        This file was generated from `agentguard.yaml` for `{agent}`.

        ## Operating Rules

        - Treat AgentGuard policy as the source of truth for command and file safety.
        - Do not execute deny-listed commands.
        - Ask for explicit approval before running approval-required commands.
        - Keep changes scoped and report any risky diff findings.
        - Do not modify protected paths unless the user explicitly asks for it.

        ## Command Policy

        Default action: `{policy.commands.default}`

        Allowed commands:
        {_bullet(policy.commands.allow)}

        Denied commands:
        {_bullet(policy.commands.deny)}

        Approval-required commands:
        {_bullet(policy.commands.require_approval)}

        ## File Policy

        Protected paths:
        {_bullet(policy.files.protected)}

        Denied write paths:
        {_bullet(policy.files.deny_write)}

        ## Dependency Policy

        - Lockfile required: `{policy.dependencies.lockfile_required}`
        - Watched manifests: `{", ".join(policy.dependencies.manifests) or "built-in defaults"}`

        ## Risk Limits

        - Max changed files: `{policy.risk.max_changed_files}`
        - Max diff lines: `{policy.risk.max_diff_lines}`
        {extra}
        """
    ).strip() + "\n"


def compile_to_directory(policy: Policy, agent: str, output_dir: str | Path) -> list[Path]:
    output_root = Path(output_dir)
    agents = supported_agents() if agent == "all" else [agent]
    written: list[Path] = []
    for name in agents:
        relative = Path(AGENT_OUTPUTS[name])
        destination = output_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(compile_policy(policy, name), encoding="utf-8")
        written.append(destination)
    return written
