from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .compiler import compile_to_directory, supported_agents
from .policy import PolicyError, load_policy
from .profiles import list_profiles, write_profile
from .reporting import latest_session, load_session, session_root
from .risk import classify_command, highest_severity, inspect_diff
from .runtime import GuardRuntime, rollback_session


def _strip_command(remainder: list[str]) -> list[str]:
    if remainder and remainder[0] == "--":
        remainder = remainder[1:]
    return remainder


def _policy_path(args: argparse.Namespace) -> str:
    return getattr(args, "policy", "agentguard.yaml")


def _load_policy(args: argparse.Namespace):
    try:
        return load_policy(_policy_path(args))
    except PolicyError as exc:
        print(f"AgentGuard policy error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _resolve_session(policy, cwd: Path, value: str) -> Path:
    root = session_root(policy.reporting.output_dir, cwd)
    if value == "latest":
        return latest_session(root)
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    by_id = root / value
    if by_id.exists():
        return by_id
    return candidate


def cmd_profiles(_args: argparse.Namespace) -> int:
    for name in list_profiles():
        print(name)
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    try:
        path = write_profile(args.profile, args.output, force=args.force)
    except (KeyError, FileExistsError) as exc:
        print(f"AgentGuard init error: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {path}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    policy = _load_policy(args)
    print(f"valid policy: {policy.name}")
    print(f"default command action: {policy.commands.default}")
    print(f"report output: {policy.reporting.output_dir}")
    return 0


def cmd_compile(args: argparse.Namespace) -> int:
    policy = _load_policy(args)
    try:
        written = compile_to_directory(policy, args.agent, args.output_dir)
    except ValueError as exc:
        print(f"AgentGuard compile error: {exc}", file=sys.stderr)
        return 2
    for path in written:
        print(f"wrote {path}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    policy = _load_policy(args)
    command = _strip_command(args.guarded_command)
    decision = classify_command(policy, command)
    print(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
    if decision.action == "deny":
        return 2
    if decision.action == "require_approval":
        return 3
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    policy = _load_policy(args)
    command = _strip_command(args.guarded_command)
    runtime = GuardRuntime(policy, cwd=Path.cwd())
    outcome = runtime.run(
        command,
        approve=args.approve,
        dry_run=args.dry_run,
        session_id=args.session_id,
    )
    record = outcome.record
    if record.get("stdout"):
        print(record["stdout"], end="")
    if record.get("stderr"):
        print(record["stderr"], end="", file=sys.stderr)
    print(f"session: {record['session_dir']}")
    return int(record.get("exit_code") or 0)


def cmd_diff_check(args: argparse.Namespace) -> int:
    policy = _load_policy(args)
    findings = inspect_diff(policy, str(Path.cwd()))
    for finding in findings:
        path = f" {finding.path}" if finding.path else ""
        print(f"{finding.severity}: {finding.code}{path}: {finding.message}")
    severity = highest_severity(findings)
    if severity == "high":
        return 2
    if severity == "warning":
        return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    policy = _load_policy(args)
    session_dir = _resolve_session(policy, Path.cwd(), args.session)
    if args.format == "json":
        print(json.dumps(load_session(session_dir), indent=2, sort_keys=True))
        return 0
    filename = "report.md" if args.format == "markdown" else "report.html"
    print((session_dir / filename).read_text(encoding="utf-8"), end="")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    policy = _load_policy(args)
    session_dir = _resolve_session(policy, Path.cwd(), args.session)
    try:
        result = rollback_session(Path.cwd(), session_dir)
    except FileNotFoundError as exc:
        print(f"AgentGuard rollback error: {exc}", file=sys.stderr)
        return 2
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode == 0:
        print(f"rolled back session {session_dir}")
    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentguard")
    parser.add_argument("--version", action="version", version=f"agentguard {__version__}")
    subcommands = parser.add_subparsers(dest="command")
    subcommands.required = True

    profiles = subcommands.add_parser("profiles", help="list built-in policy profiles")
    profiles.set_defaults(func=cmd_profiles)

    init = subcommands.add_parser("init", help="write a starter agentguard.yaml")
    init.add_argument("--profile", default="production-strict", choices=list_profiles())
    init.add_argument("--output", default="agentguard.yaml")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    validate = subcommands.add_parser("validate", help="validate a policy file")
    validate.add_argument("--policy", default="agentguard.yaml")
    validate.set_defaults(func=cmd_validate)

    compile_cmd = subcommands.add_parser("compile", help="compile policy for agents")
    compile_cmd.add_argument("--policy", default="agentguard.yaml")
    compile_cmd.add_argument("--agent", default="all", choices=["all", *supported_agents()])
    compile_cmd.add_argument("--output-dir", default=".agentguard/generated")
    compile_cmd.set_defaults(func=cmd_compile)

    check = subcommands.add_parser("check", help="classify a command without running it")
    check.add_argument("--policy", default="agentguard.yaml")
    check.add_argument("guarded_command", nargs=argparse.REMAINDER)
    check.set_defaults(func=cmd_check)

    run = subcommands.add_parser("run", help="run a guarded command")
    run.add_argument("--policy", default="agentguard.yaml")
    run.add_argument("--approve", action="store_true")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--session-id")
    run.add_argument("guarded_command", nargs=argparse.REMAINDER)
    run.set_defaults(func=cmd_run)

    diff_check = subcommands.add_parser("diff-check", help="inspect current git diff")
    diff_check.add_argument("--policy", default="agentguard.yaml")
    diff_check.set_defaults(func=cmd_diff_check)

    report = subcommands.add_parser("report", help="print a session report")
    report.add_argument("--policy", default="agentguard.yaml")
    report.add_argument("--session", default="latest")
    report.add_argument("--format", choices=["json", "markdown", "html"], default="markdown")
    report.set_defaults(func=cmd_report)

    rollback = subcommands.add_parser("rollback", help="reverse a captured session patch")
    rollback.add_argument("--policy", default="agentguard.yaml")
    rollback.add_argument("--session", default="latest")
    rollback.set_defaults(func=cmd_rollback)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
