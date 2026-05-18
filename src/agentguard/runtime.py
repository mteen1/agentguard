from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import subprocess
from typing import Sequence

from . import gitutils
from .policy import Policy
from .reporting import load_session, session_root, write_session
from .risk import classify_command, command_string, inspect_diff


@dataclass(frozen=True)
class RunOutcome:
    record: dict[str, object]
    paths: dict[str, Path]


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _session_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _state_dict(state: gitutils.GitState) -> dict[str, object]:
    return asdict(state)


class GuardRuntime:
    def __init__(self, policy: Policy, cwd: str | Path = ".") -> None:
        self.policy = policy
        self.cwd = Path(cwd)

    def run(
        self,
        command: Sequence[str],
        *,
        approve: bool = False,
        dry_run: bool = False,
        session_id: str | None = None,
    ) -> RunOutcome:
        sid = session_id or _session_id()
        root = session_root(self.policy.reporting.output_dir, self.cwd)
        session_dir = root / sid

        started_at = _utc_now()
        decision = classify_command(self.policy, command)
        git_before = gitutils.state(self.cwd)
        stdout = ""
        stderr = ""
        exit_code: int | None = None
        executed = False

        if decision.action == "deny":
            exit_code = 126
            stderr = "AgentGuard blocked command: matched deny policy\n"
        elif decision.action == "require_approval" and not approve:
            exit_code = 125
            stderr = "AgentGuard requires approval for this command; rerun with --approve\n"
        elif dry_run:
            exit_code = 0
            stdout = "AgentGuard dry run: command would be executed\n"
        else:
            executed = True
            try:
                result = subprocess.run(
                    list(command),
                    cwd=self.cwd,
                    text=True,
                    capture_output=True,
                )
                exit_code = result.returncode
                stdout = result.stdout
                stderr = result.stderr
            except FileNotFoundError as exc:
                exit_code = 127
                stderr = f"{exc}\n"

        finished_at = _utc_now()
        git_after = gitutils.state(self.cwd)
        findings = inspect_diff(self.policy, str(self.cwd))
        changed_files = gitutils.changed_files(self.cwd)
        rollback = self._write_rollback_patch(session_dir, git_before)

        record: dict[str, object] = {
            "session_id": sid,
            "policy": self.policy.to_dict(),
            "command": list(command),
            "command_string": command_string(command),
            "decision": decision.to_dict(),
            "executed": executed,
            "dry_run": dry_run,
            "approved": approve,
            "exit_code": exit_code,
            "started_at": started_at,
            "finished_at": finished_at,
            "stdout": stdout,
            "stderr": stderr,
            "git_before": _state_dict(git_before),
            "git_after": _state_dict(git_after),
            "changed_files": changed_files,
            "findings": [finding.to_dict() for finding in findings],
            "rollback": rollback,
            "session_dir": str(session_dir),
        }
        paths = write_session(session_dir, record)
        return RunOutcome(record=record, paths=paths)

    def _write_rollback_patch(
        self, session_dir: Path, git_before: gitutils.GitState
    ) -> dict[str, object]:
        rollback: dict[str, object] = {
            "available": False,
            "patch_path": None,
            "reason": None,
        }
        if not self.policy.rollback.enabled:
            rollback["reason"] = "rollback disabled by policy"
            return rollback
        if not git_before.is_repo:
            rollback["reason"] = "not a git repository"
            return rollback
        if self.policy.rollback.require_clean_git and git_before.status.strip():
            rollback["reason"] = "git worktree was dirty before command"
            return rollback

        patch_text = gitutils.combined_diff(self.cwd, binary=True)
        if not patch_text.strip():
            rollback["reason"] = "no tracked diff captured"
            return rollback

        session_dir.mkdir(parents=True, exist_ok=True)
        patch_path = session_dir / "worktree.patch"
        patch_path.write_text(patch_text, encoding="utf-8")
        rollback["available"] = True
        rollback["patch_path"] = str(patch_path)
        return rollback


def rollback_session(cwd: str | Path, session_dir: str | Path) -> subprocess.CompletedProcess[str]:
    record = load_session(session_dir)
    patch_path = record.get("rollback", {}).get("patch_path")
    if not patch_path:
        raise FileNotFoundError("session does not have a rollback patch")
    patch = Path(str(patch_path))
    if not patch.exists():
        raise FileNotFoundError(f"rollback patch not found: {patch}")
    return gitutils.apply_reverse_patch(cwd, patch)
