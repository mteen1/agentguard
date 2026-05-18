from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess


@dataclass(frozen=True)
class GitState:
    is_repo: bool
    head: str | None
    status: str


def _run_git(args: list[str], cwd: str | Path, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        text=True,
        capture_output=True,
        check=check,
    )


def is_git_repo(cwd: str | Path) -> bool:
    result = _run_git(["rev-parse", "--is-inside-work-tree"], cwd)
    return result.returncode == 0 and result.stdout.strip() == "true"


def head(cwd: str | Path) -> str | None:
    result = _run_git(["rev-parse", "HEAD"], cwd)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def status_short(cwd: str | Path) -> str:
    if not is_git_repo(cwd):
        return ""
    result = _run_git(["status", "--short"], cwd)
    return result.stdout


def state(cwd: str | Path) -> GitState:
    repo = is_git_repo(cwd)
    return GitState(is_repo=repo, head=head(cwd) if repo else None, status=status_short(cwd) if repo else "")


def diff(cwd: str | Path, cached: bool = False, binary: bool = False) -> str:
    if not is_git_repo(cwd):
        return ""
    args = ["diff", "--no-ext-diff"]
    if cached:
        args.append("--cached")
    if binary:
        args.append("--binary")
    result = _run_git(args, cwd)
    return result.stdout if result.returncode == 0 else ""


def combined_diff(cwd: str | Path, binary: bool = False) -> str:
    return diff(cwd, cached=False, binary=binary) + diff(cwd, cached=True, binary=binary)


def changed_files(cwd: str | Path) -> list[str]:
    if not is_git_repo(cwd):
        return []
    files: set[str] = set()
    for args in (["diff", "--name-only"], ["diff", "--cached", "--name-only"]):
        result = _run_git(args, cwd)
        if result.returncode == 0:
            files.update(line.strip() for line in result.stdout.splitlines() if line.strip())
    return sorted(files)


def apply_reverse_patch(cwd: str | Path, patch_path: str | Path) -> subprocess.CompletedProcess[str]:
    return _run_git(["apply", "-R", str(patch_path)], cwd)
