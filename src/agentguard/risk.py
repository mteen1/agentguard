from __future__ import annotations

from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
import re
import shlex
from typing import Sequence

from . import gitutils
from .policy import Policy


DEFAULT_SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
]

DEPENDENCY_LOCKS = {
    "package.json": ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb"],
    "pyproject.toml": ["uv.lock", "poetry.lock", "Pipfile.lock"],
    "requirements.txt": [],
    "Pipfile": ["Pipfile.lock"],
    "Gemfile": ["Gemfile.lock"],
    "go.mod": ["go.sum"],
    "Cargo.toml": ["Cargo.lock"],
    "composer.json": ["composer.lock"],
}


@dataclass(frozen=True)
class CommandDecision:
    action: str
    reasons: list[str]
    matched_rules: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    path: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def command_string(command: Sequence[str]) -> str:
    return shlex.join([str(part) for part in command])


def _matches_pattern(command: Sequence[str], pattern: str) -> bool:
    if not command:
        return False
    rendered = command_string(command)
    executable = str(command[0])
    return fnmatchcase(rendered, pattern) or fnmatchcase(executable, pattern)


def _matching_rules(command: Sequence[str], patterns: list[str]) -> list[str]:
    return [pattern for pattern in patterns if _matches_pattern(command, pattern)]


def classify_command(policy: Policy, command: Sequence[str]) -> CommandDecision:
    if not command:
        return CommandDecision("deny", ["no command provided"], [])

    deny_matches = _matching_rules(command, policy.commands.deny)
    if deny_matches:
        return CommandDecision("deny", ["matched deny rule"], deny_matches)

    approval_matches = _matching_rules(command, policy.commands.require_approval)
    if approval_matches:
        return CommandDecision(
            "require_approval",
            ["matched approval-required rule"],
            approval_matches,
        )

    allow_matches = _matching_rules(command, policy.commands.allow)
    if allow_matches:
        return CommandDecision("allow", ["matched allow rule"], allow_matches)

    if policy.commands.default == "deny":
        return CommandDecision("deny", ["commands.default is deny"], [])
    if policy.commands.default == "require_approval":
        return CommandDecision(
            "require_approval",
            ["commands.default is require_approval"],
            [],
        )
    return CommandDecision("allow", ["commands.default is allow"], [])


def _path_matches(path: str, patterns: list[str]) -> bool:
    posix = PurePosixPath(path).as_posix()
    return any(fnmatchcase(posix, pattern) for pattern in patterns)


def _dependency_manifests(policy: Policy) -> dict[str, list[str]]:
    manifests = dict(DEPENDENCY_LOCKS)
    for manifest in policy.dependencies.manifests:
        manifests.setdefault(manifest, [])
    return manifests


def inspect_diff(policy: Policy, cwd: str) -> list[Finding]:
    findings: list[Finding] = []
    if not gitutils.is_git_repo(cwd):
        return [
            Finding(
                severity="info",
                code="not_git_repo",
                message="diff checks skipped because this directory is not a git repository",
            )
        ]

    changed = gitutils.changed_files(cwd)
    diff_text = gitutils.combined_diff(cwd)
    diff_lines = len(diff_text.splitlines())

    if len(changed) > policy.risk.max_changed_files:
        findings.append(
            Finding(
                severity="warning",
                code="many_changed_files",
                message=(
                    f"{len(changed)} files changed; policy limit is "
                    f"{policy.risk.max_changed_files}"
                ),
            )
        )

    if diff_lines > policy.risk.max_diff_lines:
        findings.append(
            Finding(
                severity="warning",
                code="large_diff",
                message=f"{diff_lines} diff lines; policy limit is {policy.risk.max_diff_lines}",
            )
        )

    for path in changed:
        if _path_matches(path, policy.files.protected):
            findings.append(
                Finding(
                    severity="high",
                    code="protected_path_changed",
                    message="protected path changed",
                    path=path,
                )
            )
        if _path_matches(path, policy.files.deny_write):
            findings.append(
                Finding(
                    severity="high",
                    code="denied_path_changed",
                    message="path matches files.deny_write",
                    path=path,
                )
            )

    if policy.dependencies.lockfile_required:
        changed_set = set(changed)
        for manifest, locks in _dependency_manifests(policy).items():
            if manifest not in changed_set:
                continue
            if locks and not changed_set.intersection(locks):
                findings.append(
                    Finding(
                        severity="warning",
                        code="dependency_lock_missing",
                        message=f"{manifest} changed without a matching lockfile change",
                        path=manifest,
                    )
                )

    for pattern in [*DEFAULT_SECRET_PATTERNS, *policy.risk.secret_patterns]:
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            findings.append(
                Finding(
                    severity="warning",
                    code="invalid_secret_pattern",
                    message=f"invalid secret pattern {pattern!r}: {exc}",
                )
            )
            continue
        if compiled.search(diff_text):
            findings.append(
                Finding(
                    severity="high",
                    code="secret_pattern_detected",
                    message=f"diff matches secret pattern {pattern!r}",
                )
            )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                code="diff_clean",
                message="no policy findings in current git diff",
            )
        )
    return findings


def highest_severity(findings: list[Finding]) -> str:
    order = {"info": 0, "warning": 1, "high": 2}
    if not findings:
        return "info"
    return max(findings, key=lambda item: order.get(item.severity, 0)).severity
