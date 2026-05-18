from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml


class PolicyError(ValueError):
    """Raised when an AgentGuard policy is invalid."""


def _string_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        raise PolicyError(f"{field_name} must be a string or list of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise PolicyError(f"{field_name} must contain only strings")
        result.append(item)
    return result


def _mapping(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError(f"{field_name} must be a mapping")
    return dict(value)


def _int(value: Any, field_name: str, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int):
        raise PolicyError(f"{field_name} must be an integer")
    return value


def _bool(value: Any, field_name: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise PolicyError(f"{field_name} must be true or false")
    return value


@dataclass(frozen=True)
class CommandPolicy:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    require_approval: list[str] = field(default_factory=list)
    default: str = "allow"


@dataclass(frozen=True)
class FilePolicy:
    protected: list[str] = field(default_factory=list)
    allow_write: list[str] = field(default_factory=lambda: ["**"])
    deny_write: list[str] = field(default_factory=lambda: [".git/**"])


@dataclass(frozen=True)
class DependencyPolicy:
    lockfile_required: bool = True
    manifests: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RiskPolicy:
    max_changed_files: int = 20
    max_diff_lines: int = 800
    secret_patterns: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ReportingPolicy:
    output_dir: str = ".agentguard/sessions"
    formats: list[str] = field(default_factory=lambda: ["json", "markdown", "html"])


@dataclass(frozen=True)
class RollbackPolicy:
    enabled: bool = True
    require_clean_git: bool = True


@dataclass(frozen=True)
class Policy:
    version: int
    name: str
    description: str
    commands: CommandPolicy
    files: FilePolicy
    dependencies: DependencyPolicy
    risk: RiskPolicy
    reporting: ReportingPolicy
    rollback: RollbackPolicy
    agents: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_policy(data: dict[str, Any]) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError("policy must be a YAML mapping")

    version = _int(data.get("version"), "version", 1)
    if version != 1:
        raise PolicyError("only policy version 1 is supported")

    name = data.get("name") or "agentguard"
    if not isinstance(name, str):
        raise PolicyError("name must be a string")

    description = data.get("description") or ""
    if not isinstance(description, str):
        raise PolicyError("description must be a string")

    commands_data = _mapping(data.get("commands"), "commands")
    default_action = commands_data.get("default", "allow")
    if default_action not in {"allow", "deny", "require_approval"}:
        raise PolicyError("commands.default must be allow, deny, or require_approval")
    commands = CommandPolicy(
        allow=_string_list(commands_data.get("allow"), "commands.allow"),
        deny=_string_list(commands_data.get("deny"), "commands.deny"),
        require_approval=_string_list(
            commands_data.get("require_approval"), "commands.require_approval"
        ),
        default=default_action,
    )

    files_data = _mapping(data.get("files"), "files")
    files = FilePolicy(
        protected=_string_list(files_data.get("protected"), "files.protected"),
        allow_write=_string_list(files_data.get("allow_write"), "files.allow_write")
        or ["**"],
        deny_write=_string_list(files_data.get("deny_write"), "files.deny_write")
        or [".git/**"],
    )

    dependencies_data = _mapping(data.get("dependencies"), "dependencies")
    dependencies = DependencyPolicy(
        lockfile_required=_bool(
            dependencies_data.get("lockfile_required"),
            "dependencies.lockfile_required",
            True,
        ),
        manifests=_string_list(
            dependencies_data.get("manifests"), "dependencies.manifests"
        ),
    )

    risk_data = _mapping(data.get("risk"), "risk")
    risk = RiskPolicy(
        max_changed_files=_int(
            risk_data.get("max_changed_files"), "risk.max_changed_files", 20
        ),
        max_diff_lines=_int(risk_data.get("max_diff_lines"), "risk.max_diff_lines", 800),
        secret_patterns=_string_list(
            risk_data.get("secret_patterns"), "risk.secret_patterns"
        ),
    )

    reporting_data = _mapping(data.get("reporting"), "reporting")
    reporting = ReportingPolicy(
        output_dir=reporting_data.get("output_dir", ".agentguard/sessions"),
        formats=_string_list(reporting_data.get("formats"), "reporting.formats")
        or ["json", "markdown", "html"],
    )
    if not isinstance(reporting.output_dir, str):
        raise PolicyError("reporting.output_dir must be a string")

    rollback_data = _mapping(data.get("rollback"), "rollback")
    rollback = RollbackPolicy(
        enabled=_bool(rollback_data.get("enabled"), "rollback.enabled", True),
        require_clean_git=_bool(
            rollback_data.get("require_clean_git"),
            "rollback.require_clean_git",
            True,
        ),
    )

    agents = _mapping(data.get("agents"), "agents")

    return Policy(
        version=version,
        name=name,
        description=description,
        commands=commands,
        files=files,
        dependencies=dependencies,
        risk=risk,
        reporting=reporting,
        rollback=rollback,
        agents=agents,
    )


def load_policy(path: str | Path = "agentguard.yaml") -> Policy:
    policy_path = Path(path)
    if not policy_path.exists():
        raise PolicyError(f"policy file not found: {policy_path}")
    with policy_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return parse_policy(data)


def dump_policy(policy: Policy) -> str:
    return yaml.safe_dump(policy.to_dict(), sort_keys=False)
