from __future__ import annotations

from importlib import resources
from pathlib import Path


PROFILE_PACKAGE = "agentguard.builtin_profiles"


def list_profiles() -> list[str]:
    root = resources.files(PROFILE_PACKAGE)
    names = []
    for entry in root.iterdir():
        if entry.name.endswith(".yaml"):
            names.append(entry.name.removesuffix(".yaml"))
    return sorted(names)


def read_profile(name: str) -> str:
    if name.endswith(".yaml"):
        name = name[:-5]
    if name not in list_profiles():
        available = ", ".join(list_profiles())
        raise KeyError(f"unknown profile '{name}'. Available profiles: {available}")
    return resources.files(PROFILE_PACKAGE).joinpath(f"{name}.yaml").read_text(
        encoding="utf-8"
    )


def write_profile(name: str, destination: str | Path, force: bool = False) -> Path:
    output = Path(destination)
    if output.exists() and not force:
        raise FileExistsError(f"{output} already exists; pass --force to overwrite")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(read_profile(name), encoding="utf-8")
    return output
