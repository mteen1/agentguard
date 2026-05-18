from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from agentguard.compiler import compile_to_directory, supported_agents
from agentguard.policy import parse_policy
from agentguard.profiles import list_profiles, read_profile
from agentguard.risk import classify_command, inspect_diff
from agentguard.runtime import GuardRuntime


def base_policy(output_dir: str = ".agentguard/sessions"):
    return parse_policy(
        {
            "version": 1,
            "name": "test",
            "commands": {
                "default": "allow",
                "allow": ["git status", "python*"],
                "deny": ["rm -rf*"],
                "require_approval": ["pip install*"],
            },
            "files": {
                "protected": [".env*"],
                "deny_write": [".git/**"],
            },
            "reporting": {"output_dir": output_dir},
        }
    )


class PolicyTests(unittest.TestCase):
    def test_builtin_profiles_parse(self) -> None:
        self.assertEqual(
            list_profiles(),
            ["fast-prototype", "junior-helper", "production-strict"],
        )
        for name in list_profiles():
            policy = parse_policy(__import__("yaml").safe_load(read_profile(name)))
            self.assertEqual(policy.version, 1)
            self.assertEqual(policy.name, name)

    def test_command_precedence(self) -> None:
        policy = base_policy()
        self.assertEqual(classify_command(policy, ["rm", "-rf", "build"]).action, "deny")
        self.assertEqual(
            classify_command(policy, ["pip", "install", "requests"]).action,
            "require_approval",
        )
        self.assertEqual(classify_command(policy, ["python", "--version"]).action, "allow")


class CompilerTests(unittest.TestCase):
    def test_compile_all_agents(self) -> None:
        policy = base_policy()
        with tempfile.TemporaryDirectory() as tmp:
            written = compile_to_directory(policy, "all", tmp)
            self.assertEqual(len(written), len(supported_agents()))
            for path in written:
                self.assertTrue(path.exists(), path)
                self.assertIn("AgentGuard Policy", path.read_text(encoding="utf-8"))


class RuntimeTests(unittest.TestCase):
    def test_run_records_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = base_policy(output_dir=str(Path(tmp) / "sessions"))
            runtime = GuardRuntime(policy, cwd=tmp)
            outcome = runtime.run(
                [sys.executable, "-c", "print('ok')"],
                session_id="session-a",
            )
            self.assertEqual(outcome.record["exit_code"], 0)
            self.assertEqual(outcome.record["stdout"], "ok\n")
            self.assertTrue((Path(tmp) / "sessions" / "session-a" / "session.json").exists())
            self.assertTrue((Path(tmp) / "sessions" / "session-a" / "report.md").exists())

    def test_run_blocks_denied_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = base_policy(output_dir=str(Path(tmp) / "sessions"))
            runtime = GuardRuntime(policy, cwd=tmp)
            outcome = runtime.run(["rm", "-rf", "build"], session_id="blocked")
            self.assertEqual(outcome.record["exit_code"], 126)
            self.assertFalse(outcome.record["executed"])


class DiffRiskTests(unittest.TestCase):
    def test_protected_path_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init"], cwd=tmp, check=True, capture_output=True)
            env_path = Path(tmp) / ".env"
            env_path.write_text("TOKEN='abc123456789'\n", encoding="utf-8")
            subprocess.run(["git", "add", ".env"], cwd=tmp, check=True, capture_output=True)

            findings = inspect_diff(base_policy(), tmp)
            codes = {finding.code for finding in findings}
            self.assertIn("protected_path_changed", codes)
            self.assertIn("secret_pattern_detected", codes)


if __name__ == "__main__":
    unittest.main()
