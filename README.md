# AgentGuard

AgentGuard is a lightweight policy-as-code runtime guard for AI coding agents. It gives a developer one YAML policy that can be compiled into agent-specific instructions and enforced by a local CLI wrapper.

The MVP follows the proposal in `AgentGuard_Proposal.docx`:

- unified YAML policy for command, file, dependency, and reporting rules
- compiler output for Codex, Claude Code, Cursor, OpenCode, and Cline
- guarded command runner with allow, deny, and approval-required decisions
- session logs with Markdown, HTML, and JSON reports
- git diff monitoring for protected paths, dependency manifests, and secrets
- rollback helper that can reverse the diff captured for a session
- starter profiles: `production-strict`, `fast-prototype`, and `junior-helper`

## Quick Start

Run from source:

```bash
PYTHONPATH=src python -m agentguard profiles
PYTHONPATH=src python -m agentguard init --profile production-strict
PYTHONPATH=src python -m agentguard validate
PYTHONPATH=src python -m agentguard compile --agent all
PYTHONPATH=src python -m agentguard run -- git status
```

After installation:

```bash
pip install -e .
agentguard init --profile production-strict
agentguard run -- git status
```

## Policy File

`agentguard init` creates `agentguard.yaml` from a built-in profile. A policy controls command execution, protected files, dependency checks, risk thresholds, and report output.

```yaml
version: 1
name: production-strict
commands:
  allow:
    - git status
    - git diff*
  deny:
    - rm -rf*
    - sudo*
  require_approval:
    - pip install*
    - npm install*
files:
  protected:
    - .env*
    - secrets/**
risk:
  max_changed_files: 20
  max_diff_lines: 800
```

Command rules are shell-style globs matched against the command string. Deny rules win over approval rules, and approval rules win over allow rules.

## CLI

```bash
agentguard profiles
agentguard init --profile junior-helper
agentguard validate --policy agentguard.yaml
agentguard compile --agent codex --output-dir .agentguard/generated
agentguard check -- npm install
agentguard run --approve -- npm install
agentguard diff-check
agentguard report --session latest --format markdown
agentguard rollback --session latest
```

`run` executes commands without a shell, records stdout/stderr, captures git state before and after execution, and writes a session directory under `.agentguard/sessions/`.

## Compiled Agent Outputs

`agentguard compile --agent all` writes:

- `.agentguard/generated/CODEX.md`
- `.agentguard/generated/CLAUDE.md`
- `.agentguard/generated/.cursor/rules/agentguard.mdc`
- `.agentguard/generated/OPENCODE.md`
- `.agentguard/generated/CLINE.md`

These files are instruction artifacts for agents that do not share one config format.

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

The test suite uses the standard library plus PyYAML, so it can run without extra dev dependencies.
