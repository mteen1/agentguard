# Implementation Notes

AgentGuard is implemented as a local Python CLI rather than a hosted service. That keeps the MVP aligned with the proposal's non-goals: no SaaS dashboard, no enterprise onboarding, and no external APIs.

## MVP Mapping

- v0.1 CLI wrapper: `agentguard init`, `agentguard run`, and session logs.
- v0.2 policy compiler: `agentguard compile` for Codex, Claude, Cursor, OpenCode, and Cline.
- v0.3 hard enforcement: command classification plus git diff, protected path, dependency, and secret checks.
- v0.4 reporting: JSON, Markdown, and HTML reports per session.
- v0.5 templates: built-in and checked-in profile YAML files.

## Enforcement Model

Commands are passed as argv after `--` and run without a shell. Rules are shell-style glob patterns matched against the rendered command and executable name. Deny rules have highest precedence, followed by approval-required rules, then allow rules, then the policy default.

Rollback patches are generated only from tracked git diffs. In strict profiles, AgentGuard requires a clean worktree before it creates a rollback patch, so it does not capture unrelated user edits.
