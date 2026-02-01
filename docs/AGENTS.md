# AGENTS

## Guardrails
- Keep changes minimal and explain security impact in PRs.
- Prefer standard library for core logic.
- Avoid introducing non-deterministic behavior in policy evaluation.

## Commands
- Setup: `make setup`
- Dev: `make dev`
- Tests: `make test`
- Lint: `make lint`
- Typecheck: `make typecheck`
- Build: `make build`
- All checks: `make check`

## Conventions
- Go 1.22+.
- JSONL audit events must stay backwards compatible.
