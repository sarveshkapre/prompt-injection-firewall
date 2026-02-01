# PLAN

## Goal
Ship a minimal reverse proxy that inspects LLM requests, enforces allow/deny/approve rules, and records a full audit trail.

## Architecture
- `cmd/pif`: CLI entry point.
- `internal/config`: YAML config loader + validation.
- `internal/extract`: Extract text + tool names from request JSON.
- `internal/policy`: Rule evaluation engine with ordered decisions.
- `internal/proxy`: HTTP handler that enforces policy and forwards to upstream.
- `internal/audit`: JSONL writer for audit events.

## Stack
- Go 1.22
- Standard library HTTP server
- `gopkg.in/yaml.v3` for config

## MVP checklist
- [x] Config loader with defaults and validation
- [x] Request extraction (messages/input/prompt + tools)
- [x] Policy engine with ordered decisions
- [x] Reverse proxy + approval queue
- [x] JSONL audit logs
- [x] Tests for policy + extraction
- [x] CI + Makefile + docs

## Risks and mitigations
- Large request bodies: enforce `max_body_bytes` and return 413.
- Approval abuse: require `approval.token` in production.
- Rule order confusion: document `decision_order` and examples.

## Non-goals (MVP)
- Streaming requests/responses
- Persistent approval queue
- Response-stage inspection
