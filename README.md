# Prompt Injection Firewall

Reverse proxy that gates LLM requests and tool calls with allow/deny/approve rules, plus a full JSONL audit trail.

## What it does
- Inspects incoming LLM requests (OpenAI-style JSON) for risky patterns and tool usage.
- Applies ordered rules to allow, deny, or require approval.
- Records every decision, request metadata, and a redacted text sample to `audit.jsonl`.

## Quickstart
```bash
cp config.example.yaml config.yaml
make setup
make dev
```

Then send requests to `http://localhost:8080` (it will forward to the configured upstream).

## Approval flow
If a rule returns `approve`, the firewall responds with HTTP 202:
```json
{"status":"approval_required","approval_id":"..."}
```

Approve the request by calling:
```bash
curl -s -X POST http://localhost:8080/approve \
  -H 'X-Approval-Token: change-me' \
  -d '{"approval_id":"..."}'
```

## Configuration
See `config.example.yaml` for a complete example. Key options:
- `upstream`: Required. Base URL for the model API.
- `rules`: Ordered match rules (deny/approve/allow).
- `approval.enabled`: Enable the `/approve` endpoint.
- `audit_log_path`: JSONL output path for audit events.

## Limitations
- Non-streaming only (request body must be buffered for inspection).
- Approval queue is in-memory (no persistence).
- Only request-stage inspection in MVP.

## Security notes
- Use a strong `approval.token` if you enable approvals.
- Keep audit logs protected (contains text samples and metadata).

## License
Apache-2.0
