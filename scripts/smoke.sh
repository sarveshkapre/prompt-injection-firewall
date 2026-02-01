#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${BASE_URL:-http://localhost:8080}
APPROVAL_TOKEN=${APPROVAL_TOKEN:-change-me}

payload='{"messages":[{"role":"user","content":"hello"}],"tools":[{"name":"file_write"}]}'

approval=$(curl -s -X POST "$BASE_URL/v1/chat" -H 'Content-Type: application/json' -d "$payload")
approval_id=$(echo "$approval" | python3 - <<'PY'
import json,sys
print(json.loads(sys.stdin.read()).get('approval_id',''))
PY
)

if [[ -z "$approval_id" ]]; then
  echo "failed to get approval_id: $approval" >&2
  exit 1
fi

curl -s -X POST "$BASE_URL/approve" \
  -H "X-Approval-Token: $APPROVAL_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"approval_id":"'$approval_id'"}'
