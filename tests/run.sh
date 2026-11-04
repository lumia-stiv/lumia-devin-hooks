#!/bin/sh
# Test suite for hooks/lumia-hook.sh against a local mock policy server.
# Requires: sh, curl, python3. Runs every case with jq (if installed) and with
# the sed fallback (LUMIA_NO_JQ=1).

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK="$ROOT/hooks/lumia-hook.sh"
STATE="$(mktemp -d)"
OUT="$STATE/out"; ERR="$STATE/err"

python3 "$ROOT/tests/mock_server.py" "$STATE" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null; rm -rf "$STATE"' EXIT INT TERM
i=0
while [ ! -s "$STATE/port" ]; do
  i=$((i + 1)); [ $i -gt 50 ] && { echo "mock server did not start"; exit 1; }
  sleep 0.1
done
export LUMIA_POLICY_URL="http://127.0.0.1:$(cat "$STATE/port")/policy"

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL [$MODE] $CASE: $*"; }

reset() {
  rm -f "$STATE/response.json" "$STATE/status" "$STATE/delay" "$STATE/last_request.json" \
    "$STATE/oidc_request.txt" "$STATE/oidc_response.json" "$STATE/oidc_status" "$STATE"/tmp/lumia-devin-oidc-*
}
# No Devin OIDC token by default (as on a laptop); the OIDC cases point at their own file.
mkdir -p "$STATE/tmp"
export TMPDIR="$STATE/tmp"
export LUMIA_DEVIN_OIDC_TOKEN_FILE="$STATE/no-such-oidc-token"
export LUMIA_DEVIN_OIDC_EXCHANGE_URL="http://127.0.0.1:$(cat "$STATE/port")/oidc/token"
respond() { printf '%s' "$1" > "$STATE/response.json"; }

# run <hook_type> <stdin json> -> sets RC
run() { printf '%s' "$2" | sh "$HOOK" "$1" >"$OUT" 2>"$ERR"; RC=$?; }

expect_rc()    { [ "$RC" -eq "$1" ] && ok || fail "exit $RC, want $1 (stderr: $(cat "$ERR"))"; }
expect_empty() { [ ! -s "$OUT" ] && ok || fail "expected empty stdout, got: $(cat "$OUT")"; }
# py <expr over `out` (parsed stdout) and `req` (recorded request)>
py() {
  python3 - "$OUT" "$STATE/last_request.json" "$1" <<'PY'
import json, os, sys
out_path, req_path, expr = sys.argv[1:]
out = json.load(open(out_path)) if os.path.getsize(out_path) else None
req = json.load(open(req_path)) if os.path.exists(req_path) else None
sys.exit(0 if eval(expr) else 1)
PY
}
check() { py "$1" && ok || fail "assertion failed: $1 (stdout: $(cat "$OUT"))"; }

cases() {
  CASE="allow pre-tool-use"; reset
  run pre-tool-use '{"session_id":"s1","prompt_id":"p1","tool_name":"exec","tool_input":{"command":"ls"}}'
  expect_rc 0; expect_empty
  check 'req["path"] == "/policy/pre-tool-use"'
  check 'req["body"]["hook_type"] == "pre-tool-use" and req["body"]["event"]["tool_input"]["command"] == "ls"'
  check 'req["body"]["client"]["name"] == "devin-cli" and req["headers"]["x-lumia-hook-type"] == "pre-tool-use"'
  check 'req["headers"]["user-agent"].startswith("lumia-devin-plugin/")'

  CASE="block user-prompt-submit"; reset
  respond '{"decision":"block","reason":"Contains \"secret\" data"}'
  run user-prompt-submit '{"session_id":"s1","prompt_id":"p1","prompt":"my key is sk-123"}'
  expect_rc 2
  check 'out == {"decision": "block", "reason": "Contains \"secret\" data"}'
  grep -q 'Contains "secret" data' "$ERR" && ok || fail "stderr missing reason: $(cat "$ERR")"
  check 'req["body"]["event"]["prompt"] == "my key is sk-123"'

  CASE="block without reason"; reset
  respond '{"decision":"BLOCK"}'
  run pre-tool-use '{"tool_name":"webfetch","tool_input":{}}'
  expect_rc 2; check 'out["reason"] == "Blocked by Lumia Security policy."'

  CASE="block post-tool-use"; reset
  respond '{"decision":"block","reason":"PII in tool output"}'
  run post-tool-use '{"tool_name":"read","tool_input":{"path":"a"},"tool_response":{"success":true,"output":"ssn 123-45-6789","error":null}}'
  expect_rc 2; check 'out["reason"] == "PII in tool output"'
  check 'req["body"]["event"]["tool_response"]["output"] == "ssn 123-45-6789"'

  CASE="block permission-request"; reset
  respond '{"decision":"block","reason":"nope"}'
  run permission-request '{"tool_name":"exec","tool_input":{"command":"curl x"}}'
  expect_rc 2; check 'out["decision"] == "block"'

  CASE="allow permission-request never approves"; reset
  run permission-request '{"tool_name":"exec","tool_input":{"command":"ls"}}'
  expect_rc 0; expect_empty

  CASE="block stop"; reset
  respond '{"decision":"block","reason":"Response leaked a credential."}'
  run stop '{"session_id":"s1","prompt_id":"p1","stop_hook_active":false,"last_assistant_message":"here: sk-1"}'
  expect_rc 0
  check 'out["decision"] == "block" and "Response leaked a credential." in out["reason"]'
  check 'req["body"]["event"]["last_assistant_message"] == "here: sk-1"'

  CASE="stop does not loop"; reset
  respond '{"decision":"block","reason":"x"}'
  run stop '{"stop_hook_active": true}'
  expect_rc 0; expect_empty

  CASE="audit-only events ignore block"; reset
  respond '{"decision":"block","reason":"x"}'
  for h in session-start session-end post-compaction; do
    run "$h" '{"session_id":"s1","source":"startup"}'
    expect_rc 0; expect_empty
    check "req['path'] == '/policy/$h'"
  done

  CASE="HTTP 500 fails open"; reset
  printf 500 > "$STATE/status"; respond '{"decision":"block"}'
  run pre-tool-use '{"tool_name":"exec"}'
  expect_rc 0; expect_empty

  CASE="HTTP 500 fail-closed"; reset
  printf 500 > "$STATE/status"
  printf '%s' '{"tool_name":"exec"}' | LUMIA_FAIL_CLOSED=1 sh "$HOOK" pre-tool-use >"$OUT" 2>"$ERR"; RC=$?
  expect_rc 2; check '"unavailable" in out["reason"]'

  CASE="HTTP 401 fails open loudly"; reset
  printf 401 > "$STATE/status"
  run pre-tool-use '{"tool_name":"exec"}'
  expect_rc 0; expect_empty
  grep -q 'WARNING' "$ERR" && ok || fail "no warning on 401"

  CASE="garbage response fails open"; reset
  respond 'not json at all'
  run pre-tool-use '{"tool_name":"exec"}'
  expect_rc 0; expect_empty

  CASE="timeout fails open"; reset
  printf 3 > "$STATE/delay"
  printf '%s' '{"tool_name":"exec"}' | LUMIA_POLICY_TIMEOUT=1 sh "$HOOK" pre-tool-use >"$OUT" 2>"$ERR"; RC=$?
  expect_rc 0; expect_empty

  CASE="unreachable fails open"; reset
  printf '%s' '{"tool_name":"exec"}' | LUMIA_POLICY_URL="http://127.0.0.1:9/policy" sh "$HOOK" pre-tool-use >"$OUT" 2>"$ERR"; RC=$?
  expect_rc 0; expect_empty

  CASE="unknown hook type"; reset
  run bogus '{}'
  expect_rc 0; expect_empty
  [ ! -f "$STATE/last_request.json" ] && ok || fail "request was sent"

  CASE="disabled"; reset
  printf '%s' '{}' | LUMIA_POLICY_DISABLED=1 sh "$HOOK" pre-tool-use >"$OUT" 2>"$ERR"; RC=$?
  expect_rc 0; [ ! -f "$STATE/last_request.json" ] && ok || fail "request was sent"

  CASE="no devin oidc token on a laptop"; reset
  run pre-tool-use '{"tool_name":"exec"}'
  expect_rc 0
  check '"x-lumia-devin-oidc" not in req["headers"]'
  [ ! -f "$STATE/oidc_request.txt" ] && ok || fail "exchange attempted without a token file"

  CASE="devin oidc token exchanged and sent"; reset
  printf 'session.oidc.token\n' > "$STATE/oidc_token"
  printf '%s' '{"tool_name":"exec"}' | LUMIA_DEVIN_OIDC_TOKEN_FILE="$STATE/oidc_token" sh "$HOOK" pre-tool-use >"$OUT" 2>"$ERR"; RC=$?
  expect_rc 0
  check 'req["headers"].get("x-lumia-devin-oidc") == "aud.scoped.token"'
  grep -q 'subject_token=session.oidc.token&' "$STATE/oidc_request.txt" && ok || fail "subject token not sent (trailing newline?): $(cat "$STATE/oidc_request.txt")"
  grep -q 'audience=lumia-guardrail' "$STATE/oidc_request.txt" && ok || fail "audience not sent"
  grep -q 'subject_keys=org_id' "$STATE/oidc_request.txt" && ok || fail "subject_keys not sent (Devin rejects an exchange without them)"
  grep -q 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange' "$STATE/oidc_request.txt" && ok || fail "grant_type not sent"

  CASE="devin oidc token reused from cache"; rm -f "$STATE/oidc_request.txt"
  printf '%s' '{"tool_name":"exec"}' | LUMIA_DEVIN_OIDC_TOKEN_FILE="$STATE/oidc_token" sh "$HOOK" pre-tool-use >"$OUT" 2>"$ERR"; RC=$?
  check 'req["headers"].get("x-lumia-devin-oidc") == "aud.scoped.token"'
  [ ! -f "$STATE/oidc_request.txt" ] && ok || fail "token re-exchanged within the cache window"

  CASE="devin oidc exchange failure sends no token"; reset
  printf 500 > "$STATE/oidc_status"; printf '%s' '{"error":"nope"}' > "$STATE/oidc_response.json"
  printf '%s' '{"tool_name":"exec"}' | LUMIA_DEVIN_OIDC_TOKEN_FILE="$STATE/oidc_token" sh "$HOOK" pre-tool-use >"$OUT" 2>"$ERR"; RC=$?
  expect_rc 0
  check '"x-lumia-devin-oidc" not in req["headers"]'

  CASE="git email in client"; reset
  run session-start '{"session_id":"s1"}'
  check '"git_email" in req["body"]["client"]'

  CASE="empty stdin"; reset
  printf '' | sh "$HOOK" session-start >"$OUT" 2>"$ERR"; RC=$?
  expect_rc 0; check 'req["body"]["event"] == {}'
}

MODE=sed; export LUMIA_NO_JQ=1; cases
if command -v jq >/dev/null 2>&1; then
  MODE=jq; export LUMIA_NO_JQ=0; cases

  CASE="stop transcript capture"; reset
  T="$STATE/transcript.jsonl"
  printf '%s\n' '{"type":"user","message":{"role":"user","content":"hi"}}' \
    '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"first"}]}}' \
    '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"final answer"}]}}' > "$T"
  run stop "{\"stop_hook_active\":false,\"transcript_path\":\"$T\"}"
  expect_rc 0; check 'req["body"]["event"]["last_assistant_message"] == "final answer"'

  CASE="oversized tool output truncated"; reset
  big="$(head -c 2000 /dev/zero | tr '\0' 'a')"
  printf '{"tool_name":"read","tool_input":{"path":"x"},"tool_response":{"success":true,"output":"%s"}}' "$big" \
    | LUMIA_MAX_FIELD_CHARS=100 sh "$HOOK" post-tool-use >"$OUT" 2>"$ERR"; RC=$?
  expect_rc 0
  check 'req["body"]["event"]["tool_response"]["output"].endswith("[truncated by lumia plugin]") and len(req["body"]["event"]["tool_response"]["output"]) < 200'
  check 'req["body"]["event"]["tool_input"]["path"] == "x"'
else
  echo "jq not installed; skipped jq mode"
fi

echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
