#!/bin/sh
# Tests install.sh with a throwaway HOME: config merge, idempotency, the env file, and
# that the installed hook command reaches a mock Lumen. Requires sh, curl, python3.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"
trap 'kill $SERVER_PID 2>/dev/null; rm -rf "$T"' EXIT INT TERM
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }

python3 "$ROOT/tests/mock_server.py" "$T" & SERVER_PID=$!
i=0; while [ ! -s "$T/port" ]; do i=$((i + 1)); [ $i -gt 50 ] && { echo "mock server did not start"; exit 1; }; sleep 0.1; done
PORT="$(cat "$T/port")"

H="$T/home"; mkdir -p "$H/.config/devin"
# An existing config with an unrelated hook and setting, which must survive.
printf '%s\n' '{"model":"x","hooks":{"PreToolUse":[{"matcher":"^exec$","hooks":[{"type":"command","command":"./other.sh"}]}]}}' > "$H/.config/devin/config.json"

# Without the secret: refuses.
HOME="$H" LUMIA_POLICY_URL= sh "$ROOT/install.sh" 2>/dev/null && fail "installed without LUMIA_POLICY_URL" || ok
HOME="$H" LUMIA_POLICY_URL=http://plain sh "$ROOT/install.sh" 2>/dev/null && fail "accepted a non-https URL" || ok

for run in 1 2; do
  HOME="$H" LUMIA_POLICY_URL="https://lumen.example:8443/policy/" sh "$ROOT/install.sh" 2>"$T/err" || fail "install run $run: $(cat "$T/err")"
done

python3 - "$H" <<'PY' && ok || fail "config check"
import json, sys, os
h = sys.argv[1]
c = json.load(open(f"{h}/.config/devin/config.json"))
assert c["model"] == "x", "unrelated setting lost"
hooks = c["hooks"]
assert len(hooks) == 8, sorted(hooks)
pre = hooks["PreToolUse"]
assert pre[0]["hooks"][0]["command"] == "./other.sh", "unrelated hook lost"
lumia = [e for ev in hooks.values() for e in ev if "lumia-hook.sh" in e["hooks"][0]["command"]]
assert len(lumia) == 8, f"expected 8 lumia entries after 2 runs, got {len(lumia)}"
assert all(e.get("matcher") == "" for e in pre if "lumia" in e["hooks"][0]["command"])
env = open(f"{h}/.lumia/lumia.env").read()
assert env == "LUMIA_POLICY_URL=https://lumen.example:8443/policy\n", env
assert oct(os.stat(f"{h}/.lumia/lumia.env").st_mode & 0o777) == "0o600"
PY

# The registered command reaches Lumen, with the URL taken from the env file.
printf 'LUMIA_POLICY_URL=http://127.0.0.1:%s/policy\n' "$PORT" > "$H/.lumia/lumia.env"
cmd="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['hooks']['UserPromptSubmit'][0]['hooks'][0]['command'])" "$H/.config/devin/config.json")"
(cd /tmp && printf '%s' '{"session_id":"s","prompt_id":"p","prompt":"hi"}' | HOME="$H" TMPDIR="$T" LUMIA_DEVIN_OIDC_TOKEN_FILE=/nonexistent sh -c "$cmd") >/dev/null 2>&1
python3 -c "import json,sys;r=json.load(open(sys.argv[1]));assert r['path']=='/policy/user-prompt-submit' and r['body']['event']['prompt']=='hi'" "$T/last_request.json" && ok || fail "hook did not reach Lumen via the env file"

# The runtime environment wins over the env file.
rm -f "$T/last_request.json"
(cd /tmp && printf '{}' | HOME="$H" TMPDIR="$T" LUMIA_POLICY_URL="http://127.0.0.1:$PORT/other" LUMIA_DEVIN_OIDC_TOKEN_FILE=/nonexistent sh -c "$cmd") >/dev/null 2>&1
python3 -c "import json,sys;assert json.load(open(sys.argv[1]))['path']=='/other/user-prompt-submit'" "$T/last_request.json" && ok || fail "LUMIA_POLICY_URL did not override the env file"

# No URL anywhere: no request, allowed.
rm -f "$T/last_request.json" "$H/.lumia/lumia.env"
(cd /tmp && printf '{}' | HOME="$H" TMPDIR="$T" LUMIA_POLICY_URL= sh -c "$cmd" >/dev/null 2>&1); rc=$?
[ $rc -eq 0 ] && [ ! -f "$T/last_request.json" ] && ok || fail "unconfigured hook: rc=$rc, request sent=$([ -f "$T/last_request.json" ] && echo yes || echo no)"

echo "install: passed $PASS failed $FAIL"
[ "$FAIL" -eq 0 ]
