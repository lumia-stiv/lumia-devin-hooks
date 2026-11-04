#!/bin/sh
# Installs the Lumia Security policy hooks into a Devin environment.
#
# Meant for the `initialize` step of a Devin organization blueprint, so the hooks are
# part of the environment snapshot and run from the very first prompt of a session:
#
#   initialize:
#     - name: Lumia Security guardrail hooks
#       run: curl -fsSL https://raw.githubusercontent.com/lumia-stiv/lumia-devin-hooks/main/install.sh | sh
#
# Requires the LUMIA_POLICY_URL organization secret (your tenant's Lumen policy URL,
# ending in /policy). It is written to ~/.lumia/lumia.env (mode 600): Devin strips
# secrets from the snapshot, but keeps files written during initialize. At run time
# the hook still prefers a LUMIA_POLICY_URL in its environment.
#
# Idempotent: re-running replaces earlier Lumia hook entries and keeps all others.
#
# Environment:
#   LUMIA_POLICY_URL     required, e.g. https://<tenant host>:8443/policy
#   LUMIA_HOOKS_REF      git ref to install from (default: main; pin a tag or commit)
#   LUMIA_HOOKS_DIR      install dir (default: ~/.lumia)
#   DEVIN_CONFIG         Devin user config (default: ~/.config/devin/config.json)

set -eu

REF="${LUMIA_HOOKS_REF:-main}"
SOURCE="${LUMIA_HOOKS_SOURCE:-https://raw.githubusercontent.com/lumia-stiv/lumia-devin-hooks/$REF}"
DEST="${LUMIA_HOOKS_DIR:-$HOME/.lumia}"
CONFIG="${DEVIN_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/devin/config.json}"

say() { printf 'lumia-install: %s\n' "$*" >&2; }
die() { say "ERROR: $*"; exit 1; }

[ -n "${LUMIA_POLICY_URL:-}" ] || die "LUMIA_POLICY_URL is not set. Add it as a Devin organization secret (Settings > Secrets)."
case "$LUMIA_POLICY_URL" in
  https://*) ;;
  *) die "LUMIA_POLICY_URL must be an https:// URL" ;;
esac
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required to update $CONFIG"

mkdir -p "$DEST/hooks" "$(dirname "$CONFIG")"

# The hook script: from this checkout when run as ./install.sh, else downloaded.
here=""
case "$0" in */install.sh|install.sh) here="$(cd "$(dirname "$0")" && pwd)" ;; esac
if [ -n "$here" ] && [ -f "$here/hooks/lumia-hook.sh" ]; then
  cp "$here/hooks/lumia-hook.sh" "$DEST/hooks/lumia-hook.sh.tmp"
else
  curl -fsSL --max-time 30 "$SOURCE/hooks/lumia-hook.sh" -o "$DEST/hooks/lumia-hook.sh.tmp" \
    || die "could not download $SOURCE/hooks/lumia-hook.sh"
fi
head -n 1 "$DEST/hooks/lumia-hook.sh.tmp" | grep -q '^#!/bin/sh' || die "downloaded hook script looks wrong"
chmod 755 "$DEST/hooks/lumia-hook.sh.tmp"
mv -f "$DEST/hooks/lumia-hook.sh.tmp" "$DEST/hooks/lumia-hook.sh"

( umask 077 && printf 'LUMIA_POLICY_URL=%s\n' "${LUMIA_POLICY_URL%/}" > "$DEST/lumia.env" )

# Merge the hooks into Devin's user config, replacing earlier Lumia entries only.
HOOK="$DEST/hooks/lumia-hook.sh" CONFIG="$CONFIG" python3 - <<'PY'
import json, os, shlex

hook, path = os.environ["HOOK"], os.environ["CONFIG"]
events = {
    "SessionStart": "session-start",
    "UserPromptSubmit": "user-prompt-submit",
    "PreToolUse": "pre-tool-use",
    "PermissionRequest": "permission-request",
    "PostToolUse": "post-tool-use",
    "Stop": "stop",
    "PostCompaction": "post-compaction",
    "SessionEnd": "session-end",
}
tool_events = {"PreToolUse", "PermissionRequest", "PostToolUse"}

config = {}
if os.path.exists(path):
    with open(path, encoding="utf-8") as f:
        text = f.read().strip()
    if text:
        config = json.loads(text)  # refuse to clobber a config we can't parse
if not isinstance(config, dict):
    raise SystemExit(f"{path} is not a JSON object")
hooks = config.setdefault("hooks", {})

def is_lumia(entry):
    return any("lumia-hook.sh" in (h.get("command") or "") for h in entry.get("hooks", []))

for event, hook_type in events.items():
    kept = [e for e in hooks.get(event, []) if isinstance(e, dict) and not is_lumia(e)]
    entry = {"hooks": [{"type": "command", "command": f"sh {shlex.quote(hook)} {hook_type}", "timeout": 15}]}
    if event in tool_events:
        entry = {"matcher": "", **entry}
    hooks[event] = kept + [entry]

tmp = path + ".lumia.tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
PY

say "installed $DEST/hooks/lumia-hook.sh and registered 8 hooks in $CONFIG"
say "Lumen URL written to $DEST/lumia.env (not printed: it identifies your tenant)"
