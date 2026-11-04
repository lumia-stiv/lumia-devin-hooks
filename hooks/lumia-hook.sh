#!/bin/sh
# Lumia Security policy hook for Devin.
#
# Usage (installed by install.sh into Devin's hooks config):  lumia-hook.sh <hook_type>
#
# Reads the Devin hook payload from stdin, POSTs it to
#   ${LUMIA_POLICY_URL}/<hook_type>
# and translates Lumia's {"decision":"allow"|"block","reason":"..."} answer into
# Devin's hook output (stdout JSON + exit code).
#
# The Lumen URL is never built in: it comes from LUMIA_POLICY_URL (a Devin
# organization secret), else from the env file install.sh writes. Without one the
# hook does nothing and allows.
#
# Fails open by default: network errors, timeouts, non-2xx responses and
# unparseable bodies allow the action. Set LUMIA_FAIL_CLOSED=1 to block instead.
#
# Requires: POSIX sh, curl. Uses jq when present (better JSON handling and
# response capture on Stop), falls back to sed otherwise.

set -u

PLUGIN_VERSION="0.2.0"
LUMIA_ENV_FILE="${LUMIA_ENV_FILE:-${HOME:-/tmp}/.lumia/lumia.env}"

HOOK_TYPE="${1:-}"
POLICY_URL="${LUMIA_POLICY_URL:-}"
if [ -z "$POLICY_URL" ] && [ -r "$LUMIA_ENV_FILE" ]; then
  # Only the value is read: the file is never sourced, so it can't run code.
  POLICY_URL="$(sed -n 's/^LUMIA_POLICY_URL=//p' "$LUMIA_ENV_FILE" | head -n 1 | tr -d '\r')"
fi
POLICY_URL="${POLICY_URL%/}"
TIMEOUT="${LUMIA_POLICY_TIMEOUT:-10}"
FAIL_CLOSED="${LUMIA_FAIL_CLOSED:-0}"
DEFAULT_REASON="Blocked by Lumia Security policy."

log() {
  if [ "${LUMIA_DEBUG:-0}" = "1" ]; then
    printf 'lumia[%s]: %s\n' "$HOOK_TYPE" "$*" >&2
  fi
  return 0
}

# One line per run, so "did the hook run, and what happened" is answerable on the box:
#   tail /tmp/lumia-hook.log      (LUMIA_HOOK_LOG to move it, "" to turn it off)
HOOK_LOG="${LUMIA_HOOK_LOG-${TMPDIR:-/tmp}/lumia-hook.log}"
code="-"
run_note="-"
on_exit() {
  rc=$?
  [ -n "$HOOK_LOG" ] && printf '%s %s rc=%s http=%s v=%s note=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" "${HOOK_TYPE:-?}" "$rc" "$code" "$PLUGIN_VERSION" "$run_note" \
    >> "$HOOK_LOG" 2>/dev/null
  return 0
}
trap on_exit EXIT

case "$HOOK_TYPE" in
  session-start|user-prompt-submit|pre-tool-use|post-tool-use|permission-request|stop|post-compaction|session-end) ;;
  *) log "unknown hook type '$HOOK_TYPE'; ignoring"; exit 0 ;;
esac

if [ "${LUMIA_POLICY_DISABLED:-0}" = "1" ]; then
  exit 0
fi

if [ -z "$POLICY_URL" ]; then
  # Not configured: nothing to ask, so allow (or block, if told to fail closed).
  run_note="no-lumia-url"
  printf 'lumia[%s]: WARNING: no Lumen URL (set LUMIA_POLICY_URL or run install.sh); policy NOT enforced\n' "$HOOK_TYPE" >&2
  if [ "${LUMIA_FAIL_CLOSED:-0}" = "1" ]; then
    case "$HOOK_TYPE" in
      user-prompt-submit|pre-tool-use|permission-request|post-tool-use)
        printf '{"decision":"block","reason":"Lumia Security policy is not configured on this machine."}\n'
        exit 2 ;;
    esac
  fi
  exit 0
fi

have() {
  if [ "$1" = "jq" ] && [ "${LUMIA_NO_JQ:-0}" = "1" ]; then return 1; fi
  command -v "$1" >/dev/null 2>&1
}

# Escape a plain string for embedding inside a JSON string literal.
json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n\r\t' '   ' | tr -d '\000-\037'
}

input="$(cat)"
[ -n "$input" ] || input='{}'

# --- Response capture on Stop -------------------------------------------------
# Devin's documented Stop payload has no assistant text. If Devin provides it
# (last_assistant_message) we forward it as is; otherwise, when a transcript
# path is given and jq is available, extract the last assistant message.
if [ "$HOOK_TYPE" = "stop" ] && have jq; then
  has_msg="$(printf '%s' "$input" | jq -r 'has("last_assistant_message")' 2>/dev/null || echo false)"
  tpath="$(printf '%s' "$input" | jq -r '.transcript_path // empty' 2>/dev/null || true)"
  if [ "$has_msg" != "true" ] && [ -n "$tpath" ] && [ -r "$tpath" ]; then
    msg="$(tail -n 500 "$tpath" | jq -rs '
      [ .[] | select(.type == "assistant" or .role == "assistant" or .message.role == "assistant") ]
      | last
      | (.message.content // .content // .text // "")
      | if type == "array" then map(select(.type == "text") | .text) | join("\n") else tostring end
    ' 2>/dev/null || true)"
    if [ -n "$msg" ] && [ "$msg" != "null" ]; then
      enriched="$(printf '%s' "$input" | jq -c --arg m "$msg" '. + {last_assistant_message: $m}' 2>/dev/null || true)"
      [ -n "$enriched" ] && input="$enriched"
    fi
  fi
fi

# --- Size cap -------------------------------------------------------------------
# Lumia rejects bodies over 1 MiB (HTTP 413 -> fail open), which would let a huge
# tool result skip policy. Truncate the bulky string fields instead (needs jq).
MAX_FIELD="${LUMIA_MAX_FIELD_CHARS:-262144}"
if have jq && [ "$(printf '%s' "$input" | wc -c)" -gt "$MAX_FIELD" ]; then
  truncated="$(printf '%s' "$input" | jq -c --argjson n "$MAX_FIELD" '
    def cap: if type == "string" and length > $n then .[0:$n] + "...[truncated by lumia plugin]" else . end;
    (if .tool_response.output? then .tool_response.output |= cap else . end)
    | (if .tool_input? then .tool_input |= walk(cap) else . end)
    | (if .last_assistant_message? then .last_assistant_message |= cap else . end)
    | (if .prompt? then .prompt |= cap else . end)
    | (if .summary? then .summary |= cap else . end)
  ' 2>/dev/null || true)"
  [ -n "$truncated" ] && input="$truncated"
fi

# --- Build request --------------------------------------------------------------
os_user="${USER:-${USERNAME:-$(id -un 2>/dev/null || echo unknown)}}"
host_name="$(hostname 2>/dev/null || echo unknown)"
platform="$(uname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo unknown)"
# Informational fallback identity (unverified): Lumia trusts only the SNI user or a Devin
# OIDC token, but logs this for local CLI sessions, which have no OIDC token.
git_email="$(git config user.email 2>/dev/null || true)"

body="$(printf '{"hook_type":"%s","client":{"name":"devin-cli","plugin_version":"%s","hostname":"%s","os_user":"%s","git_email":"%s","platform":"%s","cwd":"%s","project_dir":"%s"},"event":%s}' \
  "$HOOK_TYPE" "$PLUGIN_VERSION" \
  "$(json_escape "$host_name")" "$(json_escape "$os_user")" "$(json_escape "$git_email")" "$(json_escape "$platform")" \
  "$(json_escape "$(pwd)")" "$(json_escape "${DEVIN_PROJECT_DIR:-}")" \
  "$input")"

# --- Devin OIDC identity (Devin Cloud) -------------------------------------------
# A cloud session holds a Devin-issued token at /opt/.devin/oidc_token. Exchange it
# (RFC 8693) for one scoped to the Lumia guardrail, which carries the session's
# requesting_user_email; Lumia verifies it against Devin's JWKS. Exchanged tokens live
# 60s, so one is reused for 40s. Any failure just sends no token (the SNI user applies).
OIDC_TOKEN_FILE="${LUMIA_DEVIN_OIDC_TOKEN_FILE:-/opt/.devin/oidc_token}"
OIDC_EXCHANGE_URL="${LUMIA_DEVIN_OIDC_EXCHANGE_URL:-https://app.devin.ai/api/oidc/token}"
OIDC_AUDIENCE="${LUMIA_DEVIN_OIDC_AUDIENCE:-lumia-guardrail}"
OIDC_CACHE_SECONDS="${LUMIA_DEVIN_OIDC_CACHE_SECONDS:-40}"
# Devin rejects an exchange without subject_keys ("subject_keys must be non-empty"); they only
# shape the token's sub claim, requesting_user_email is present either way.
OIDC_SUBJECT_KEYS="${LUMIA_DEVIN_OIDC_SUBJECT_KEYS:-org_id requesting_user_id}"

file_mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || echo 0; }

devin_identity_token() {
  [ "${LUMIA_DEVIN_OIDC_DISABLED:-0}" = "1" ] && return 1
  [ -r "$OIDC_TOKEN_FILE" ] || return 1
  cache="${TMPDIR:-/tmp}/lumia-devin-oidc-$(id -u 2>/dev/null || echo 0)-$(printf '%s' "$OIDC_AUDIENCE" | tr -c 'A-Za-z0-9_-' '_')"
  if [ -s "$cache" ] && [ $(( $(date +%s) - $(file_mtime "$cache") )) -lt "$OIDC_CACHE_SECONDS" ]; then
    cat "$cache"
    return 0
  fi
  # The session token goes on stdin, not argv, so it isn't visible in the process list.
  resp="$(printf '%s' "$(cat "$OIDC_TOKEN_FILE")" | curl -sS --max-time 5 -X POST \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    --data-urlencode "subject_token@-" \
    --data-urlencode "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
    --data-urlencode "audience=$OIDC_AUDIENCE" \
    --data-urlencode "subject_keys=$OIDC_SUBJECT_KEYS" \
    "$OIDC_EXCHANGE_URL" 2>/dev/null)" || return 1
  if have jq; then
    tok="$(printf '%s' "$resp" | jq -r '.access_token // empty' 2>/dev/null)"
  else
    tok="$(printf '%s' "$resp" | tr '\n\r' '  ' | sed -nE 's/.*"access_token"[[:space:]]*:[[:space:]]*"([A-Za-z0-9._-]+)".*/\1/p')"
  fi
  [ -n "$tok" ] || return 1
  ( umask 077 && printf '%s' "$tok" > "$cache.$$" && mv -f "$cache.$$" "$cache" ) 2>/dev/null || true
  printf '%s' "$tok"
}

# --- Decision handling -------------------------------------------------------
# emit_block <reason as escaped JSON string content> <reason as plain text>
emit_block() {
  r_json="$1"
  r_text="$2"
  case "$HOOK_TYPE" in
    user-prompt-submit|pre-tool-use|permission-request|post-tool-use)
      printf '{"decision":"block","reason":"%s"}\n' "$r_json"
      printf '%s\n' "$r_text" >&2
      exit 2
      ;;
    stop)
      # A blocking Stop keeps the agent working with `reason` as its next
      # instruction. Never block twice in a row, or the agent loops forever.
      if printf '%s' "$input" | grep -Eq '"stop_hook_active"[[:space:]]*:[[:space:]]*true'; then
        log "stop_hook_active=true; not blocking again"
        exit 0
      fi
      printf '{"decision":"block","reason":"Lumia Security policy blocked your last response: %s Do not repeat the blocked content. Tell the user that the response was blocked by their organization'"'"'s security policy."}\n' "$r_json"
      exit 0
      ;;
    *)
      # session-start, session-end, post-compaction: audit only.
      exit 0
      ;;
  esac
}

on_failure() {
  log "$1"
  run_note="$(printf '%s' "$1" | tr ' ' '_')"
  if [ "$FAIL_CLOSED" = "1" ]; then
    emit_block "Lumia Security policy service is unavailable ($(json_escape "$1"))." \
      "Lumia Security policy service is unavailable ($1)."
  fi
  exit 0
}

have curl || on_failure "curl not found"

# --- Lumen CA ----------------------------------------------------------------------
# Lumen serves a certificate from the tenant's private CA, and sends the whole chain up
# to its self-signed root. Unless LUMIA_CA_CERT is set, the session-start hook checks
# whether the system trust store already verifies Lumen; if not, it takes the root from
# the chain Lumen presents and caches it, and every hook trusts that file.
# PoC: the root is trusted on first use, without pinning. LUMIA_CA_AUTO=0 turns this off.
LUMEN_ORIGIN="$(printf '%s' "$POLICY_URL" | sed -E 's#^(https?://[^/]+).*#\1#')"
CA_CACHE="${LUMIA_CA_CACHE:-${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/lumia/lumen-ca-$(printf '%s' "$LUMEN_ORIGIN" | cksum | cut -d' ' -f1).pem}"

# last_pem_block: the last PEM certificate on stdin (the chain's root).
last_pem_block() {
  awk '/-----BEGIN CERTIFICATE-----/{buf=""; inb=1} inb{buf=buf $0 "\n"} /-----END CERTIFICATE-----/{last=buf; inb=0} END{printf "%s", last}'
}

fetch_lumen_root() {
  hostport="${LUMEN_ORIGIN#*://}"
  case "$hostport" in *:*) ;; *) hostport="$hostport:443" ;; esac
  # curl >= 7.88 prints the chain it was sent; -k only for this read, nothing is sent.
  pem="$(curl -sk --max-time 5 -o /dev/null -w '%{certs}' "$LUMEN_ORIGIN/health/live" 2>/dev/null | last_pem_block)"
  if [ -z "$pem" ] && have openssl; then
    pem="$(openssl s_client -connect "$hostport" -servername "${hostport%:*}" -showcerts </dev/null 2>/dev/null | last_pem_block)"
  fi
  [ -n "$pem" ] || return 1
  mkdir -p "$(dirname "$CA_CACHE")" 2>/dev/null || return 1
  printf '%s' "$pem" > "$CA_CACHE.$$" && mv -f "$CA_CACHE.$$" "$CA_CACHE"
}

ensure_lumen_ca() {
  [ -n "${LUMIA_CA_CERT:-}" ] && return 0
  [ "${LUMIA_CA_AUTO:-1}" = "1" ] || return 0
  case "$LUMEN_ORIGIN" in https://*) ;; *) return 0 ;; esac
  if [ "$HOOK_TYPE" != "session-start" ] && [ -f "$CA_CACHE.public" ]; then return 0; fi
  if [ "$HOOK_TYPE" = "session-start" ] || [ ! -s "$CA_CACHE" ]; then
    if curl -s --max-time 5 -o /dev/null "$LUMEN_ORIGIN/health/live" 2>/dev/null; then
      # Publicly trusted: no CA file needed until the next session start re-checks.
      rm -f "$CA_CACHE" 2>/dev/null
      mkdir -p "$(dirname "$CA_CACHE")" 2>/dev/null && : > "$CA_CACHE.public"
      return 0
    fi
    rm -f "$CA_CACHE.public" 2>/dev/null
    if fetch_lumen_root; then log "trusting Lumen's root CA from its chain ($CA_CACHE)"; else log "could not read Lumen's certificate chain"; fi
  fi
  [ -s "$CA_CACHE" ] && LUMIA_CA_CERT="$CA_CACHE"
  return 0
}

ensure_lumen_ca
set --
if [ -n "${LUMIA_CA_CERT:-}" ]; then
  set -- --cacert "$LUMIA_CA_CERT"
  # Windows' Schannel curl demands a revocation check a private CA can't answer.
  if curl -V 2>/dev/null | grep -qi schannel; then set -- "$@" --ssl-no-revoke; fi
fi
if identity_token="$(devin_identity_token)"; then
  set -- "$@" -H "X-Lumia-Devin-Oidc: $identity_token"
  run_note="oidc"
else
  log "no Devin OIDC identity token (not a Devin Cloud session, or the exchange failed)"
  run_note="no-oidc"
fi

warn() { printf 'lumia[%s]: WARNING: %s\n' "$HOOK_TYPE" "$*" >&2; }

raw="$(printf '%s' "$body" | curl -sS --max-time "$TIMEOUT" -X POST "$@" \
  -H "Content-Type: application/json" \
  -H "User-Agent: lumia-devin-plugin/$PLUGIN_VERSION" \
  -H "X-Lumia-Client: devin-cli" \
  -H "X-Lumia-Hook-Type: $HOOK_TYPE" \
  --data-binary @- \
  -w '\n%{http_code}' \
  "$POLICY_URL/$HOOK_TYPE" 2>/dev/null)"
rc=$?

if [ $rc -ne 0 ]; then
  case $rc in
    35|51|58|60|77|83|90|91)
      warn "TLS error talking to Lumia (curl exit $rc); policy NOT enforced. Is the tenant CA trusted? See LUMIA_CA_CERT." ;;
  esac
  on_failure "request failed (curl exit $rc)"
fi

code="$(printf '%s\n' "$raw" | tail -n 1)"
resp="$(printf '%s\n' "$raw" | sed '$d')"

case "$code" in
  2??) ;;
  401|403)
    warn "Lumia rejected the client identity (HTTP $code); policy NOT enforced. Check the tenant hostname in LUMIA_POLICY_URL."
    on_failure "policy endpoint returned HTTP $code" ;;
  *) on_failure "policy endpoint returned HTTP $code" ;;
esac

log "HTTP $code: $resp"
[ -n "$resp" ] || exit 0

if have jq; then
  decision="$(printf '%s' "$resp" | jq -r '.decision // empty' 2>/dev/null)" || on_failure "unparseable response"
  reason_text="$(printf '%s' "$resp" | jq -r '.reason // empty' 2>/dev/null || true)"
  reason_json="$(json_escape "$reason_text")"
else
  flat="$(printf '%s' "$resp" | tr '\n\r' '  ')"
  decision="$(printf '%s' "$flat" | sed -nE 's/.*"decision"[[:space:]]*:[[:space:]]*"([A-Za-z_]*)".*/\1/p' | head -n 1)"
  # Keep the JSON escapes for stdout; unescape the common ones for stderr.
  reason_json="$(printf '%s' "$flat" | sed -nE 's/.*"reason"[[:space:]]*:[[:space:]]*"(([^"\\]|\\.)*)".*/\1/p' | head -n 1)"
  reason_text="$(printf '%s' "$reason_json" | sed -e 's/\\n/ /g' -e 's/\\"/"/g' -e 's/\\\\/\\/g')"
fi

decision="$(printf '%s' "$decision" | tr '[:upper:]' '[:lower:]')"
case "$decision" in
  block|deny)
    [ -n "$reason_text" ] || { reason_text="$DEFAULT_REASON"; reason_json="$DEFAULT_REASON"; }
    log "block: $reason_text"
    emit_block "$reason_json" "$reason_text"
    ;;
  *)
    exit 0
    ;;
esac
