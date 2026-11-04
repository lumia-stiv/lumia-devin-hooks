# Lumia Security hooks for Devin

Enforces your organization's [Lumia Security](https://lumiasecurity.com) AI-usage policy in Devin
sessions. Devin lifecycle hooks send every prompt, tool call, tool result and model response to your
Lumia tenant's Lumen, which allows or blocks each one.

The hooks are installed by the **organization blueprint**, so they are part of the environment
snapshot and run from a session's first prompt. Hooks shipped as a Devin plugin are only loaded once
a session's repository is set up, so they miss the first prompt.

## Setup (Devin Cloud)

1. **Add the organization secret** `LUMIA_POLICY_URL` under Settings > Secrets. Its value is your
   tenant's Lumen policy URL, provided by Lumia, ending in `/policy`.
2. **Add a step to the organization blueprint's `initialize`:**

   ```yaml
   initialize:
     - name: Lumia Security guardrail hooks
       run: curl -fsSL https://raw.githubusercontent.com/lumia-stiv/lumia-devin-hooks/main/install.sh | sh
   ```

   Pin a tag or commit for production: replace `main` in the URL, and set `LUMIA_HOOKS_REF` to the
   same ref, so the script it downloads matches.
3. **Save the blueprint.** Devin rebuilds the environment. Sessions started after the build have the
   hooks.

If you also installed the Lumia Devin *plugin*, remove it. Otherwise every event is sent twice.

### What `install.sh` does

- Installs the hook script to `~/.lumia/hooks/lumia-hook.sh`.
- Writes the secret's value to `~/.lumia/lumia.env` (mode 600). Devin strips secrets from the
  snapshot but keeps files written during `initialize`. At run time a `LUMIA_POLICY_URL` in the
  hook's environment still takes precedence.
- Registers the 8 hooks in Devin's user config, `~/.config/devin/config.json` under `"hooks"`.
  Earlier Lumia entries are replaced; everything else in the file is kept.

### Verify

In a session's terminal:

```bash
tail /tmp/lumia-hook.log   # one line per hook run: hook, exit code, HTTP status, identity
```

## What is covered

| Devin event         | Lumia sees                                         | On block                     |
|---------------------|----------------------------------------------------|------------------------------|
| `UserPromptSubmit`  | the user's prompt                                  | prompt rejected              |
| `PreToolUse`        | the tool call (`message_user`: Devin's reply)      | tool call denied             |
| `PermissionRequest` | a tool call that needs approval                    | denied (never auto-approves) |
| `PostToolUse`       | the tool's result                                  | result flagged to the agent  |
| `Stop`              | the final response                                 | logged only                  |
| `SessionStart`, `PostCompaction`, `SessionEnd` | session events          | logged only                  |

**Identity.** In Devin Cloud, the hook exchanges the session's Devin OIDC token
(`/opt/.devin/oidc_token`) for one scoped to the guardrail. Lumen verifies it against Devin's JWKS
and attributes events to the session's Devin user.

**Certificates.** If Lumen's certificate isn't trusted system-wide, the hook trusts the root CA that
Lumen presents in its chain, cached at session start.

## Configuration

These variables are read by the hook at run time:

| Variable                | Default              | Meaning                                                      |
|-------------------------|----------------------|--------------------------------------------------------------|
| `LUMIA_POLICY_URL`      | `~/.lumia/lumia.env` | Lumen policy URL. Without one, the hook does nothing and allows. |
| `LUMIA_FAIL_CLOSED`     | `0`                  | `1` blocks when Lumen is unreachable or not configured       |
| `LUMIA_POLICY_TIMEOUT`  | `10`                 | Request timeout in seconds                                   |
| `LUMIA_CA_CERT`         | auto                 | PEM file of the tenant CA                                    |
| `LUMIA_POLICY_DISABLED` | `0`                  | `1` turns the hook off                                       |
| `LUMIA_HOOK_LOG`        | `/tmp/lumia-hook.log`| Run log; empty turns it off                                  |
| `LUMIA_DEBUG`           | `0`                  | `1` logs requests and decisions to stderr                    |

By default the hooks **fail open**: errors and timeouts allow the action.

## Local Devin CLI

```bash
LUMIA_POLICY_URL=https://<your tenant's Lumen>/policy sh install.sh
```

Requirements: POSIX `sh`, `curl` and `python3` (for the installer). `jq` and `openssl` are used when
present.

## Development

```bash
sh tests/run.sh          # hook tests against a mock Lumen (curl, python3)
sh tests/install_test.sh # installer: config merge, idempotency, env file
```
