# Threat Model & Failure Modes

`claude-safety-hooks` is a **second-line, heuristic-based defense** designed to catch high-velocity agent confusion in Claude Code sessions. It is not a sandbox.

## What this defends against

1. **Scope drift during long autonomous runs:** Agents issuing valid commands in the wrong environment across 200+ iterations.
2. **Credential mismatch:** Running a `deploy` or `DROP` against prod because a `.env` file from a previous repo was still active.
3. **Sandbox-to-Prod leakage:** The "yes I'm ready" effect where an agent continues executing past its sandbox boundary.

## What this does NOT defend against

1. **Malicious intent with shell access:** A determined operator who knows the hooks can disable them by modifying `.claude/settings.json` or removing the hook files.
2. **Low-privilege account attacks:** If your API/CLI creds are scoped to `AdministratorAccess`, a whitelist hook could be evaded by brute-forcing a list of whitelisted read endpoints if those endpoints allow destructive state via query parameters.
3. **Zero-day or custom CLI tooling:** The hooks rely on command matching (e.g., `aws`, `sf`, `sfdx`). Custom wrappers calling the same SDK libraries without the binary name will not trigger the hook.

## Known failure modes

| Scenario | Result | Severity | Mitigation |
|---|---|---|---|
| Hook script is removed/silenced by the agent | Agent executes unblocked | Critical | Enforce read-only permissions on `.claude/settings.json` or the hooks themselves. |
| Env vars are set in a shared session (tmux/screen) | Cross-tenant pollution | High | Use environment-scoped hashes; never share passkeys between prod/sandbox. |
| Agent bypasses `exit 2` by using `exec` or backgrounding | Command executes out of band | Medium | Audit system logs for unmasked prod writes. |
