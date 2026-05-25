# claude-safety-hooks

> Production safety hooks for [Claude Code](https://claude.com/claude-code). Blocks destructive commands against your real infrastructure behind a passkey gate.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## The problem

You hand Claude Code admin credentials and turn it loose on your repo. It writes code, runs commands, and reads output. Then one day it decides — for very plausible-looking reasons — to run:

```bash
aws rds delete-db-instance --db-instance-identifier prod-main --skip-final-snapshot
```

There's no undo. Region wiped, customers offline, RPO blown. The agent didn't "go rogue" — it followed a chain of reasonable-looking steps to a catastrophic conclusion. This is not a hypothetical: agents with broad credentials have already done this to real environments.

The default Claude Code safety model relies on you reviewing every command. That works at low intensity. It does not survive a long autonomous session where 200+ commands fly by.

**This repo is the second line of defense.** Three pre-tool-use hooks that intercept Bash commands *before* they execute, classify them as read vs. write, and block writes against production unless the human types a passkey.

---

## Install

```bash
git clone https://github.com/farjad-hasan/claude-safety-hooks.git
cd claude-safety-hooks
./install.sh
```

The installer copies the three guardians into `.claude/hooks/` and registers them in your project's `.claude/settings.json` as `PreToolUse` hooks for the Bash tool.

Then configure — copy `.env.example` to `.env` and fill in your account IDs and passkey hashes. See [Configuration](#configuration) below.

---

## The three guardians

Each hook covers a different blast radius. Defense postures escalate with the cost of being wrong:

| Hook | Posture | Allows on prod | Blocks on prod |
|---|---|---|---|
| `sf-prod-guardian.sh` | **Blacklist writes** | retrieve, query, describe, log fetch | deploy, data modify, apex run, delete |
| `db-prod-guardian.sh` | **Blacklist writes + connection enforcement** | SELECT, EXPLAIN via read-only wrapper | INSERT/UPDATE/DELETE/DROP/TRUNCATE, raw `psql` to prod |
| `aws-prod-guardian.sh` | **Whitelist reads only** | `describe-*`, `list-*`, `get-*`, `s3 ls/cp` to local | everything else (anything not in the whitelist) |

Why the escalation? Salesforce write damage is usually recoverable from sandbox refresh. DB damage is recoverable from backup. **AWS damage with AdministratorAccess can wipe a region in seconds with no undo.** The whitelist for AWS isn't paranoia — it's the only defense matching the threat model.

---

## How the passkey gate works

When a guardian decides a command targets production and isn't a safe read, it blocks with `exit 2` and prints a message instructing Claude to ask the human for a passkey. The human types it themselves. Claude re-runs the command with the passkey inlined:

```bash
SF_PROD_PASSKEY=<passkey> SF_PROD_CONFIRMED=true sf project deploy start --target-org production
```

The hook computes `sha256(passkey)` and compares it to the hash you configured. If they match, the command runs. If they don't, blocked.

**The passkey itself is never stored, logged, or committed.** Only its SHA-256 hash lives in your environment. You can rotate the passkey by re-hashing — no infrastructure change required.

**Critical**: The hook instructs Claude to *ask the human every time*. Caching, guessing, or reusing the passkey from earlier in the session defeats the gate. The block message in each guardian makes this explicit.

---

## Configuration

Copy `.env.example` to `.env` and source it before starting Claude Code (or set the vars in your shell rc):

```bash
# Required: passkey hashes for each guardian
SF_PROD_PASSKEY_HASH=<64-char sha256 hex>
DB_PROD_PASSKEY_HASH=<64-char sha256 hex>
AWS_PROD_PASSKEY_HASH=<64-char sha256 hex>

# Required: AWS production account
PROD_ACCOUNT_ID=<12-digit account id>

# Optional: non-prod AWS accounts (skipped without prompting)
UAT_ACCOUNT_ID=
DEV_ACCOUNT_ID=
SANDBOX_ACCOUNT_ID=

# Optional: Salesforce production identifiers
SF_PROD_USERNAME=
SF_PROD_ORG_ID=

# Optional: DB name shown in block messages
DB_NAME=
```

Generate a passkey hash:

```bash
echo -n "<your-chosen-passkey>" | sha256sum | awk '{print $1}'
```

Pick a passkey that's memorable to *you* but not guessable. You can reuse the same passkey across all three guardians, or use different ones per service.

---

## Example: a blocked command

Claude attempts:

```bash
aws s3 rb s3://prod-customer-data --force
```

The AWS guardian intercepts and writes to stderr:

```
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  AWS WRITE BLOCKED — AWS PROD GUARDIAN                    ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Command targets PRODUCTION account and is not in the         ║
║  read-only whitelist.                                         ║
║                                                               ║
║  Account: 123456789012 (production)                           ║
║  Command: aws s3 rb s3://prod-customer-data --force           ║
║                                                               ║
║  To proceed, you MUST:                                        ║
║  1. Ask the user for their production PASSKEY                 ║
║  2. User must type the passkey themselves                     ║
║  3. Rerun with both env vars set:                             ║
║     AWS_PROD_PASSKEY=<passkey> AWS_PROD_CONFIRMED=true ...    ║
║                                                               ║
║  NEVER guess, cache, or reuse the passkey from memory.        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

Claude reads this and asks the human. Without the passkey it cannot continue.

---

## Architecture

```
Claude Code Bash tool call
         │
         ▼
   PreToolUse hook (one of these three)
         │
         ├─ Not a sf/db/aws command? → exit 0 (allow)
         │
         ├─ Targets non-prod account? → exit 0 (allow)
         │
         ├─ Targets prod + read-only? → exit 0 (allow)
         │
         ├─ Targets prod + write + valid passkey? → exit 0 (allow)
         │
         └─ Targets prod + write + no/invalid passkey → exit 2 (BLOCK)
                                                          │
                                                          ▼
                                                  Claude sees stderr,
                                                  asks human for passkey
```

Each hook is a single bash script. No daemons, no agents, no network calls. The only "state" is your env vars. Easy to audit (~250 lines per hook), easy to fork, easy to extend.

---

## Extending

Add a fourth guardian — say, for `kubectl` against a prod cluster:

1. Copy `aws-prod-guardian.sh` as a starting template (closest in shape — whitelist posture)
2. Replace the command detection (`grep -qE '...aws\s'` → `'...kubectl\s'`)
3. Replace the production identifier (`PROD_ACCOUNT_ID` → `KUBE_PROD_CONTEXT` or similar)
4. Adjust the read-only whitelist for your tool
5. Register it in `.claude/settings.json` alongside the others

The base shape — env-var-driven config, fail-closed defaults, SHA-256 passkey gate, escalation message instructing Claude to ask the human — is reusable for any high-blast-radius CLI.

---

## What this is not

- **Not a sandbox.** A determined attacker with shell access can disable the hooks. This is defense against *agent confusion*, not against a malicious operator.
- **Not a substitute for least-privilege IAM.** If your Claude session has `AdministratorAccess`, you have a problem even with these hooks. Scope the credentials.
- **Not magic.** It catches `aws`, `sf`, `sfdx`, and the project's `db-query.py` wrapper. Custom infra-touching scripts won't be intercepted unless you add patterns.

---

## License

MIT — see [LICENSE](LICENSE). Contributions welcome via PR.

---

## Acknowledgements

Distilled from production patterns in a working engineering environment. The escalation-by-blast-radius design and the passkey-gate-with-no-caching rule came from learning what *almost* went wrong.
