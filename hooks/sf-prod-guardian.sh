#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# Salesforce Production Guardian Hook
# ═══════════════════════════════════════════════════════════════════
#
# Pre-tool-use hook for Claude Code. Intercepts sf/sfdx CLI commands
# and enforces production safety:
#
#   READ operations on production  → ALLOWED (no prompt)
#   WRITE operations on production → BLOCKED (exit 2)
#
# To bypass after explicit user confirmation AND passkey entry:
#   SF_PROD_PASSKEY=<passkey> SF_PROD_CONFIRMED=true <command>
#
# The passkey is verified via SHA-256 hash comparison.
# Claude must ask the user for the passkey every time — never cache it.
#
# REQUIRED ENVIRONMENT VARIABLES (set in your shell rc or a .env loaded
# before Claude Code starts — see .env.example):
#   SF_PROD_USERNAME      e.g. you@yourcompany.com (without sandbox suffix)
#   SF_PROD_ORG_ID        18-char SF org ID, starts with 00D
#   SF_PROD_PASSKEY_HASH  SHA-256 hex of your chosen production passkey
#                         (echo -n "<passkey>" | sha256sum)
#
# Production identifiers (any match = production):
#   --target-org production | -o production
#   $SF_PROD_USERNAME (exact match, without sandbox suffix)
#   $SF_PROD_ORG_ID
# ═══════════════════════════════════════════════════════════════════

# ── Required environment ─────────────────────────────────────────────
SF_PROD_USERNAME="${SF_PROD_USERNAME:-}"
SF_PROD_ORG_ID="${SF_PROD_ORG_ID:-}"
SF_PROD_PASSKEY_HASH="${SF_PROD_PASSKEY_HASH:-}"

if [ -z "$SF_PROD_PASSKEY_HASH" ]; then
    cat >&2 <<'CONFIG'
✗ SF Guardian misconfigured: SF_PROD_PASSKEY_HASH is empty.
  Compute the hash once:
    echo -n "<your-chosen-passkey>" | sha256sum
  Export the hex digest as SF_PROD_PASSKEY_HASH (e.g. in your shell rc).
  See .env.example in the repo for all required variables.
CONFIG
    exit 2
fi

# ── Read the command ─────────────────────────────────────────────────
CMD=""
if [ -n "$CLAUDE_BASH_COMMAND" ]; then
    CMD="$CLAUDE_BASH_COMMAND"
else
    INPUT=$(cat 2>/dev/null)
    if [ -n "$INPUT" ]; then
        CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)
    fi
fi

# No command found → allow (not a Bash tool call we can inspect)
if [ -z "$CMD" ]; then
    exit 0
fi

# ── Normalize Windows sf path form ─────────────────────────────────
# On Windows, sf CLI is invoked as:
#   "C:/Program Files/sf/client/bin/node.exe" "C:/Program Files/sf/client/bin/run.js" <subcommand> ...
# Strip the node.exe + run.js prefix so downstream checks see: sf <subcommand> ...
NORM_CMD="$CMD"
if echo "$CMD" | grep -q 'sf/client/bin/run\.js'; then
    NORM_CMD="sf $(echo "$CMD" | sed 's|.*sf/client/bin/run\.js[" ]*||')"
fi

# ── Quick exit: not an sf/sfdx command ─────────────────────────────
if ! echo "$NORM_CMD" | grep -qE '(^|\s|;|&&|\|\||")(sf|sfdx)\s'; then
    exit 0
fi

# ── Detect production targeting ────────────────────────────────────
TARGETS_PROD=false

# Check --target-org / -o flags
if echo "$NORM_CMD" | grep -qiE '(-o|--target-org)\s+production(\s|$|;|")'; then
    TARGETS_PROD=true
fi

# Check production username (exact match, but reject sandbox suffix forms)
# Fixed-string grep avoids regex escaping issues with arbitrary usernames.
if [ -n "$SF_PROD_USERNAME" ]; then
    if echo "$NORM_CMD" | grep -qF "$SF_PROD_USERNAME" && \
       ! echo "$NORM_CMD" | grep -qF "${SF_PROD_USERNAME}."; then
        TARGETS_PROD=true
    fi
fi

# Check production org ID
if [ -n "$SF_PROD_ORG_ID" ] && echo "$NORM_CMD" | grep -qF "$SF_PROD_ORG_ID"; then
    TARGETS_PROD=true
fi

# ── Not targeting production → allow everything ────────────────────
if [ "$TARGETS_PROD" = false ]; then
    exit 0
fi

# ── Targeting production: classify as READ or WRITE ────────────────
READ_PATTERNS=(
    'sf project retrieve'
    'sf source retrieve'
    'sf source pull'
    'sf retrieve'
    'sf data query'
    'sf data tree export'
    'sf data export'
    'sf org display'
    'sf org list'
    'sf org open'
    'sf sobject describe'
    'sf sobject list'
    'sf apex log list'
    'sf apex log get'
    'sf apex log tail'
    'sf limits api display'
    'sf org resume'
    'sf org login'
    'sf config list'
    'sf config get'
    'sf alias list'
    'sfdx force:source:retrieve'
    'sfdx force:source:pull'
    'sfdx force:data:soql:query'
    'sfdx force:org:display'
    'sfdx force:org:list'
    'sfdx force:org:open'
    'sfdx force:limits:api:display'
    'sfdx force:schema:sobject:describe'
    'sfdx force:schema:sobject:list'
)

IS_READ=false
for pattern in "${READ_PATTERNS[@]}"; do
    if echo "$NORM_CMD" | grep -q "$pattern"; then
        IS_READ=true
        break
    fi
done

# ── Production READ → allow silently ──────────────────────────────
if [ "$IS_READ" = true ]; then
    exit 0
fi

# ── Production WRITE: check for explicit user confirmation + passkey ──
EXPECTED_HASH="$SF_PROD_PASSKEY_HASH"

if echo "$NORM_CMD" | grep -q 'SF_PROD_CONFIRMED=true'; then
    PASSKEY=$(echo "$NORM_CMD" | sed -n 's/.*SF_PROD_PASSKEY=\([^ ;][^ ;]*\).*/\1/p')

    if [ -n "$PASSKEY" ]; then
        ACTUAL_HASH=$(echo -n "$PASSKEY" | sha256sum | awk '{print $1}')
        if [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ]; then
            exit 0
        fi
    fi

    cat >&2 <<'WRONGKEY'
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  PASSKEY INVALID — SALESFORCE GUARDIAN                    ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  SF_PROD_CONFIRMED was set but the passkey is missing or      ║
║  incorrect. Production write BLOCKED.                         ║
║                                                               ║
║  You MUST ask the user to provide their production passkey.   ║
║  Do NOT guess, reuse, or hardcode the passkey.                ║
║                                                               ║
║  Rerun with:                                                  ║
║    SF_PROD_PASSKEY=<passkey> SF_PROD_CONFIRMED=true <cmd>     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
WRONGKEY
    exit 2
fi

# ── BLOCK: Production write without confirmation ───────────────────
cat >&2 <<BLOCK
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  PRODUCTION WRITE BLOCKED — SALESFORCE GUARDIAN          ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  This command would MODIFY the PRODUCTION Salesforce org.     ║
║                                                               ║
║  Org:  ${SF_PROD_USERNAME:-<not configured>} (production)
║  ID:   ${SF_PROD_ORG_ID:-<not configured>}
║                                                               ║
║  To proceed, you MUST:                                        ║
║  1. Ask the user for their production PASSKEY                 ║
║  2. User must type the passkey themselves                     ║
║  3. Rerun with both:                                          ║
║     SF_PROD_PASSKEY=<passkey> SF_PROD_CONFIRMED=true <cmd>    ║
║                                                               ║
║  NEVER guess, cache, or reuse the passkey from memory.        ║
║  NEVER bypass this check. The user MUST provide it each time. ║
║                                                               ║
║  Read operations (retrieve, query, describe) are allowed.     ║
║  Write operations (deploy, data modify, apex run) are not.    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
BLOCK

exit 2
