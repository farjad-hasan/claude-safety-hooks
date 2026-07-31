#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# Database Production Guardian Hook
# ═══════════════════════════════════════════════════════════════════
#
# Pre-tool-use hook for Claude Code. Intercepts database commands
# and enforces read-only safety:
#
#   READ operations (SELECT, EXPLAIN, exploration) → ALLOWED
#   WRITE operations (INSERT, UPDATE, DELETE, etc.) → BLOCKED (exit 2)
#
# To bypass after explicit user confirmation AND passkey entry:
#   DB_PROD_PASSKEY=<passkey> DB_PROD_CONFIRMED=true <command>
#
# The passkey is verified via SHA-256 hash comparison.
# Claude must ask the user for the passkey every time — never cache it.
#
# Also enforces that database access goes through a read-only wrapper
# (blocks raw psql connections to production).
#
# REQUIRED ENVIRONMENT VARIABLES:
#   DB_PROD_PASSKEY_HASH  SHA-256 hex of your chosen production passkey
#   DB_NAME               (optional) Name of the production database
#                         shown in block messages. Defaults to "<prod>".
# ═══════════════════════════════════════════════════════════════════

# ── Required environment ─────────────────────────────────────────────
DB_PROD_PASSKEY_HASH="${DB_PROD_PASSKEY_HASH:-}"
DB_NAME="${DB_NAME:-<prod>}"

if [ -z "$DB_PROD_PASSKEY_HASH" ]; then
    cat >&2 <<'CONFIG'
✗ DB Guardian misconfigured: DB_PROD_PASSKEY_HASH is empty.
  Compute the hash once:
    echo -n "<your-chosen-passkey>" | sha256sum
  Export the hex digest as DB_PROD_PASSKEY_HASH.
  See .env.example in the repo.
CONFIG
    exit 2
fi

# ── Read the command ─────────────────────────────────────────────
# Two input paths: CLAUDE_BASH_COMMAND env var or JSON on stdin.
# Track HAD_INPUT so we can fail closed when input arrived but couldn't
# be parsed — silent input loss is a fail-open vulnerability.
CMD=""
HAD_INPUT=false
if [ -n "$CLAUDE_BASH_COMMAND" ]; then
    CMD="$CLAUDE_BASH_COMMAND"
    HAD_INPUT=true
else
    INPUT=$(cat 2>/dev/null)
    if [ -n "$INPUT" ]; then
        HAD_INPUT=true
        if ! command -v jq >/dev/null 2>&1; then
            cat >&2 <<'JQMISSING'
✗ DB Guardian dependency missing: jq is required to parse tool input.
  Install jq before using this hook:
    macOS:   brew install jq
    Linux:   apt install jq   (or your distro equivalent)
    Windows: winget install jqlang.jq
  Failing closed — no command will be allowed without jq.
JQMISSING
            exit 2
        fi
        CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)
    fi
fi

# If we had input but couldn't extract a command, JSON was malformed →
# fail closed. NEVER silently allow when the hook couldn't inspect.
if [ "$HAD_INPUT" = true ] && [ -z "$CMD" ]; then
    echo "✗ DB Guardian: received input but could not extract a command. Failing closed." >&2
    exit 2
fi

if [ -z "$CMD" ]; then
    exit 0
fi

# ── Quick exit: not a database-related command ───────────────────
IS_DB_CMD=false

if echo "$CMD" | grep -qE 'db-query\.(py|sh)'; then
    IS_DB_CMD=true
fi

if echo "$CMD" | grep -qE '(^|\s|;|&&|\|\||")psql\s'; then
    IS_DB_CMD=true
fi

if echo "$CMD" | grep -qE 'postgresql://|host=.*port=5432'; then
    IS_DB_CMD=true
fi

if echo "$CMD" | grep -qE 'import psycopg|import psycopg2|from psycopg'; then
    IS_DB_CMD=true
fi

if [ "$IS_DB_CMD" = false ]; then
    exit 0
fi

# ── Check for explicit bypass with passkey ──────────────────────
EXPECTED_HASH="$DB_PROD_PASSKEY_HASH"

if echo "$CMD" | grep -q 'DB_PROD_CONFIRMED=true'; then
    PASSKEY=$(echo "$CMD" | sed -n 's/.*DB_PROD_PASSKEY=\([^ ;][^ ;]*\).*/\1/p')

    if [ -n "$PASSKEY" ]; then
        ACTUAL_HASH=$(echo -n "$PASSKEY" | sha256sum | awk '{print $1}')
        if [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ]; then
            exit 0
        fi
    fi

    cat >&2 <<'WRONGKEY'
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  PASSKEY INVALID — DB PRODUCTION GUARDIAN                 ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  DB_PROD_CONFIRMED was set but the passkey is missing or      ║
║  incorrect. Production write BLOCKED.                         ║
║                                                               ║
║  You MUST ask the user to provide their production passkey.   ║
║  Do NOT guess, reuse, or hardcode the passkey.                ║
║                                                               ║
║  Rerun with:                                                  ║
║    DB_PROD_PASSKEY=<passkey> DB_PROD_CONFIRMED=true <cmd>     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
WRONGKEY
    exit 2
fi

# ── Block raw psql (must use read-only wrapper) ──────────────────
if echo "$CMD" | grep -qE '(^|\s|;|&&|\|\||")psql\s' && \
   ! echo "$CMD" | grep -qE 'db-query\.(py|sh)'; then
    cat >&2 <<'BLOCK'
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  RAW PSQL BLOCKED — DB PRODUCTION GUARDIAN               ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Direct psql connections to production are not allowed.        ║
║  Use the read-only wrapper script instead:                    ║
║                                                               ║
║    python scripts/db-query.py -c "SELECT ..."                 ║
║    python scripts/db-query.py --schemas                       ║
║    python scripts/db-query.py --tables <schema>               ║
║                                                               ║
║  The wrapper enforces read-only at the session level.         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
BLOCK
    exit 2
fi

# ── Block inline Python DB connections ──────────────────────────
if echo "$CMD" | grep -qE 'import psycopg|import psycopg2|from psycopg' && \
   ! echo "$CMD" | grep -qE 'db-query\.(py|sh)'; then
    cat >&2 <<'BLOCK'
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  DIRECT DB CONNECTION BLOCKED — DB PRODUCTION GUARDIAN    ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Direct database connections via Python are not allowed.      ║
║  Use the read-only wrapper script instead:                    ║
║                                                               ║
║    python scripts/db-query.py -c "SELECT ..."                 ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
BLOCK
    exit 2
fi

# ── Using db-query wrapper: validate the SQL content ────────────
SQL=""
if echo "$CMD" | grep -qE '\s-c\s'; then
    SQL=$(echo "$CMD" | sed -n "s/.*-c[[:space:]]*[\"']\(.*\)[\"'].*/\1/p")
    if [ -z "$SQL" ]; then
        SQL=$(echo "$CMD" | sed -n 's/.*-c[[:space:]]*\([^-].*\)/\1/p')
    fi
fi

if echo "$CMD" | grep -qE '\s-f\s|--file\s'; then
    SQL_FILE=$(echo "$CMD" | sed -n "s/.*\(-f\|--file\)[[:space:]]*[\"']*\([^\"' ]*\).*/\2/p")
    if [ -n "$SQL_FILE" ] && [ -f "$SQL_FILE" ]; then
        SQL=$(cat "$SQL_FILE" 2>/dev/null)
    fi
fi

if echo "$CMD" | grep -qE '\-\-schemas|\-\-tables|\-\-describe|\-\-search|\-\-counts'; then
    exit 0
fi

if [ -z "$SQL" ]; then
    exit 0
fi

# ── Check SQL for write operations ──────────────────────────────
SQL_UPPER=$(echo "$SQL" | tr '[:lower:]' '[:upper:]')
SQL_UPPER=$(echo "$SQL_UPPER" | sed 's/--.*$//' | sed 's|/\*.*\*/||g')

WRITE_KEYWORDS=(
    "INSERT"
    "UPDATE"
    "DELETE"
    "DROP"
    "ALTER"
    "TRUNCATE"
    "CREATE"
    "GRANT"
    "REVOKE"
    "CALL"
    "LOCK"
    "VACUUM"
    "REINDEX"
)

for keyword in "${WRITE_KEYWORDS[@]}"; do
    if echo "$SQL_UPPER" | grep -qwE "\b${keyword}\b"; then
        cat >&2 <<BLOCK
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  WRITE BLOCKED — DB PRODUCTION GUARDIAN                  ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Write operation detected: ${keyword}
║                                                               ║
║  Database: ${DB_NAME} (PRODUCTION)
║  Only SELECT/read queries are allowed.                        ║
║                                                               ║
║  To proceed, you MUST:                                        ║
║  1. Ask the user for their production PASSKEY                 ║
║  2. User must type the passkey themselves                     ║
║  3. Rerun with both:                                          ║
║     DB_PROD_PASSKEY=<passkey> DB_PROD_CONFIRMED=true <cmd>    ║
║                                                               ║
║  NEVER guess, cache, or reuse the passkey from memory.        ║
║  NEVER bypass this check. The user MUST provide it each time. ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
BLOCK
        exit 2
    fi
done

if echo "$SQL_UPPER" | grep -qE '\bCOPY\b.*\bFROM\b'; then
    cat >&2 <<'BLOCK'
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  WRITE BLOCKED — DB PRODUCTION GUARDIAN                  ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Write operation detected: COPY FROM (data import)            ║
║  Only SELECT/read queries are allowed.                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
BLOCK
    exit 2
fi

if echo "$SQL_UPPER" | grep -qE '\bDO\s+\$'; then
    cat >&2 <<'BLOCK'
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  WRITE BLOCKED — DB PRODUCTION GUARDIAN                  ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Write operation detected: DO $$ (anonymous code block)       ║
║  Only SELECT/read queries are allowed.                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
BLOCK
    exit 2
fi

if echo "$SQL_UPPER" | grep -qE '\bSELECT\b.*\bINTO\b'; then
    cat >&2 <<'BLOCK'
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  WRITE BLOCKED — DB PRODUCTION GUARDIAN                  ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Write operation detected: SELECT INTO (creates new table)    ║
║  Only SELECT/read queries are allowed.                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
BLOCK
    exit 2
fi

if echo "$SQL_UPPER" | grep -qE 'SET\s+DEFAULT_TRANSACTION_READ_ONLY\s*(=|TO)\s*OFF'; then
    cat >&2 <<'BLOCK'
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  BYPASS ATTEMPT BLOCKED — DB PRODUCTION GUARDIAN         ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Attempted to disable read-only mode.                         ║
║  This is not allowed on the production database.              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
BLOCK
    exit 2
fi

exit 0
