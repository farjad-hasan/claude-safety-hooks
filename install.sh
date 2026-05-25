#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# claude-safety-hooks installer
# ═══════════════════════════════════════════════════════════════════
#
# What it does:
#   1. Copies the three guardian hooks into .claude/hooks/
#   2. Registers them as PreToolUse hooks in .claude/settings.json
#      (merges with any existing config — does not clobber)
#   3. Makes hooks executable
#
# Usage:
#   ./install.sh              # install to ./.claude/ (project-level)
#   ./install.sh --user       # install to ~/.claude/ (user-level)
#   ./install.sh --help       # this message
#
# Re-running is safe (idempotent).
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Parse args ───────────────────────────────────────────────────────
SCOPE="project"

while [ $# -gt 0 ]; do
    case "$1" in
        --user)    SCOPE="user"; shift ;;
        --project) SCOPE="project"; shift ;;
        --help|-h)
            sed -n '2,17p' "$0" | sed 's/^# //;s/^#//'
            exit 0
            ;;
        *)
            echo "✗ Unknown argument: $1" >&2
            echo "  Run with --help for usage." >&2
            exit 1
            ;;
    esac
done

# ── Locate source files (where this script lives) ───────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_HOOKS_DIR="$SCRIPT_DIR/hooks"

if [ ! -d "$SRC_HOOKS_DIR" ]; then
    echo "✗ Cannot find hooks/ directory at $SRC_HOOKS_DIR" >&2
    echo "  Run this script from the repo root, not from elsewhere." >&2
    exit 1
fi

HOOKS=(sf-prod-guardian.sh db-prod-guardian.sh aws-prod-guardian.sh)

for h in "${HOOKS[@]}"; do
    if [ ! -f "$SRC_HOOKS_DIR/$h" ]; then
        echo "✗ Missing source hook: $SRC_HOOKS_DIR/$h" >&2
        exit 1
    fi
done

# ── Resolve install target ──────────────────────────────────────────
if [ "$SCOPE" = "user" ]; then
    TARGET_BASE="$HOME/.claude"
    HOOK_PATH_PREFIX="$HOME/.claude/hooks"
    echo "→ Installing claude-safety-hooks (user-level: $TARGET_BASE)"
else
    TARGET_BASE="$(pwd)/.claude"
    HOOK_PATH_PREFIX=".claude/hooks"
    echo "→ Installing claude-safety-hooks (project-level: $(pwd)/.claude)"
fi

TARGET_HOOKS_DIR="$TARGET_BASE/hooks"
SETTINGS_FILE="$TARGET_BASE/settings.json"

# ── Check jq is available (we need it for safe JSON merging) ────────
if ! command -v jq >/dev/null 2>&1; then
    cat >&2 <<'JQMISSING'
✗ jq is required but not installed.
  The hooks themselves also use jq to parse tool input. Install it first:
    macOS:   brew install jq
    Linux:   apt install jq   (or your distro equivalent)
    Windows: winget install jqlang.jq
  Then re-run this installer.
JQMISSING
    exit 1
fi

# ── Copy hooks ──────────────────────────────────────────────────────
mkdir -p "$TARGET_HOOKS_DIR"

for h in "${HOOKS[@]}"; do
    cp "$SRC_HOOKS_DIR/$h" "$TARGET_HOOKS_DIR/$h"
    chmod +x "$TARGET_HOOKS_DIR/$h"
    echo "✓ Installed $h"
done

# ── Build the hook registration JSON ────────────────────────────────
# Claude Code's PreToolUse config groups hooks by matcher. We add one
# entry per guardian, all matching the Bash tool.
HOOK_ENTRIES=$(jq -n \
    --arg sf "$HOOK_PATH_PREFIX/sf-prod-guardian.sh" \
    --arg db "$HOOK_PATH_PREFIX/db-prod-guardian.sh" \
    --arg aws "$HOOK_PATH_PREFIX/aws-prod-guardian.sh" \
    '[
        {matcher: "Bash", hooks: [{type: "command", command: $sf}]},
        {matcher: "Bash", hooks: [{type: "command", command: $db}]},
        {matcher: "Bash", hooks: [{type: "command", command: $aws}]}
    ]')

# ── Merge into settings.json ────────────────────────────────────────
if [ -f "$SETTINGS_FILE" ]; then
    # Validate existing file is parseable JSON before touching it
    if ! jq empty "$SETTINGS_FILE" 2>/dev/null; then
        echo "✗ Existing $SETTINGS_FILE is not valid JSON." >&2
        echo "  Fix or remove it before running the installer." >&2
        exit 1
    fi

    # Filter out any prior registrations of OUR hooks (idempotency),
    # then append the fresh entries.
    TMP=$(mktemp)
    jq --argjson new "$HOOK_ENTRIES" '
        .hooks //= {} |
        .hooks.PreToolUse //= [] |
        .hooks.PreToolUse |= (
            map(select(
                .hooks // [] |
                any(.command | test("(sf|db|aws)-prod-guardian\\.sh$")) | not
            )) + $new
        )
    ' "$SETTINGS_FILE" > "$TMP"

    mv "$TMP" "$SETTINGS_FILE"
    echo "✓ Updated $SETTINGS_FILE (merged with existing config)"
else
    jq -n --argjson hooks "$HOOK_ENTRIES" \
        '{hooks: {PreToolUse: $hooks}}' > "$SETTINGS_FILE"
    echo "✓ Created $SETTINGS_FILE"
fi

# ── Verify ──────────────────────────────────────────────────────────
REGISTERED=$(jq '[.hooks.PreToolUse[]?.hooks[]?.command] | map(select(test("prod-guardian"))) | length' "$SETTINGS_FILE")

if [ "$REGISTERED" -lt 3 ]; then
    echo "✗ Verification failed: expected 3 guardian hooks registered, found $REGISTERED" >&2
    exit 1
fi

cat <<DONE

═══════════════════════════════════════════════════════════════════
✓ Installed: 3 PreToolUse hooks registered in $SETTINGS_FILE

NEXT STEPS

  1. Copy .env.example to .env and fill in your account IDs and
     passkey hashes. Generate a hash with:
         echo -n "<your-passkey>" | sha256sum | awk '{print \$1}'

  2. Source .env before starting Claude Code:
         set -a; source .env; set +a

  3. (Optional) Test that the hook fires by running:
         echo '{"tool_input":{"command":"aws s3 rb s3://test"}}' \\
           | $HOOK_PATH_PREFIX/aws-prod-guardian.sh
         # → should exit 2 with a config error if .env not loaded,
         # → or with a "production write blocked" message if loaded.

  See README.md for full configuration details.
═══════════════════════════════════════════════════════════════════
DONE
