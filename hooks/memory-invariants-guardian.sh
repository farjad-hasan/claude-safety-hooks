#!/usr/bin/env bash
# Memory Invariants Guardian (PostToolUse)
#
# Runs after Edit/Write. If the edited file is a memory index (MEMORY.md
# or INDEX.md), validates link and count invariants via
# scripts/check_memory_invariants.py. Exit 2 surfaces violations to Claude
# so the next response can fix them; non-index edits exit 0 silently.
#
# Follows the fail-closed conventions of the v0.1.x guardians:
#   - no stdin input at all        -> exit 0 (not an inspectable call)
#   - input present but unparsable -> exit 2 (fail closed)

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INPUT="$(cat 2>/dev/null || true)"
[ -z "$INPUT" ] && exit 0

if ! command -v jq >/dev/null 2>&1; then
    echo "memory-invariants-guardian: jq not found; failing closed" >&2
    exit 2
fi

FILE_PATH="$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)"
if [ -z "$FILE_PATH" ]; then
    echo "memory-invariants-guardian: could not parse tool input; failing closed" >&2
    exit 2
fi

case "$(basename "$FILE_PATH")" in
    MEMORY.md|INDEX.md) ;;
    *) exit 0 ;;
esac

PY="$(command -v python3 || command -v python)"
if [ -z "$PY" ]; then
    echo "memory-invariants-guardian: python not found; failing closed" >&2
    exit 2
fi

exec "$PY" "$SCRIPT_DIR/../scripts/check_memory_invariants.py" "$FILE_PATH"
