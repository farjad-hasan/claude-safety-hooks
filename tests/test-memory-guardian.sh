#!/usr/bin/env bash
# Tests for check_memory_invariants.py and memory-invariants-guardian.sh
set -u
PASS=0; FAIL=0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$(command -v python3 || command -v python)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

check() { # name expected_exit actual_exit
  if [ "$2" -eq "$3" ]; then PASS=$((PASS+1)); echo "PASS: $1";
  else FAIL=$((FAIL+1)); echo "FAIL: $1 (expected exit $2, got $3)"; fi
}

# Fixtures
mkdir -p "$TMP/mem"
echo "note" > "$TMP/mem/exists.md"

# 1. Clean index -> 0
printf -- "- [ok](exists.md)\n- [[exists]]\n" > "$TMP/mem/MEMORY.md"
"$PY" "$ROOT/scripts/check_memory_invariants.py" "$TMP/mem/MEMORY.md"; check "clean index" 0 $?

# 2. Dead markdown link -> 2
printf -- "- [gone](missing.md)\n" > "$TMP/mem/MEMORY.md"
"$PY" "$ROOT/scripts/check_memory_invariants.py" "$TMP/mem/MEMORY.md" 2>/dev/null; check "dead md link" 2 $?

# 3. Dead wikilink -> 2
printf -- "see [[nothere]]\n" > "$TMP/mem/MEMORY.md"
"$PY" "$ROOT/scripts/check_memory_invariants.py" "$TMP/mem/MEMORY.md" 2>/dev/null; check "dead wikilink" 2 $?

# 4. Count annotation correct -> 0 (exists.md + MEMORY.md = 2 files match *.md)
printf -- "2 files tracked <!-- invariant-count: *.md -->\n" > "$TMP/mem/MEMORY.md"
"$PY" "$ROOT/scripts/check_memory_invariants.py" "$TMP/mem/MEMORY.md"; check "count ok" 0 $?

# 5. Count annotation stale -> 2
printf -- "99 files tracked <!-- invariant-count: *.md -->\n" > "$TMP/mem/MEMORY.md"
"$PY" "$ROOT/scripts/check_memory_invariants.py" "$TMP/mem/MEMORY.md" 2>/dev/null; check "count stale" 2 $?

# 6. Non-index file -> 0 regardless of content
printf -- "[gone](missing.md)\n" > "$TMP/mem/notes.md"
"$PY" "$ROOT/scripts/check_memory_invariants.py" "$TMP/mem/notes.md"; check "non-index skipped" 0 $?

# Hook wrapper tests (stdin JSON contract)
HOOK="$ROOT/hooks/memory-invariants-guardian.sh"
printf -- "- [gone](missing.md)\n" > "$TMP/mem/MEMORY.md"

# 7. No stdin input -> 0 (not an Edit/Write call)
bash "$HOOK" < /dev/null; check "hook: no input" 0 $?

# 8. Valid JSON, index file with violation -> 2
echo "{\"tool_input\":{\"file_path\":\"$TMP/mem/MEMORY.md\"}}" | bash "$HOOK" 2>/dev/null; check "hook: violation surfaces" 2 $?

# 9. Valid JSON, non-index path -> 0
echo "{\"tool_input\":{\"file_path\":\"$TMP/mem/notes.md\"}}" | bash "$HOOK"; check "hook: non-index" 0 $?

# 10. Malformed JSON with input present -> 2 (fail closed, v0.1.1 convention)
echo "not json" | bash "$HOOK" 2>/dev/null; check "hook: malformed input fails closed" 2 $?

echo; echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
