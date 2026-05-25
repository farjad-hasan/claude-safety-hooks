#!/usr/bin/env bash
# Regression tests for fail-closed behavior in the input-parsing path.
#
# These tests verify that the hooks NEVER silently allow a command when
# they couldn't inspect the input. They cover:
#
#   1. malformed JSON input            → exit 2 (fail closed)
#   2. JSON with no command field      → exit 2 (fail closed)
#   3. no input at all                 → exit 0 (legit non-Bash call)
#   4. valid input + non-target cmd    → exit 0 (allow)
#   5. valid input + destructive prod  → exit 2 (block)
#
# The "jq missing" case is verified by code review: the hook explicitly
# checks `command -v jq` before attempting to parse, and exits 2 with a
# clear install-jq message if absent. Cleanly automating this would
# require shadowing $PATH in a way that also breaks cat/grep/sed —
# defeating the test. Manual verification: install hooks on a system
# without jq, pipe any JSON, observe the dependency-missing message.
#
# Run: bash tests/test-fail-closed.sh
# Or:  bash tests/test-fail-closed.sh sf-prod-guardian

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOKS=("sf-prod-guardian" "db-prod-guardian" "aws-prod-guardian")

if [ $# -gt 0 ]; then
    HOOKS=("$1")
fi

# Required by the hooks themselves
if ! command -v jq >/dev/null 2>&1; then
    echo "✗ These tests require jq to be installed." >&2
    echo "  macOS:   brew install jq" >&2
    echo "  Linux:   apt install jq" >&2
    echo "  Windows: winget install jqlang.jq" >&2
    exit 1
fi

# Minimal env so the hooks don't bail on config-missing before they reach
# the input-parsing code we're testing.
export SF_PROD_PASSKEY_HASH=000000000000000000000000000000000000000000000000000000000000aaaa
export DB_PROD_PASSKEY_HASH=000000000000000000000000000000000000000000000000000000000000bbbb
export AWS_PROD_PASSKEY_HASH=000000000000000000000000000000000000000000000000000000000000cccc
export PROD_ACCOUNT_ID=999999999999

PASS=0
FAIL=0
report() {
    local case_name="$1"
    local expected="$2"
    local actual="$3"
    local hook="$4"
    if [ "$expected" = "$actual" ]; then
        printf "  \033[32m✓\033[0m %-32s [%-19s] expected=%s actual=%s\n" "$case_name" "$hook" "$expected" "$actual"
        PASS=$((PASS + 1))
    else
        printf "  \033[31m✗\033[0m %-32s [%-19s] expected=%s actual=%s\n" "$case_name" "$hook" "$expected" "$actual"
        FAIL=$((FAIL + 1))
    fi
}

for hook in "${HOOKS[@]}"; do
    HOOK_PATH="$REPO_ROOT/hooks/${hook}.sh"
    if [ ! -x "$HOOK_PATH" ]; then
        echo "✗ $HOOK_PATH not executable or not found"
        exit 1
    fi
    echo "── Testing $hook ──"

    # Case 1: malformed JSON input → fail closed (exit 2)
    actual=$(echo "not-json-at-all" | "$HOOK_PATH" >/dev/null 2>&1; echo $?)
    report "malformed JSON input" 2 "$actual" "$hook"

    # Case 2: valid JSON but no .tool_input.command field → fail closed (exit 2)
    actual=$(echo '{"some":"other","shape":1}' | "$HOOK_PATH" >/dev/null 2>&1; echo $?)
    report "JSON with no command field" 2 "$actual" "$hook"

    # Case 3: no input at all → allow (exit 0)
    actual=$("$HOOK_PATH" </dev/null >/dev/null 2>&1; echo $?)
    report "no input at all" 0 "$actual" "$hook"

    # Case 4: valid JSON with non-target command → allow (exit 0)
    actual=$(echo '{"tool_input":{"command":"ls -la"}}' | "$HOOK_PATH" >/dev/null 2>&1; echo $?)
    report "valid input, non-target cmd" 0 "$actual" "$hook"
done

# Case 5: each hook should block its own destructive command class.
# These verify the original v0.1.0 behavior wasn't regressed by the new
# fail-closed input-parsing code.
echo ""
echo "── Per-hook destructive command (regression check) ──"

# AWS — non-whitelisted command on production
actual=$(echo '{"tool_input":{"command":"aws s3 rb s3://prod-data --force"}}' \
    | "$REPO_ROOT/hooks/aws-prod-guardian.sh" >/dev/null 2>&1; echo $?)
report "aws s3 rb prod                 " 2 "$actual" "aws-prod-guardian "

# DB — DROP statement
actual=$(echo '{"tool_input":{"command":"psql -c \"DROP TABLE users;\""}}' \
    | "$REPO_ROOT/hooks/db-prod-guardian.sh" >/dev/null 2>&1; echo $?)
report "psql DROP TABLE                " 2 "$actual" "db-prod-guardian  "

echo ""
echo "═══════════════════════════════════════════════════════════════"
printf "Result: \033[32m%d passed\033[0m" "$PASS"
if [ $FAIL -gt 0 ]; then
    printf ", \033[31m%d failed\033[0m" "$FAIL"
fi
echo ""
echo "═══════════════════════════════════════════════════════════════"

exit $FAIL
