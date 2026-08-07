#!/usr/bin/env bash
# Regression tests for the ALLOW path.
#
# test-fail-closed.sh proves dangerous commands are blocked. It does NOT
# prove safe commands are permitted — a hook that blocks everything passes
# that entire suite. This file closes that gap.
#
# Covers:
#   1. whitelisted AWS reads          -> exit 0 (allowed)
#   2. valid passkey bypass           -> exit 0 (allowed)
#   3. invalid passkey                -> exit 2 (blocked)
#
# Case 1 fails on macOS before the v0.3.1 parser fix (BSD sed lacks \s, so
# the service parses as the literal "aws" and no whitelist entry matches).
# Case 2 fails on stock macOS before the v0.3.1 hash fix (no sha256sum).
#
# Run: bash tests/test-allow-path.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS_HOOK="$REPO_ROOT/hooks/aws-prod-guardian.sh"

if ! command -v jq >/dev/null 2>&1; then
    echo "✗ These tests require jq." >&2
    exit 1
fi

# ── Hermetic AWS shim ────────────────────────────────────────────────
# The guardian shells out to `aws sts get-caller-identity` to resolve the
# account. Left real, this test would depend on whether the runner has the
# AWS CLI and credentials, and could hang on the EC2/container metadata
# endpoint. Shim it so every case deterministically takes the PROD
# whitelist path, on every runner, with no network.
#
# The shimmed account matches neither PROD_ACCOUNT_ID nor any non-prod var,
# so it resolves as "unknown -> treated as PROD" -> whitelist.
SHIM_DIR=$(mktemp -d)
cat > "$SHIM_DIR/aws" <<'SHIM'
#!/bin/bash
[ "$1" = "sts" ] && { echo "999999999998"; exit 0; }
exit 0
SHIM
chmod +x "$SHIM_DIR/aws"
PATH="$SHIM_DIR:$PATH"
export PATH
trap 'rm -rf "$SHIM_DIR"' EXIT

# Portable SHA-256 for the test harness itself.
test_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    else
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    fi
}

TEST_PASSKEY="test-passkey-do-not-use-in-production"
export AWS_PROD_PASSKEY_HASH
AWS_PROD_PASSKEY_HASH="$(test_sha256 "$TEST_PASSKEY")"
# An account ID that will never match whatever the runner resolves (usually
# nothing), so every case exercises the PROD whitelist path.
export PROD_ACCOUNT_ID=999999999999

PASS=0
FAIL=0
report() {
    local case_name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        printf "  \033[32m✓\033[0m %-46s expected=%s actual=%s\n" "$case_name" "$expected" "$actual"
        PASS=$((PASS + 1))
    else
        printf "  \033[31m✗\033[0m %-46s expected=%s actual=%s\n" "$case_name" "$expected" "$actual"
        FAIL=$((FAIL + 1))
    fi
}

run_hook() {
    local cmd="$1"
    local payload
    payload=$(jq -n --arg c "$cmd" '{tool_input:{command:$c}}')
    printf '%s' "$payload" | "$AWS_HOOK" >/dev/null 2>&1
    echo $?
}

echo "── AWS guardian: whitelisted reads must be ALLOWED ──"
report "aws s3 ls"                                 0 "$(run_hook 'aws s3 ls')"
report "aws ec2 describe-instances"                0 "$(run_hook 'aws ec2 describe-instances')"
report "aws logs describe-log-groups"              0 "$(run_hook 'aws logs describe-log-groups')"
report "aws sts get-caller-identity"               0 "$(run_hook 'aws sts get-caller-identity')"
report "aws rds describe-db-instances"             0 "$(run_hook 'aws rds describe-db-instances')"
report "read with global flag before subcommand"   0 "$(run_hook 'aws --region us-east-1 logs describe-log-groups')"
report "read with --flag=value form"               0 "$(run_hook 'aws --region=us-east-1 s3 ls')"

echo ""
echo "── AWS guardian: writes still BLOCKED (no regression) ──"
report "aws s3 rb --force"                         2 "$(run_hook 'aws s3 rb s3://prod-data --force')"
report "aws rds delete-db-instance"                2 "$(run_hook 'aws rds delete-db-instance --db-instance-identifier p')"
report "aws ec2 terminate-instances"               2 "$(run_hook 'aws ec2 terminate-instances --instance-ids i-1')"

echo ""
echo "── AWS guardian: passkey gate ──"
report "valid passkey allows the write" 0 \
    "$(run_hook "AWS_PROD_PASSKEY=$TEST_PASSKEY AWS_PROD_CONFIRMED=true aws s3 rb s3://prod-data --force")"
report "wrong passkey still blocks"     2 \
    "$(run_hook 'AWS_PROD_PASSKEY=wrong-key AWS_PROD_CONFIRMED=true aws s3 rb s3://prod-data --force')"

echo ""
echo "═══════════════════════════════════════════════════════════════"
printf "Result: \033[32m%d passed\033[0m" "$PASS"
if [ $FAIL -gt 0 ]; then
    printf ", \033[31m%d failed\033[0m" "$FAIL"
fi
echo ""
echo "═══════════════════════════════════════════════════════════════"

exit $FAIL
