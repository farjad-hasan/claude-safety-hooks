#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# AWS Production Guardian Hook
# ═══════════════════════════════════════════════════════════════════
#
# Pre-tool-use hook for Claude Code. Uses a WHITELIST approach:
# only explicitly allowed read-only AWS CLI commands pass on production.
# Everything else is blocked.
#
# This is intentionally more restrictive than the DB/SF guardians.
# AWS with AdministratorAccess has enormous blast radius — entire
# regions have been wiped by misbehaving AI agents.
#
# Bypass: AWS_PROD_PASSKEY=<passkey> AWS_PROD_CONFIRMED=true aws ...
#
# The passkey is verified via SHA-256 hash comparison.
# Claude must ask the user for the passkey every time — never cache it.
#
# REQUIRED ENVIRONMENT VARIABLES:
#   PROD_ACCOUNT_ID          12-digit AWS production account ID
#   AWS_PROD_PASSKEY_HASH    SHA-256 hex of your chosen passkey
#
# OPTIONAL ENVIRONMENT VARIABLES (non-prod account IDs the guardian
# should skip without prompting):
#   UAT_ACCOUNT_ID
#   DEV_ACCOUNT_ID
#   SANDBOX_ACCOUNT_ID
# Unknown accounts (not matching any of the above) are treated
# defensively as PROD-equivalent.
# ═══════════════════════════════════════════════════════════════════

# ── Required environment ─────────────────────────────────────────────
PROD_ACCOUNT_ID="${PROD_ACCOUNT_ID:-}"
AWS_PROD_PASSKEY_HASH="${AWS_PROD_PASSKEY_HASH:-}"
UAT_ACCOUNT_ID="${UAT_ACCOUNT_ID:-}"
DEV_ACCOUNT_ID="${DEV_ACCOUNT_ID:-}"
SANDBOX_ACCOUNT_ID="${SANDBOX_ACCOUNT_ID:-}"

# NOTE: the misconfiguration check deliberately runs AFTER command detection,
# further down. Checking it here would exit 2 for EVERY Bash command — `ls`,
# `git status`, everything — on an unconfigured install, making Claude Code
# unusable rather than merely guarded. See the check below the aws-command
# detection.

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
✗ AWS Guardian dependency missing: jq is required to parse tool input.
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
    echo "✗ AWS Guardian: received input but could not extract a command. Failing closed." >&2
    exit 2
fi

if [ -z "$CMD" ]; then
    exit 0
fi

# ── Quick exit: not an AWS command ───────────────────────────────
if ! echo "$CMD" | grep -qE '(^|\s|;|&&|\|\||")aws\s'; then
    exit 0
fi

# ── Required environment (checked only once we know this IS an aws command) ──
# Ordering matters: an unconfigured guardian must not block unrelated commands.
# It still fails closed for the commands it actually governs.
if [ -z "$PROD_ACCOUNT_ID" ] || [ -z "$AWS_PROD_PASSKEY_HASH" ]; then
    cat >&2 <<'CONFIG'
✗ AWS Guardian misconfigured: PROD_ACCOUNT_ID and/or
  AWS_PROD_PASSKEY_HASH is empty.
  Set both before running aws commands:
    PROD_ACCOUNT_ID=123456789012
    AWS_PROD_PASSKEY_HASH=$(printf '%s' "<your-passkey>" | sha256sum | awk '{print $1}')
    # macOS (no sha256sum):
    AWS_PROD_PASSKEY_HASH=$(printf '%s' "<your-passkey>" | shasum -a 256 | awk '{print $1}')
  See .env.example in the repo for all required variables.
  Failing closed — this aws command is blocked until configured.
CONFIG
    exit 2
fi

# ── Portable SHA-256 ────────────────────────────────────────────
# GNU coreutils ships sha256sum; macOS ships shasum. Assuming sha256sum
# meant the passkey could never be verified on a Mac — the gate could not
# be opened at all, which gets a guardian deleted rather than respected.
# printf is used over `echo -n`, which is not portable across shells.
sha256_hex() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    else
        return 1
    fi
}

# ── Check for explicit bypass with passkey ──────────────────────
EXPECTED_HASH="$AWS_PROD_PASSKEY_HASH"

if echo "$CMD" | grep -q 'AWS_PROD_CONFIRMED=true'; then
    PASSKEY=$(echo "$CMD" | sed -n 's/.*AWS_PROD_PASSKEY=\([^ ;][^ ;]*\).*/\1/p')

    if [ -n "$PASSKEY" ]; then
        if ! ACTUAL_HASH=$(sha256_hex "$PASSKEY"); then
            echo "✗ AWS Guardian: no sha256sum or shasum available; cannot verify passkey. Failing closed." >&2
            exit 2
        fi
        if [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ]; then
            exit 0
        fi
    fi

    cat >&2 <<'WRONGKEY'
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  PASSKEY INVALID — AWS PRODUCTION GUARDIAN                ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  AWS_PROD_CONFIRMED was set but the passkey is missing or     ║
║  incorrect. Production command BLOCKED.                       ║
║                                                               ║
║  You MUST ask the user to provide their production passkey.   ║
║  Do NOT guess, reuse, or hardcode the passkey.                ║
║                                                               ║
║  Rerun with:                                                  ║
║    AWS_PROD_PASSKEY=<passkey> AWS_PROD_CONFIRMED=true <cmd>   ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
WRONGKEY
    exit 2
fi

# ── Account-aware skip ───────────────────────────────────────────
# Skip guardian entirely for KNOWN non-PROD accounts.
# Unknown accounts fall through to the whitelist (defensive: never
# auto-trust an unmapped account).

account_label() {
    local acct="$1"
    # Empty resolved account → unresolved. This check must come first;
    # otherwise a case statement against empty $UAT_ACCOUNT_ID etc. would
    # match the empty input and mislabel it (the v0.1.1 cosmetic bug).
    if [ -z "$acct" ]; then
        echo "Unresolved — treated as PROD"
        return
    fi
    # Each comparison is guarded by `[ -n ... ]` so an unset env var
    # cannot accidentally match a resolved account ID.
    if [ -n "$PROD_ACCOUNT_ID" ]    && [ "$acct" = "$PROD_ACCOUNT_ID" ];    then echo "Production"; return; fi
    if [ -n "$UAT_ACCOUNT_ID" ]     && [ "$acct" = "$UAT_ACCOUNT_ID" ];     then echo "UAT"; return; fi
    if [ -n "$DEV_ACCOUNT_ID" ]     && [ "$acct" = "$DEV_ACCOUNT_ID" ];     then echo "Dev"; return; fi
    if [ -n "$SANDBOX_ACCOUNT_ID" ] && [ "$acct" = "$SANDBOX_ACCOUNT_ID" ]; then echo "Sandbox"; return; fi
    echo "Unknown account — treated as PROD"
}

# Detect profile from --profile flag in the command
CMD_PROFILE=$(echo "$CMD" | grep -oE '\-\-profile\s+[a-zA-Z0-9_-]+' | awk '{print $2}' | head -1)

# Fall back to AWS_PROFILE env var (may be set via eval/export before the aws command)
if [ -z "$CMD_PROFILE" ]; then
    CMD_PROFILE=$(echo "$CMD" | grep -oE 'AWS_PROFILE=[a-zA-Z0-9_-]+' | cut -d= -f2 | head -1)
fi
if [ -z "$CMD_PROFILE" ]; then
    CMD_PROFILE="$AWS_PROFILE"
fi

# Resolve account ID: profile-driven first, then default credentials
if [ -n "$CMD_PROFILE" ]; then
    RESOLVED_ACCOUNT=$(aws sts get-caller-identity --profile "$CMD_PROFILE" --query Account --output text 2>/dev/null)
else
    RESOLVED_ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
fi

# Skip guardian for KNOWN non-PROD accounts (only when their env vars are set).
# Empty UAT_ACCOUNT_ID etc. would otherwise match an empty $RESOLVED_ACCOUNT,
# which is a fail-open bug — we guard against that here.
if [ -n "$UAT_ACCOUNT_ID" ] && [ "$RESOLVED_ACCOUNT" = "$UAT_ACCOUNT_ID" ]; then
    exit 0
fi
if [ -n "$DEV_ACCOUNT_ID" ] && [ "$RESOLVED_ACCOUNT" = "$DEV_ACCOUNT_ID" ]; then
    exit 0
fi
if [ -n "$SANDBOX_ACCOUNT_ID" ] && [ "$RESOLVED_ACCOUNT" = "$SANDBOX_ACCOUNT_ID" ]; then
    exit 0
fi

# At this point the target is PROD or unknown — both fall through to whitelist
ACCOUNT_LABEL=$(account_label "$RESOLVED_ACCOUNT")

# ── Extract the AWS subcommand ──────────────────────────────────
# Handles: aws logs describe-log-groups, aws --region us-east-1 logs ..., piped commands

# Collapse multiline commands (backslash-newline continuations) into a single line
CMD_FLAT=$(echo "$CMD" | tr '\n' ' ' | sed 's/\\[[:space:]]*/ /g; s/  */ /g')

# Extract service + action by walking tokens, NOT by regex.
#
# The previous sed approach used \b and \s, which are GNU extensions. On BSD
# sed (stock macOS) `aws\s+` parses as "aw" + one-or-more "s", so the prefix
# was never stripped and SERVICE became the literal string "aws" — matching
# no whitelist entry and blocking every read on macOS. awk token comparison
# has no regex-dialect surface at all.
#
# Walk: find the first token that is `aws` (or a path ending in /aws), then
# skip global flags in both `--flag value` and `--flag=value` forms, then
# take the next two tokens as service and action.
AWS_TOKENS=$(echo "$CMD_FLAT" | awk '{
    for (i = 1; i <= NF; i++) {
        if ($i == "aws" || $i ~ /\/aws$/) {
            j = i + 1
            while (j <= NF && substr($j, 1, 2) == "--") {
                if (index($j, "=") > 0) { j += 1 } else { j += 2 }
            }
            print $j, $(j + 1)
            exit
        }
    }
}')

SERVICE=$(echo "$AWS_TOKENS" | awk '{print $1}')
ACTION=$(echo "$AWS_TOKENS" | awk '{print $2}')

# ── WHITELIST: Allowed read-only operations ─────────────────────

ALLOWED=false

case "$SERVICE" in
    logs)
        case "$ACTION" in
            describe-log-groups|describe-log-streams) ALLOWED=true ;;
            get-log-events|get-log-record)            ALLOWED=true ;;
            filter-log-events)                        ALLOWED=true ;;
            start-query|get-query-results)            ALLOWED=true ;;
            stop-query)                               ALLOWED=true ;;
        esac
        ;;

    sts)
        case "$ACTION" in
            get-caller-identity|get-session-token|get-access-key-info) ALLOWED=true ;;
        esac
        ;;

    ecs)
        case "$ACTION" in
            describe-services|describe-tasks|describe-task-definition) ALLOWED=true ;;
            describe-clusters|describe-container-instances)            ALLOWED=true ;;
            list-services|list-tasks|list-clusters)                   ALLOWED=true ;;
            list-task-definitions|list-container-instances)            ALLOWED=true ;;
        esac
        ;;

    ec2)
        case "$ACTION" in
            describe-instances|describe-security-groups)         ALLOWED=true ;;
            describe-vpcs|describe-subnets)                      ALLOWED=true ;;
            describe-network-interfaces|describe-volumes)        ALLOWED=true ;;
            describe-load-balancers|describe-target-groups)      ALLOWED=true ;;
            describe-addresses|describe-key-pairs)               ALLOWED=true ;;
        esac
        ;;

    rds)
        case "$ACTION" in
            describe-db-instances|describe-db-clusters)     ALLOWED=true ;;
            describe-db-snapshots|describe-db-subnet-groups) ALLOWED=true ;;
        esac
        ;;

    elasticache)
        case "$ACTION" in
            describe-cache-clusters|describe-replication-groups) ALLOWED=true ;;
        esac
        ;;

    lambda)
        case "$ACTION" in
            get-function|get-function-configuration)   ALLOWED=true ;;
            list-functions|list-event-source-mappings) ALLOWED=true ;;
        esac
        ;;

    s3)
        case "$ACTION" in
            ls) ALLOWED=true ;;
        esac
        ;;

    s3api)
        case "$ACTION" in
            list-buckets|list-objects|list-objects-v2) ALLOWED=true ;;
            get-object|head-object|get-bucket-location) ALLOWED=true ;;
        esac
        ;;

    secretsmanager)
        case "$ACTION" in
            get-secret-value|describe-secret|list-secrets) ALLOWED=true ;;
        esac
        ;;

    ssm)
        case "$ACTION" in
            get-parameter|get-parameters|get-parameters-by-path) ALLOWED=true ;;
            describe-parameters)                                  ALLOWED=true ;;
        esac
        ;;

    cloudwatch)
        case "$ACTION" in
            get-metric-data|get-metric-statistics|list-metrics) ALLOWED=true ;;
            describe-alarms|list-dashboards)                    ALLOWED=true ;;
        esac
        ;;

    elbv2)
        case "$ACTION" in
            describe-load-balancers|describe-target-groups)    ALLOWED=true ;;
            describe-listeners|describe-rules|describe-target-health) ALLOWED=true ;;
        esac
        ;;

    elb)
        case "$ACTION" in
            describe-load-balancers|describe-instance-health) ALLOWED=true ;;
        esac
        ;;

    route53)
        case "$ACTION" in
            list-hosted-zones|list-resource-record-sets|get-hosted-zone) ALLOWED=true ;;
        esac
        ;;

    iam)
        case "$ACTION" in
            get-user|get-role|get-policy|list-users|list-roles) ALLOWED=true ;;
            list-policies|list-attached-role-policies)          ALLOWED=true ;;
        esac
        ;;

    codepipeline)
        case "$ACTION" in
            get-pipeline|get-pipeline-state|get-pipeline-execution) ALLOWED=true ;;
            list-pipelines|list-pipeline-executions)                ALLOWED=true ;;
            get-action-type|list-action-types)                      ALLOWED=true ;;
        esac
        ;;

    deploy)
        case "$ACTION" in
            get-deployment|get-deployment-group|get-deployment-instance) ALLOWED=true ;;
            list-deployments|list-deployment-groups|list-deployment-instances) ALLOWED=true ;;
            batch-get-deployments|batch-get-deployment-instances)  ALLOWED=true ;;
            get-application|list-applications)                     ALLOWED=true ;;
        esac
        ;;

    codebuild)
        case "$ACTION" in
            get-build|batch-get-builds|list-builds|list-builds-for-project) ALLOWED=true ;;
            batch-get-projects|list-projects)                               ALLOWED=true ;;
        esac
        ;;
esac

# ── Decision ────────────────────────────────────────────────────
if [ "$ALLOWED" = true ]; then
    exit 0
fi

# Show the SSO-refresh hint only when it's actually relevant:
# a profile is set AND the account couldn't be resolved (the typical
# signature of an expired SSO session). Without this guard, the hint
# appeared in unrelated contexts (e.g. fresh installs without AWS
# configured at all) and confused new users.
SSO_HINT=""
if [ -n "$CMD_PROFILE" ] && [ -z "$RESOLVED_ACCOUNT" ]; then
    SSO_HINT="
║                                                               ║
║  Profile is set but account did not resolve — your SSO        ║
║  session may have expired. Refresh with:                      ║
║    aws sso login --profile $CMD_PROFILE                       ║"
fi

# ── BLOCKED ─────────────────────────────────────────────────────
cat >&2 <<BLOCK
╔═══════════════════════════════════════════════════════════════╗
║  ⛔  BLOCKED — AWS PRODUCTION GUARDIAN                       ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  Command: aws ${SERVICE} ${ACTION}
║                                                               ║
║  Account: ${RESOLVED_ACCOUNT:-(no account resolved)}
║  Status:  ${ACCOUNT_LABEL:-Production}
║  Profile: ${CMD_PROFILE:-default}${SSO_HINT}
║                                                               ║
║  Only whitelisted READ operations are allowed on PROD.        ║
║  Write/modify/delete operations are BLOCKED.                  ║
║                                                               ║
║  To proceed, you MUST:                                        ║
║  1. Ask the user for their production PASSKEY                 ║
║  2. User must type the passkey themselves                     ║
║  3. Rerun with both:                                          ║
║     AWS_PROD_PASSKEY=<passkey> AWS_PROD_CONFIRMED=true <cmd>  ║
║                                                               ║
║  NEVER guess, cache, or reuse the passkey from memory.        ║
║  NEVER bypass this check. The user MUST provide it each time. ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
BLOCK
exit 2
