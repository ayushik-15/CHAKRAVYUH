#!/usr/bin/env bash
# =============================================================================
# CHAKRAVYUH — Network Isolation Verification Script
# =============================================================================
# Verifies that the triple-plane sandbox enforces strict network isolation:
#   - Red  ✗→ Blue,  Red  ✗→ LLM   (MUST FAIL)
#   - Blue ✗→ Red,   Blue ✗→ LLM   (MUST FAIL)
#   - Red  ✓→ Arbiter               (MUST SUCCEED)
#   - Blue ✓→ Arbiter               (MUST SUCCEED)
#
# Exit code 0 = all isolation checks pass; 1 = at least one check failed.
# =============================================================================

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Counters ────────────────────────────────────────────────────────────────
TOTAL=0
PASSED=0
FAILED=0

# Parallel arrays to store results for the summary table
declare -a TEST_NAMES=()
declare -a TEST_DESCS=()
declare -a TEST_EXPECTED=()
declare -a TEST_RESULTS=()

# ─── Helpers ─────────────────────────────────────────────────────────────────

print_header() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║${RESET}  ${BOLD}🛡️  CHAKRAVYUH — Network Isolation Verification${RESET}               ${CYAN}║${RESET}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# assert_failure <test_name> <description> <command...>
#   Runs the command inside docker compose exec; expects it to FAIL (non-zero
#   exit code, connection refused, timeout, or DNS resolution failure).
assert_failure() {
    local test_name="$1"
    local description="$2"
    shift 2

    TOTAL=$((TOTAL + 1))
    echo -e "  ${DIM}[${TOTAL}]${RESET} ${description}..."

    # Run the command and capture exit code; suppress output
    if eval "$@" > /dev/null 2>&1; then
        # Command SUCCEEDED — isolation is BROKEN
        FAILED=$((FAILED + 1))
        TEST_NAMES+=("$test_name")
        TEST_DESCS+=("$description")
        TEST_EXPECTED+=("FAIL (blocked)")
        TEST_RESULTS+=("FAIL")
        echo -e "      ${RED}❌ FAIL — connection succeeded (isolation BROKEN)${RESET}"
    else
        # Command FAILED — isolation is WORKING
        PASSED=$((PASSED + 1))
        TEST_NAMES+=("$test_name")
        TEST_DESCS+=("$description")
        TEST_EXPECTED+=("FAIL (blocked)")
        TEST_RESULTS+=("PASS")
        echo -e "      ${GREEN}✅ PASS — connection blocked as expected${RESET}"
    fi
}

# assert_success <test_name> <description> <command...>
#   Runs the command; expects it to SUCCEED (zero exit code).
assert_success() {
    local test_name="$1"
    local description="$2"
    shift 2

    TOTAL=$((TOTAL + 1))
    echo -e "  ${DIM}[${TOTAL}]${RESET} ${description}..."

    if eval "$@" > /dev/null 2>&1; then
        # Command SUCCEEDED — connectivity is WORKING
        PASSED=$((PASSED + 1))
        TEST_NAMES+=("$test_name")
        TEST_DESCS+=("$description")
        TEST_EXPECTED+=("SUCCESS")
        TEST_RESULTS+=("PASS")
        echo -e "      ${GREEN}✅ PASS — connection succeeded as expected${RESET}"
    else
        # Command FAILED — connectivity is BROKEN
        FAILED=$((FAILED + 1))
        TEST_NAMES+=("$test_name")
        TEST_DESCS+=("$description")
        TEST_EXPECTED+=("SUCCESS")
        TEST_RESULTS+=("FAIL")
        echo -e "      ${RED}❌ FAIL — connection failed (should have succeeded)${RESET}"
    fi
}

print_summary_table() {
    echo ""
    echo -e "${CYAN}┌──────┬────────────────────────────────────────────────────────┬───────────────┬──────────┐${RESET}"
    echo -e "${CYAN}│${RESET} ${BOLD}  #  ${RESET}${CYAN}│${RESET} ${BOLD}Test Description                                       ${RESET}${CYAN}│${RESET} ${BOLD}Expected      ${RESET}${CYAN}│${RESET} ${BOLD}Result   ${RESET}${CYAN}│${RESET}"
    echo -e "${CYAN}├──────┼────────────────────────────────────────────────────────┼───────────────┼──────────┤${RESET}"

    for i in "${!TEST_NAMES[@]}"; do
        local idx=$((i + 1))
        local desc="${TEST_DESCS[$i]}"
        local expected="${TEST_EXPECTED[$i]}"
        local result="${TEST_RESULTS[$i]}"

        # Pad description to 54 chars
        desc=$(printf "%-54s" "$desc")
        expected=$(printf "%-13s" "$expected")

        if [ "$result" = "PASS" ]; then
            result_display="${GREEN}✅ PASS ${RESET}"
        else
            result_display="${RED}❌ FAIL ${RESET}"
        fi

        printf "${CYAN}│${RESET}  %2d  ${CYAN}│${RESET} %s ${CYAN}│${RESET} %s ${CYAN}│${RESET} %b${CYAN}│${RESET}\n" \
            "$idx" "$desc" "$expected" "$result_display"
    done

    echo -e "${CYAN}└──────┴────────────────────────────────────────────────────────┴───────────────┴──────────┘${RESET}"
}

print_final_verdict() {
    echo ""
    if [ "$FAILED" -eq 0 ]; then
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
        echo -e "${GREEN}║${RESET}  ${BOLD}${GREEN}✅  ALL ${TOTAL} ISOLATION TESTS PASSED${RESET}                              ${GREEN}║${RESET}"
        echo -e "${GREEN}║${RESET}  ${DIM}Triple-plane sandbox isolation is correctly enforced.${RESET}        ${GREEN}║${RESET}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    else
        echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${RESET}"
        echo -e "${RED}║${RESET}  ${BOLD}${RED}❌  ${FAILED}/${TOTAL} ISOLATION TESTS FAILED${RESET}                                  ${RED}║${RESET}"
        echo -e "${RED}║${RESET}  ${DIM}Network isolation is BROKEN — review Docker network config.${RESET}  ${RED}║${RESET}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    fi
    echo ""
}

# =============================================================================
# Main
# =============================================================================

print_header

echo -e "${YELLOW}▸ Phase 1: Cross-Plane Isolation (must FAIL)${RESET}"
echo -e "${DIM}  These tests verify that planes CANNOT communicate directly.${RESET}"
echo ""

# Test 1: Red → Blue (HTTP) — MUST FAIL
assert_failure \
    "RED→BLUE_HTTP" \
    "Red plane → Blue plane (HTTP :8080)" \
    "docker compose exec red-plane curl -s --max-time 3 http://blue-plane:8080"

# Test 2: Red → LLM (ICMP ping) — MUST FAIL
assert_failure \
    "RED→LLM_PING" \
    "Red plane → LLM plane (ICMP ping)" \
    "docker compose exec red-plane ping -c 1 -W 2 llm-plane"

# Test 3: Blue → Red (HTTP) — MUST FAIL
assert_failure \
    "BLUE→RED_HTTP" \
    "Blue plane → Red plane (HTTP :8080)" \
    "docker compose exec blue-plane curl -s --max-time 3 http://red-plane:8080"

# Test 4: Blue → LLM (ICMP ping) — MUST FAIL
assert_failure \
    "BLUE→LLM_PING" \
    "Blue plane → LLM plane (ICMP ping)" \
    "docker compose exec blue-plane ping -c 1 -W 2 llm-plane"

echo ""
echo -e "${YELLOW}▸ Phase 2: Arbiter Connectivity (must SUCCEED)${RESET}"
echo -e "${DIM}  These tests verify that planes CAN reach the Arbiter.${RESET}"
echo ""

# Test 5: Red → Arbiter health (HTTP) — MUST SUCCEED
assert_success \
    "RED→ARBITER" \
    "Red plane → Arbiter health check (HTTP :8000)" \
    "docker compose exec red-plane curl -s --max-time 3 http://arbiter:8000/health"

# Test 6: Blue → Arbiter health (HTTP) — MUST SUCCEED
assert_success \
    "BLUE→ARBITER" \
    "Blue plane → Arbiter health check (HTTP :8000)" \
    "docker compose exec blue-plane curl -s --max-time 3 http://arbiter:8000/health"

# ─── Summary ─────────────────────────────────────────────────────────────────

print_summary_table
print_final_verdict

# Exit with appropriate code
if [ "$FAILED" -eq 0 ]; then
    exit 0
else
    exit 1
fi
