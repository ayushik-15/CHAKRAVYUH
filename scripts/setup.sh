#!/usr/bin/env bash
# =============================================================================
# CHAKRAVYUH — One-Command Setup Script
# =============================================================================
# Bootstraps the entire CHAKRAVYUH adversarial AI safety testing platform:
#   1. Validates prerequisites (Docker, Docker Compose, Node.js, Python)
#   2. Creates .env from .env.example if missing
#   3. Builds and starts all containers
#   4. Waits for services to become healthy
#   5. Runs the isolation verification suite
#
# Usage:
#   chmod +x scripts/setup.sh
#   ./scripts/setup.sh
#
# Exit code 0 = setup complete; 1 = setup failed.
# =============================================================================

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Configuration ──────────────────────────────────────────────────────────
ARBITER_HOST="${ARBITER_HOST:-localhost}"
ARBITER_PORT="${ARBITER_PORT:-8000}"
HEALTH_ENDPOINT="http://${ARBITER_HOST}:${ARBITER_PORT}/health"
MAX_HEALTH_RETRIES=30          # Maximum number of health-check poll attempts
HEALTH_POLL_INTERVAL=3         # Seconds between polls
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ─── Step Counter ────────────────────────────────────────────────────────────
STEP=0
ERRORS=0

next_step() {
    STEP=$((STEP + 1))
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  Step ${STEP}: $1${RESET}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

success() {
    echo -e "  ${GREEN}✅ $1${RESET}"
}

warn() {
    echo -e "  ${YELLOW}⚠️  $1${RESET}"
}

fail() {
    echo -e "  ${RED}❌ $1${RESET}"
    ERRORS=$((ERRORS + 1))
}

info() {
    echo -e "  ${DIM}$1${RESET}"
}

# ─── Banner ──────────────────────────────────────────────────────────────────
print_banner() {
    echo ""
    echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${MAGENTA}║${RESET}                                                                ${MAGENTA}║${RESET}"
    echo -e "${MAGENTA}║${RESET}   ${BOLD}🛡️  CHAKRAVYUH — Secure Adversarial AI Safety Platform${RESET}       ${MAGENTA}║${RESET}"
    echo -e "${MAGENTA}║${RESET}   ${DIM}One-command setup for the complete testing infrastructure${RESET}    ${MAGENTA}║${RESET}"
    echo -e "${MAGENTA}║${RESET}                                                                ${MAGENTA}║${RESET}"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  ${DIM}Project Root:  ${PROJECT_ROOT}${RESET}"
    echo -e "  ${DIM}Started at:    $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
}

# =============================================================================
# Step 1: Check Docker
# =============================================================================
check_docker() {
    next_step "Checking Docker"

    if ! command -v docker &> /dev/null; then
        fail "Docker is not installed. Please install Docker: https://docs.docker.com/get-docker/"
        return 1
    fi

    local docker_version
    docker_version=$(docker --version 2>/dev/null || echo "unknown")
    success "Docker found: ${docker_version}"

    # Verify Docker daemon is running
    if ! docker info &> /dev/null; then
        fail "Docker daemon is not running. Please start Docker."
        return 1
    fi
    success "Docker daemon is running"
}

# =============================================================================
# Step 2: Check Docker Compose
# =============================================================================
check_docker_compose() {
    next_step "Checking Docker Compose"

    # Check for 'docker compose' (v2 plugin) first, then 'docker-compose' (v1)
    if docker compose version &> /dev/null; then
        local compose_version
        compose_version=$(docker compose version 2>/dev/null || echo "unknown")
        success "Docker Compose (v2 plugin) found: ${compose_version}"
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        local compose_version
        compose_version=$(docker-compose --version 2>/dev/null || echo "unknown")
        success "Docker Compose (standalone) found: ${compose_version}"
        COMPOSE_CMD="docker-compose"
    else
        fail "Docker Compose is not installed. Please install it: https://docs.docker.com/compose/install/"
        return 1
    fi
}

# =============================================================================
# Step 3: Check Node.js (>= 18)
# =============================================================================
check_nodejs() {
    next_step "Checking Node.js (>= 18)"

    if ! command -v node &> /dev/null; then
        warn "Node.js is not installed. Frontend development requires Node.js >= 18."
        warn "Install from: https://nodejs.org/"
        info "Continuing — containers will handle Node.js internally."
        return 0
    fi

    local node_version_raw
    node_version_raw=$(node --version 2>/dev/null || echo "v0.0.0")
    # Strip leading 'v' and extract major version
    local node_major
    node_major=$(echo "${node_version_raw}" | sed 's/^v//' | cut -d. -f1)

    if [ "${node_major}" -ge 18 ] 2>/dev/null; then
        success "Node.js found: ${node_version_raw} (major: ${node_major} >= 18 ✓)"
    else
        warn "Node.js version ${node_version_raw} detected — requires >= 18."
        warn "Install latest LTS from: https://nodejs.org/"
        info "Continuing — containers will handle Node.js internally."
    fi
}

# =============================================================================
# Step 4: Check Python (>= 3.10)
# =============================================================================
check_python() {
    next_step "Checking Python (>= 3.10)"

    local python_cmd=""

    if command -v python3 &> /dev/null; then
        python_cmd="python3"
    elif command -v python &> /dev/null; then
        python_cmd="python"
    fi

    if [ -z "${python_cmd}" ]; then
        warn "Python is not installed. Local development requires Python >= 3.10."
        warn "Install from: https://www.python.org/downloads/"
        info "Continuing — containers will handle Python internally."
        return 0
    fi

    local py_version_raw
    py_version_raw=$(${python_cmd} --version 2>/dev/null || echo "Python 0.0.0")
    local py_version
    py_version=$(echo "${py_version_raw}" | awk '{print $2}')
    local py_major
    py_major=$(echo "${py_version}" | cut -d. -f1)
    local py_minor
    py_minor=$(echo "${py_version}" | cut -d. -f2)

    if [ "${py_major}" -ge 3 ] && [ "${py_minor}" -ge 10 ] 2>/dev/null; then
        success "Python found: ${py_version_raw} (${py_major}.${py_minor} >= 3.10 ✓)"
    else
        warn "Python ${py_version} detected — requires >= 3.10."
        warn "Install from: https://www.python.org/downloads/"
        info "Continuing — containers will handle Python internally."
    fi
}

# =============================================================================
# Step 5: Create .env from .env.example
# =============================================================================
setup_env_file() {
    next_step "Setting up environment configuration"

    cd "${PROJECT_ROOT}"

    if [ -f ".env" ]; then
        success ".env file already exists"
        info "Current variables:"
        while IFS= read -r line; do
            # Mask sensitive values
            if echo "$line" | grep -qiE "(password|secret|key|token)"; then
                local key
                key=$(echo "$line" | cut -d= -f1)
                info "  ${key}=********"
            elif [ -n "$line" ] && [[ ! "$line" =~ ^# ]]; then
                info "  ${line}"
            fi
        done < .env
    elif [ -f ".env.example" ]; then
        cp .env.example .env
        success "Created .env from .env.example"
        warn "Review .env and update secrets before production use!"
    else
        # Create a default .env with standard values
        cat > .env << 'EOF'
POSTGRES_PASSWORD=chakravyuh_dev
ARBITER_HOST=arbiter
ARBITER_PORT=8000
MERKLE_HOST=merkle-log
MERKLE_PORT=8001
LLM_MODEL=qwen2.5:0.5b
JWT_SECRET=dev-secret-change-in-prod
EOF
        success "Created default .env file"
        warn "Using default development credentials — change before production!"
    fi
}

# =============================================================================
# Step 6: Build containers
# =============================================================================
build_containers() {
    next_step "Building Docker containers"

    cd "${PROJECT_ROOT}"

    info "This may take several minutes on first run..."
    echo ""

    if ${COMPOSE_CMD} build --progress=plain 2>&1 | while IFS= read -r line; do
        # Show build progress with indentation
        echo -e "  ${DIM}${line}${RESET}"
    done; then
        echo ""
        success "All containers built successfully"
    else
        fail "Container build failed — check the output above for errors"
        return 1
    fi
}

# =============================================================================
# Step 7: Start services
# =============================================================================
start_services() {
    next_step "Starting all services"

    cd "${PROJECT_ROOT}"

    if ${COMPOSE_CMD} up -d 2>&1 | while IFS= read -r line; do
        echo -e "  ${DIM}${line}${RESET}"
    done; then
        success "All services started in detached mode"
    else
        fail "Failed to start services"
        return 1
    fi

    # Show container status
    echo ""
    info "Container status:"
    ${COMPOSE_CMD} ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | while IFS= read -r line; do
        echo -e "  ${line}"
    done
}

# =============================================================================
# Step 8: Wait for services to be healthy
# =============================================================================
wait_for_health() {
    next_step "Waiting for services to become healthy"

    info "Polling ${HEALTH_ENDPOINT} (max ${MAX_HEALTH_RETRIES} attempts, ${HEALTH_POLL_INTERVAL}s interval)..."
    echo ""

    local attempt=0
    local healthy=false

    while [ ${attempt} -lt ${MAX_HEALTH_RETRIES} ]; do
        attempt=$((attempt + 1))

        # Show progress spinner
        local spinner_chars=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
        local spinner_idx=$(( (attempt - 1) % ${#spinner_chars[@]} ))
        printf "\r  ${YELLOW}${spinner_chars[$spinner_idx]}${RESET} Attempt %d/%d — checking arbiter health..." \
            "${attempt}" "${MAX_HEALTH_RETRIES}"

        # Try to hit the health endpoint
        local response
        if response=$(curl -s --max-time 5 "${HEALTH_ENDPOINT}" 2>/dev/null); then
            # Check if response indicates healthy status
            if echo "${response}" | grep -qiE "(healthy|ok)"; then
                printf "\r"  # Clear spinner line
                success "Arbiter is healthy! (attempt ${attempt}/${MAX_HEALTH_RETRIES})"
                info "Response: ${response}"
                healthy=true
                break
            fi
        fi

        sleep "${HEALTH_POLL_INTERVAL}"
    done

    if [ "${healthy}" = false ]; then
        printf "\r"  # Clear spinner line
        fail "Arbiter did not become healthy within $((MAX_HEALTH_RETRIES * HEALTH_POLL_INTERVAL))s"
        warn "Troubleshooting:"
        info "  1. Check logs: ${COMPOSE_CMD} logs arbiter"
        info "  2. Check if port ${ARBITER_PORT} is available"
        info "  3. Verify .env configuration"
        return 1
    fi
}

# =============================================================================
# Step 9: Print service summary table
# =============================================================================
print_service_summary() {
    next_step "Service Summary"

    echo -e "  ${CYAN}┌──────────────────────┬────────────────┬─────────────────────────────────┐${RESET}"
    echo -e "  ${CYAN}│${RESET} ${BOLD}Service              ${RESET}${CYAN}│${RESET} ${BOLD}Status         ${RESET}${CYAN}│${RESET} ${BOLD}URL                             ${RESET}${CYAN}│${RESET}"
    echo -e "  ${CYAN}├──────────────────────┼────────────────┼─────────────────────────────────┤${RESET}"

    # Define services and their expected ports/URLs
    declare -a svc_names=("Arbiter (API)"    "Frontend (UI)"   "Merkle Log"       "PostgreSQL"       "Red Plane"        "Blue Plane"       "LLM Plane")
    declare -a svc_containers=("chakravyuh-arbiter" "chakravyuh-frontend" "chakravyuh-merkle-log" "chakravyuh-postgres" "chakravyuh-red-plane" "chakravyuh-blue-plane" "chakravyuh-llm-plane")
    declare -a svc_urls=("http://localhost:8000" "http://localhost:3000" "http://localhost:8001" "localhost:5432 (internal)" "— (isolated)" "— (isolated)" "— (isolated)")

    for i in "${!svc_names[@]}"; do
        local name="${svc_names[$i]}"
        local container="${svc_containers[$i]}"
        local url="${svc_urls[$i]}"

        # Check container status
        local status
        if docker ps --filter "name=${container}" --filter "status=running" --format "{{.Names}}" 2>/dev/null | grep -q "${container}"; then
            status="${GREEN}● Running${RESET}      "
        else
            status="${RED}○ Stopped${RESET}      "
        fi

        printf "  ${CYAN}│${RESET} %-20s ${CYAN}│${RESET} %b ${CYAN}│${RESET} %-31s ${CYAN}│${RESET}\n" \
            "${name}" "${status}" "${url}"
    done

    echo -e "  ${CYAN}└──────────────────────┴────────────────┴─────────────────────────────────┘${RESET}"
}

# =============================================================================
# Step 10: Run isolation verification
# =============================================================================
run_isolation_verification() {
    next_step "Running isolation verification"

    local verify_script="${SCRIPT_DIR}/verify-isolation.sh"

    if [ ! -f "${verify_script}" ]; then
        warn "verify-isolation.sh not found at ${verify_script}"
        info "Skipping isolation verification."
        return 0
    fi

    if [ ! -x "${verify_script}" ]; then
        chmod +x "${verify_script}"
        info "Made verify-isolation.sh executable"
    fi

    echo ""
    cd "${PROJECT_ROOT}"
    if bash "${verify_script}"; then
        success "Isolation verification passed!"
    else
        fail "Isolation verification detected issues — review output above"
    fi
}

# =============================================================================
# Final Summary
# =============================================================================
print_final_summary() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    if [ "${ERRORS}" -eq 0 ]; then
        echo ""
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${RESET}"
        echo -e "${GREEN}║${RESET}                                                                ${GREEN}║${RESET}"
        echo -e "${GREEN}║${RESET}   ${BOLD}${GREEN}✅  CHAKRAVYUH setup completed successfully!${RESET}                 ${GREEN}║${RESET}"
        echo -e "${GREEN}║${RESET}                                                                ${GREEN}║${RESET}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${RESET}"
        echo ""
        echo -e "  ${BOLD}Quick Start:${RESET}"
        echo -e "  ${DIM}───────────────────────────────────────────────${RESET}"
        echo -e "  📊 Dashboard:    ${CYAN}http://localhost:3000${RESET}"
        echo -e "  🔗 API Docs:     ${CYAN}http://localhost:8000/docs${RESET}"
        echo -e "  📜 Merkle Log:   ${CYAN}http://localhost:8001/docs${RESET}"
        echo -e "  🔍 Run demo:     ${CYAN}./scripts/demo.sh${RESET}"
        echo -e "  🛡️  Re-verify:   ${CYAN}./scripts/verify-isolation.sh${RESET}"
        echo -e "  📋 View logs:    ${CYAN}docker compose logs -f${RESET}"
        echo -e "  🛑 Stop all:     ${CYAN}docker compose down${RESET}"
        echo ""
    else
        echo ""
        echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${RESET}"
        echo -e "${RED}║${RESET}                                                                ${RED}║${RESET}"
        echo -e "${RED}║${RESET}   ${BOLD}${RED}⚠️  Setup completed with ${ERRORS} error(s)${RESET}                          ${RED}║${RESET}"
        echo -e "${RED}║${RESET}                                                                ${RED}║${RESET}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${RESET}"
        echo ""
        echo -e "  ${BOLD}Troubleshooting:${RESET}"
        echo -e "  ${DIM}───────────────────────────────────────────────${RESET}"
        echo -e "  1. Check Docker is running:  ${CYAN}docker info${RESET}"
        echo -e "  2. Check container logs:     ${CYAN}docker compose logs${RESET}"
        echo -e "  3. Rebuild from scratch:     ${CYAN}docker compose down -v && ./scripts/setup.sh${RESET}"
        echo -e "  4. Check port conflicts:     ${CYAN}lsof -i :8000 -i :3000 -i :8001${RESET}"
        echo ""
    fi

    echo -e "  ${DIM}Finished at: $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
    echo ""
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    print_banner

    # Prerequisite checks (Steps 1-4)
    check_docker          || true
    check_docker_compose  || true
    check_nodejs          || true
    check_python          || true

    # Bail early if critical prerequisites are missing
    if [ "${ERRORS}" -gt 0 ]; then
        echo ""
        fail "Critical prerequisites missing. Fix the errors above and re-run."
        print_final_summary
        exit 1
    fi

    # Environment setup (Step 5)
    setup_env_file

    # Build and start (Steps 6-7)
    build_containers || true
    start_services   || true

    # Health check (Step 8)
    wait_for_health || true

    # Summary (Step 9)
    print_service_summary

    # Isolation verification (Step 10)
    run_isolation_verification || true

    # Final report
    print_final_summary

    # Exit with appropriate code
    if [ "${ERRORS}" -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

main "$@"
