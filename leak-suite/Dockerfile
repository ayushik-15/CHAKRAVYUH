# ═══════════════════════════════════════════════════════════════════════
# CHAKRAVYUH Leak Suite — Dockerfile
# ═══════════════════════════════════════════════════════════════════════
#
# Container image for the Leak Suite covert-channel probe runner.
#
# This container runs the probe suite against the triple-plane sandbox
# to verify isolation properties. It needs network access to test
# cross-plane reachability, and /proc access to test filesystem isolation.
#
# Build:
#   docker build -t chakravyuh-leak-suite ./leak-suite
#
# Run (standalone):
#   docker run --rm chakravyuh-leak-suite python runner.py --probe all --report
#
# Run (via docker-compose):
#   docker compose run leak-suite python runner.py --probe all --report
# ═══════════════════════════════════════════════════════════════════════

FROM python:3.11-slim

# Install system dependencies for timing probes (perf_counter_ns needs
# no extras, but we include procps for /proc inspection utilities)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        iputils-ping \
        net-tools \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source files
COPY leak-suite/ .

# Create results directory
RUN mkdir -p /app/results

# Default command: run all probes and generate report
CMD ["python", "runner.py", "--probe", "all", "--report", "--verbose"]
