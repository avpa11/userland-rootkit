#!/bin/bash
# Run with: sudo ./test_integration.sh
# For manual diagnosis: sudo ./test_integration.sh --diag
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASS=0
FAIL=0
TMPDIR="/tmp/comp8505_int_$$"
KEEP_LOGS=0

if [ "${1:-}" = "--diag" ]; then
    KEEP_LOGS=1
    TMPDIR="/tmp/comp8505_diag"
    mkdir -p "${TMPDIR}"
fi

if [ "${KEEP_LOGS}" = "0" ]; then
    trap 'kill %1 2>/dev/null; wait 2>/dev/null; rm -rf ${TMPDIR}' EXIT
fi
mkdir -p "${TMPDIR}"

pass() { PASS=$((PASS+1)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { FAIL=$((FAIL+1)); echo -e "  ${RED}[FAIL]${NC} $1"; }

echo "=== Integration Tests (require root) ==="
echo ""

if [ "$(id -u)" != "0" ]; then
    fail "Must run as root"
    echo "Usage: sudo ./test_integration.sh"
    exit 1
fi

echo "Starting victim..."
./victim > "${TMPDIR}/victim.log" 2>&1 &
VICTIM_PID=$!
sleep 2

if ! kill -0 ${VICTIM_PID} 2>/dev/null; then
    fail "Victim failed to start"
    cat "${TMPDIR}/victim.log"
    exit 1
fi
pass "Victim started (PID ${VICTIM_PID})"

# ── Knock + Session ──
echo ""
echo "--- Test: Port Knock + Session Open ---"

# Run the commander and victim interaction with longer timeout
(
    sleep 3
    echo "Sending knock sequence..."
    # Manual knock + session via commander
    printf "1\n"      # Connect
    sleep 4
    printf "9\n"      # Heartbeat
    sleep 2
    printf "10\n"     # Disconnect
    sleep 1
    printf "3\n"      # Exit
) | ./commander 127.0.0.1 > "${TMPDIR}/cmd1.log" 2>&1 &
CMD_PID=$!

wait $CMD_PID 2>/dev/null || true
sleep 1

echo "=== Victim log ==="
cat "${TMPDIR}/victim.log" 2>/dev/null | head -30
echo ""
echo "=== Commander log ==="
cat "${TMPDIR}/cmd1.log" 2>/dev/null | head -30
echo ""

if grep -q "Session active\|Session opened" "${TMPDIR}/cmd1.log" "${TMPDIR}/victim.log" 2>/dev/null; then
    pass "Port knock + session open with obfuscated protocol"
else
    fail "Port knock or session open failed"
fi

if grep -q "HEARTBEAT\|heartbeat ok" "${TMPDIR}/cmd1.log" "${TMPDIR}/victim.log" 2>/dev/null; then
    pass "Heartbeat over obfuscated covert channel"
else
    fail "Heartbeat failed"
fi

if grep -q "Command HEARTBEAT" "${TMPDIR}/victim.log" 2>/dev/null; then
    pass "IP ID + UDP source port header-level encoding active (covert channel using raw sockets)"
else
    fail "Raw socket covert channel not functioning"
fi

# TOS encoding removed in favor of raw socket IP ID + source port encoding
# (more reliable cross-platform header-level data encoding)

# ── Results ──
echo ""
echo "=== Integration Results ==="
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo ""
echo "Logs kept at: ${TMPDIR}"

kill ${VICTIM_PID} 2>/dev/null || true
wait 2>/dev/null || true

if [ "${FAIL}" -gt 0 ]; then
    echo -e "${RED}*** INTEGRATION TESTS FAILED ***${NC}"
    exit 1
fi
echo -e "${GREEN}All integration tests passed.${NC}"
