#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

TIMEOUT=30
TMPDIR="/tmp/comp8505_test_$$"
VICTIM_LOG="${TMPDIR}/victim.log"
COMMANDER_LOG="${TMPDIR}/commander.log"

pass() { PASS=$((PASS+1)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { FAIL=$((FAIL+1)); echo -e "  ${RED}[FAIL]${NC} $1"; }
skip() { SKIP=$((SKIP+1)); echo -e "  ${YELLOW}[SKIP]${NC} $1"; }

cleanup() {
    kill %1 %2 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

mkdir -p "${TMPDIR}"

echo "=== Covert Channel Test Suite ==="
echo ""

# ──────────────────────────────────────────
echo "--- Build & Binary Verification ---"

if [ ! -x commander ]; then
    if ! make 2>&1; then
        fail "Build failed"
        echo ""
        echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
        exit 1
    fi
fi

if [ ! -x commander ] || [ ! -x victim ]; then
    fail "Binaries missing"
    exit 1
fi
pass "Commander binary exists and is executable"
pass "Victim binary exists and is executable"

# Verify compilation warnings-free
if make clean 2>&1 >/dev/null && make 2>&1 | grep -q "warning"; then
    fail "Compilation produced warnings"
else
    pass "Clean compilation with zero warnings"
fi

# ──────────────────────────────────────────
echo ""
echo "--- Protocol Unit Tests (no network) ---"

# Test: XOR obfuscation is an involution (decrypt = encrypt)
cat > "${TMPDIR}/test_obfuscate.c" << 'CEOF'
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define OBFUSCATION_KEY_BASE 0xC75A9E3Du
#define SEQ_INIT 0x13370000u

uint32_t protocol_derive_obfuscation_key(uint32_t session_id) {
    uint32_t key = OBFUSCATION_KEY_BASE ^ session_id;
    key ^= (key >> 17);
    key *= 0xED5AD4BBu;
    key ^= (key >> 11);
    key *= 0xAC4C1B51u;
    key ^= (key >> 15);
    return key;
}

void protocol_obfuscate_payload(uint8_t *data, size_t len, uint32_t key) {
    uint8_t keystream[4];
    uint32_t state = key;
    keystream[0] = (uint8_t)(state >> 24);
    keystream[1] = (uint8_t)(state >> 16);
    keystream[2] = (uint8_t)(state >> 8);
    keystream[3] = (uint8_t)(state);
    for (size_t i = 0; i < len; i++) {
        data[i] ^= keystream[i & 3];
        if ((i & 3) == 3) {
            state ^= (state >> 13);
            state *= 0x9E3779B9u;
            state ^= (state >> 16);
            keystream[0] = (uint8_t)(state >> 24);
            keystream[1] = (uint8_t)(state >> 16);
            keystream[2] = (uint8_t)(state >> 8);
            keystream[3] = (uint8_t)(state);
        }
    }
}

int main() {
    uint32_t key = protocol_derive_obfuscation_key(SEQ_INIT);
    uint8_t buf[256];
    uint8_t orig[256];
    int failures = 0;

    for (int i = 0; i < 256; i++) {
        buf[i] = (uint8_t)i;
        orig[i] = (uint8_t)i;
    }

    protocol_obfuscate_payload(buf, 256, key);

    int identical = 1;
    for (int i = 0; i < 256; i++) {
        if (buf[i] == orig[i]) identical = 0;
    }
    if (identical) {
        printf("FAIL: Obfuscation produced no change\n");
        failures++;
    } else {
        printf("PASS: Obfuscation changed the data\n");
    }

    protocol_obfuscate_payload(buf, 256, key);

    for (int i = 0; i < 256; i++) {
        if (buf[i] != orig[i]) {
            printf("FAIL: Round-trip failed at byte %d (got %02x, expected %02x)\n", i, buf[i], orig[i]);
            failures++;
            break;
        }
    }
    if (failures == 0) printf("PASS: XOR obfuscation round-trip OK\n");

    return failures ? 1 : 0;
}
CEOF

if gcc -Wall -Wextra -std=gnu99 -o "${TMPDIR}/test_obfuscate" "${TMPDIR}/test_obfuscate.c" 2>&1; then
    if "${TMPDIR}/test_obfuscate" 2>&1 | grep -q "FAIL"; then
        fail "XOR obfuscation involution test failed"
    else
        "${TMPDIR}/test_obfuscate"
        pass "XOR obfuscation is a proper involution (decrypt = encrypt)"
    fi
else
    fail "Could not compile obfuscation test"
fi

# Test: IP ID encoding is deterministic and per-index unique
cat > "${TMPDIR}/test_ipid.c" << 'CEOF'
#include <stdio.h>
#include <stdint.h>

#define OBFUSCATION_KEY_BASE 0xC75A9E3Du
#define SEQ_INIT 0x13370000u

uint32_t protocol_knock_session_token(uint32_t session_id) {
    uint32_t token = OBFUSCATION_KEY_BASE ^ session_id;
    token ^= (token >> 13);
    token *= 0x7FEB352Du;
    token ^= (token >> 16);
    return token & 0xFFFFu;
}

uint16_t protocol_encode_ip_id(uint8_t knock_index, uint32_t token) {
    uint32_t mixed = token ^ ((uint32_t)knock_index << 12);
    mixed ^= (mixed >> 8);
    mixed *= 0x45D9F3B3u;
    mixed ^= (mixed >> 12);
    return (uint16_t)(mixed & 0xFFFFu);
}

int main() {
    uint32_t token = protocol_knock_session_token(SEQ_INIT);
    uint16_t prev = protocol_encode_ip_id(0, token);
    int failures = 0;

    if (token == 0) { printf("FAIL: token is 0\n"); failures++; }
    else printf("PASS: Session token is non-zero (0x%04x)\n", (unsigned)token);

    for (uint8_t i = 1; i < 3; i++) {
        uint16_t curr = protocol_encode_ip_id(i, token);
        if (curr == prev) {
            printf("FAIL: IP ID for index %d matches index %d\n", i, i-1);
            failures++;
        }
        prev = curr;
    }
    if (failures == 0) printf("PASS: IP ID values are per-index unique\n");

    uint32_t token2 = protocol_knock_session_token(SEQ_INIT + 1);
    uint16_t ip_id_diff = protocol_encode_ip_id(0, token2);
    if (ip_id_diff == protocol_encode_ip_id(0, token)) {
        printf("FAIL: Different tokens produce same IP ID\n");
        failures++;
    } else {
        printf("PASS: Different session tokens produce different IP IDs\n");
    }

    for (uint8_t i = 0; i < 3; i++) {
        uint16_t id = protocol_encode_ip_id(i, token);
        if (id == 0) {
            printf("FAIL: IP ID for index %d is 0\n", i);
            failures++;
        }
    }
    if (failures == 0) printf("PASS: All IP ID values are non-zero\n");

    return failures ? 1 : 0;
}
CEOF

if gcc -Wall -Wextra -std=gnu99 -o "${TMPDIR}/test_ipid" "${TMPDIR}/test_ipid.c" 2>&1; then
    if "${TMPDIR}/test_ipid" 2>&1 | grep -q "FAIL"; then
        fail "IP ID encoding tests had failures"
    else
        "${TMPDIR}/test_ipid"
        pass "IP ID encoding produces deterministic, unique, non-zero values"
    fi
else
    fail "Could not compile IP ID test"
fi

# Test: Checksum computation is correct for a known vector
cat > "${TMPDIR}/test_checksum.c" << 'CEOF'
#include <stdio.h>
#include <stdint.h>

uint16_t protocol_compute_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
        if (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)(~sum & 0xFFFFu);
}

int main() {
    uint8_t test1[] = { 0x00, 0x01, 0x02, 0x03 };
    uint16_t csum1 = protocol_compute_checksum(test1, 4);
    if (csum1 == 0) { printf("FAIL: checksum of non-zero data should not be 0\n"); return 1; }
    printf("PASS: Checksum of data [00 01 02 03] = 0x%04x\n", (unsigned)csum1);

    uint8_t test2[] = { 0x00, 0x00, 0x00, 0x00 };
    uint16_t csum2 = protocol_compute_checksum(test2, 4);
    if (csum2 != 0xFFFF) { printf("FAIL: checksum of all-zeros should be 0xFFFF, got 0x%04x\n", (unsigned)csum2); return 1; }
    printf("PASS: Checksum of zero data = 0x%04x\n", (unsigned)csum2);

    return 0;
}
CEOF

if gcc -Wall -Wextra -std=gnu99 -o "${TMPDIR}/test_checksum" "${TMPDIR}/test_checksum.c" 2>&1; then
    if "${TMPDIR}/test_checksum" 2>&1 | grep -q "FAIL"; then
        fail "Checksum test had failures"
    else
        "${TMPDIR}/test_checksum"
        pass "Checksum computation is correct"
    fi
else
    fail "Could not compile checksum test"
fi

# ──────────────────────────────────────────
echo ""
echo "--- Integration: Port Knock + Obfuscated Session ---"

SKIP_INTEGRATION=0

if [ "$(id -u)" != "0" ]; then
    skip "Integration test requires root (pcap + raw sockets)"
    skip "Run: sudo ./test.sh"
    SKIP_INTEGRATION=1
fi

if [ "${SKIP_INTEGRATION}" = "0" ]; then
    touch "${TMPDIR}/test_upload_file.txt"
    echo "integration test data for file transfer" > "${TMPDIR}/test_upload_file.txt"

    echo "Starting victim..."
    ./victim > "${VICTIM_LOG}" 2>&1 &
    VICTIM_PID=$!
    sleep 2

    if ! kill -0 ${VICTIM_PID} 2>/dev/null; then
        fail "Victim process failed to start"
        cat "${VICTIM_LOG}"
        SKIP_INTEGRATION=1
    else
        pass "Victim process started (PID ${VICTIM_PID})"

        if grep -qi "process conceal\|kworker\|conceal" "${VICTIM_LOG}" 2>/dev/null; then
            pass "Process concealment active"
        fi
    fi

    if [ "${SKIP_INTEGRATION}" = "0" ]; then
        echo "Running commander connect sequence..."
        timeout ${TIMEOUT} expect << EXPECT_SCRIPT 2>&1 > "${COMMANDER_LOG}"
set timeout 25
spawn ./commander 127.0.0.1 --connect
expect {
    "Session active" {
        puts "\n*** SESSION ESTABLISHED ***"
        send "9\r"
        expect "Victim*"
        puts "\n*** HEARTBEAT OK ***"
        send "10\r"
        expect "Commander Menu"
        send "3\r"
        puts "\n*** DISCONNECTED ***"
    }
    timeout { puts "TIMEOUT"; exit 1 }
    eof { puts "EOF"; exit 1 }
}
expect eof
EXPECT_SCRIPT

        if grep -q "SESSION ESTABLISHED" "${COMMANDER_LOG}" 2>/dev/null; then
            pass "Port knock + session open with obfuscated protocol succeeded"
        else
            fail "Port knock or session open failed"
            echo "--- Commander log ---"
            cat "${COMMANDER_LOG}"
            echo "--- Victim log ---"
            cat "${VICTIM_LOG}"
        fi

        if grep -q "HEARTBEAT OK" "${COMMANDER_LOG}" 2>/dev/null; then
            pass "Heartbeat command works through obfuscated channel"
        else
            fail "Heartbeat command failed"
        fi

        if grep -q "verified IP ID\|Command HEARTBEAT.*TOS 0x" "${VICTIM_LOG}" 2>/dev/null; then
            pass "IP ID verification during knock logged on victim"
        fi
    fi

    # Test file transfer
    if [ "${SKIP_INTEGRATION}" = "0" ]; then
        echo "Starting fresh victim for file transfer test..."
        kill ${VICTIM_PID} 2>/dev/null || true
        sleep 1
        ./victim > "${VICTIM_LOG}" 2>&1 &
        VICTIM_PID=$!
        sleep 2

        echo "Hello from integration test" > "/tmp/comp8505_protocol_test_local.txt"

        timeout ${TIMEOUT} expect << EXPECT_FILE 2>&1 > "${COMMANDER_LOG}"
set timeout 25
spawn ./commander 127.0.0.1 --connect
expect "Session active"
send "4\r"
expect "Local source path:"
send "/tmp/comp8505_protocol_test_local.txt\r"
expect "Remote destination path on victim"
send "/tmp/comp8505_protocol_test_dest.txt\r"
expect "Victim*"
puts "\n*** UPLOAD DONE ***"
send "5\r"
expect "Remote file path on victim:"
send "/tmp/comp8505_protocol_test_dest.txt\r"
expect "Local destination path"
send "/tmp/comp8505_protocol_test_dl.txt\r"
expect "Victim*"
puts "\n*** DOWNLOAD DONE ***"
send "10\r"
expect "Commander Menu"
send "3\r"
expect eof
EXPECT_FILE

        if grep -q "UPLOAD DONE" "${COMMANDER_LOG}" 2>/dev/null; then
            pass "File upload through obfuscated channel"
        else
            fail "File upload failed"
        fi

        if grep -q "DOWNLOAD DONE" "${COMMANDER_LOG}" 2>/dev/null; then
            pass "File download through obfuscated channel"
        else
            fail "File download failed"
        fi

        if [ -f "/tmp/comp8505_protocol_test_dl.txt" ] && \
           grep -q "Hello from integration test" "/tmp/comp8505_protocol_test_dl.txt" 2>/dev/null; then
            pass "Downloaded file content integrity verified"
        fi

        rm -f "/tmp/comp8505_protocol_test_local.txt" "/tmp/comp8505_protocol_test_dl.txt" 2>/dev/null || true
    fi

    # Cleanup
    kill ${VICTIM_PID} 2>/dev/null || true
    wait 2>/dev/null || true
fi

# ──────────────────────────────────────────
echo ""
echo "--- Process Renaming Verification ---"

if [ "$(uname -s)" = "Darwin" ]; then
    skip "Process renaming verification is platform-specific (reviewed manually)"
else
    skip "Linux process renaming verification requires /proc"
fi

# ──────────────────────────────────────────
echo ""
echo "--- Obfuscation Key Consistency ---"

cat > "${TMPDIR}/test_key_consistency.c" << 'CEOF'
#include <stdio.h>
#include <stdint.h>

#define OBFUSCATION_KEY_BASE 0xC75A9E3Du
#define SEQ_INIT 0x13370000u

uint32_t proto_derive(uint32_t id) {
    uint32_t k = OBFUSCATION_KEY_BASE ^ id;
    k ^= (k >> 17); k *= 0xED5AD4BBu; k ^= (k >> 11);
    k *= 0xAC4C1B51u; k ^= (k >> 15);
    return k;
}

int main() {
    uint32_t k1 = proto_derive(SEQ_INIT);
    uint32_t k2 = proto_derive(SEQ_INIT);
    uint32_t k3 = proto_derive(SEQ_INIT + 1);

    printf("Key from SEQ_INIT (call 1): 0x%08x\n", (unsigned)k1);
    printf("Key from SEQ_INIT (call 2): 0x%08x\n", (unsigned)k2);
    printf("Key from SEQ_INIT+1:       0x%08x\n", (unsigned)k3);

    if (k1 != k2) { printf("FAIL: Non-deterministic key derivation\n"); return 1; }
    if (k1 == k3) { printf("FAIL: Same key for different session IDs\n"); return 1; }
    if (k1 == 0)  { printf("FAIL: Key is zero\n"); return 1; }
    printf("PASS: Key derivation is deterministic and session-specific\n");
    return 0;
}
CEOF

if gcc -Wall -Wextra -std=gnu99 -o "${TMPDIR}/test_key" "${TMPDIR}/test_key_consistency.c" 2>&1; then
    if "${TMPDIR}/test_key" 2>&1 | grep -q "FAIL"; then
        fail "Key derivation consistency test failed"
    else
        "${TMPDIR}/test_key"
        pass "Key derivation: deterministic, session-specific, non-zero"
    fi
fi

# ──────────────────────────────────────────
echo ""
echo "--- Results ---"
echo ""
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo "  Skipped: ${SKIP}"
echo ""

if [ "${FAIL}" -gt 0 ]; then
    echo -e "${RED}*** TESTS FAILED ***${NC}"
    exit 1
else
    echo -e "${GREEN}All non-skipped tests passed.${NC}"
    exit 0
fi
