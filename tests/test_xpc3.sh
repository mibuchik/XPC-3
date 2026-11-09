#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$REPO_DIR/XPC-3/xpc3"
TMP_DIR="$(mktemp -d /tmp/xpc3-tests.XXXXXX)"

trap 'rm -rf "$TMP_DIR"' EXIT

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

pass_count=0
fail_count=0

run_test() {
    local name="$1"
    shift
    printf "${CYAN}[TEST]${NC} %-45s " "$name..."
    if "$@"; then
        printf "${GREEN}${BOLD}[PASS]${NC}\n"
        pass_count=$((pass_count + 1))
    else
        printf "${RED}${BOLD}[FAIL]${NC}\n"
        fail_count=$((fail_count + 1))
    fi
}

# 1. Text Round-trip
test_text_roundtrip() {
    local in="$TMP_DIR/plain.txt"
    local enc="$TMP_DIR/plain.txt.xpc"
    local dec="$TMP_DIR/plain_dec.txt"
    echo "XPC-3: The quick brown fox jumps over the lazy dog. 1234567890!@#$%^&*()_+" > "$in"

    "$BIN" enc -i "$in" -o "$enc" -p "SuperSecretPassphrase123!" >/dev/null 2>&1
    "$BIN" dec -i "$enc" -o "$dec" -p "SuperSecretPassphrase123!" >/dev/null 2>&1

    cmp "$in" "$dec" >/dev/null 2>&1
}

# 2. Binary 1MB Round-trip
test_binary_1mb() {
    local in="$TMP_DIR/bin1m.dat"
    local enc="$TMP_DIR/bin1m.xpc"
    local dec="$TMP_DIR/bin1m_dec.dat"
    head -c 1048576 /dev/urandom > "$in"

    "$BIN" enc -i "$in" -o "$enc" -p "BinaryKeyTest@2026" >/dev/null 2>&1
    "$BIN" dec -i "$enc" -o "$dec" -p "BinaryKeyTest@2026" >/dev/null 2>&1

    cmp "$in" "$dec" >/dev/null 2>&1
}

# 3. Wrong Password Detection
test_wrong_password() {
    local in="$TMP_DIR/auth_test.txt"
    local enc="$TMP_DIR/auth_test.xpc"
    local dec="$TMP_DIR/auth_test_dec.txt"
    echo "Top secret intelligence" > "$in"

    "$BIN" enc -i "$in" -o "$enc" -p "RightPassword" >/dev/null 2>&1
    if "$BIN" dec -i "$enc" -o "$dec" -p "WrongPassword" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# 4. Tamper Resistance: Body Corruption
test_tamper_body() {
    local in="$TMP_DIR/tamper_body.txt"
    local enc="$TMP_DIR/tamper_body.xpc"
    local dec="$TMP_DIR/tamper_body_dec.txt"
    echo "Do not modify this ciphertext or integrity verification fails!" > "$in"

    "$BIN" enc -i "$in" -o "$enc" -p "TamperCheckPass" >/dev/null 2>&1
    
    # Flip byte at offset 120
    python3 -c "
with open('$enc', 'r+b') as f:
    f.seek(120)
    b = f.read(1)
    f.seek(120)
    f.write(bytes([b[0] ^ 0xFF]))
"
    if "$BIN" dec -i "$enc" -o "$dec" -p "TamperCheckPass" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# 5. Tamper Resistance: Header/Salt Corruption
test_tamper_salt() {
    local in="$TMP_DIR/tamper_salt.txt"
    local enc="$TMP_DIR/tamper_salt.xpc"
    local dec="$TMP_DIR/tamper_salt_dec.txt"
    echo "Salt protection verification test." > "$in"

    "$BIN" enc -i "$in" -o "$enc" -p "SaltPass123" >/dev/null 2>&1

    # Flip byte in salt (byte 10)
    python3 -c "
with open('$enc', 'r+b') as f:
    f.seek(10)
    b = f.read(1)
    f.seek(10)
    f.write(bytes([b[0] ^ 0xAA]))
"
    if "$BIN" dec -i "$enc" -o "$dec" -p "SaltPass123" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# 6. Tamper Resistance: Trailer Corruption
test_tamper_trailer() {
    local in="$TMP_DIR/tamper_trailer.txt"
    local enc="$TMP_DIR/tamper_trailer.xpc"
    local dec="$TMP_DIR/tamper_trailer_dec.txt"
    echo "Testing inner HMAC and padding trailer integrity." > "$in"

    "$BIN" enc -i "$in" -o "$enc" -p "TrailerPass" >/dev/null 2>&1

    # Flip last byte (padding length byte)
    python3 -c "
with open('$enc', 'r+b') as f:
    f.seek(-1, 2)
    b = f.read(1)
    f.seek(-1, 2)
    f.write(bytes([b[0] ^ 0x01]))
"
    if "$BIN" dec -i "$enc" -o "$dec" -p "TrailerPass" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# 7. Non-existent file error
test_missing_file() {
    if "$BIN" enc -i "$TMP_DIR/definitely_not_exists.dat" -o "$TMP_DIR/out.xpc" -p "abc" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

echo "======================================================="
echo "  XPC-3 Cryptographic & Security Verification Suite    "
echo "======================================================="

run_test "UTF-8 Text Round-trip" test_text_roundtrip
run_test "1 MiB Binary File Round-trip" test_binary_1mb
run_test "Wrong Passphrase Rejection" test_wrong_password
run_test "AEAD Tamper Detection (Ciphertext Body)" test_tamper_body
run_test "AEAD Tamper Detection (Salt Header)" test_tamper_salt
run_test "HMAC/Trailer Tamper Detection (Pad byte)" test_tamper_trailer
run_test "Missing File Error Handling" test_missing_file

echo "======================================================="
printf "Summary: %d Passed, %d Failed\n" "$pass_count" "$fail_count"
echo "======================================================="

if [ "$fail_count" -gt 0 ]; then
    exit 1
fi
exit 0
