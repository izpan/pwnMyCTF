#!/usr/bin/env bash
# Simple end-to-end test for pwnMyCTF

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
PWNMYCTF="${SCRIPT_DIR}/pwnmyctf.sh"

echo "=== Simple E2E Test for pwnMyCTF ==="

# Test 1: Check if --help shows retries flag
echo "Test 1: Checking help output for --retries flag"
help_output=$("$PWNMYCTF" --help 2>&1)
if echo "$help_output" | grep -q "\-\-retries"; then
    echo "PASS: --retries flag found in help"
else
    echo "FAIL: --retries flag NOT found in help"
    echo "Help output was:"
    echo "$help_output"
fi

# Test 2: Create a simple test file with a flag
echo "Test 2: Testing basic solve functionality"
echo "flag{test123}" > /tmp/test_flag.txt
output=$("$PWNMYCTF" solve /tmp/test_flag.txt 2>/dev/null)
if [ "$output" = "flag{test123}" ]; then
    echo "PASS: Basic solve works"
else
    echo "FAIL: Basic solve failed. Expected 'flag{test123}', got '$output'"
fi
rm -f /tmp/test_flag.txt

# Test 3: Test --retries 0 (should work same as default)
echo "Test 3: Testing --retries 0"
echo "flag{test456}" > /tmp/test_flag2.txt
output=$("$PWNMYCTF" --retries 0 solve /tmp/test_flag2.txt 2>/dev/null)
if [ "$output" = "flag{test456}" ]; then
    echo "PASS: --retries 0 works"
else
    echo "FAIL: --retries 0 failed. Expected 'flag{test456}', got '$output'"
fi
rm -f /tmp/test_flag2.txt

# Test 4: Test --retries with a number
echo "Test 4: Testing --retries 2"
echo "flag{test789}" > /tmp/test_flag3.txt
output=$("$PWNMYCTF" --retries 2 solve /tmp/test_flag3.txt 2>/dev/null)
if [ "$output" = "flag{test789}" ]; then
    echo "PASS: --retries 2 works"
else
    echo "FAIL: --retries 2 failed. Expected 'flag{test789}', got '$output'"
fi
rm -f /tmp/test_flag3.txt

# Test 5: Test invalid --retries value
echo "Test 5: Testing invalid --retries value"
output=$("$PWNMYCTF" --retries abc solve /etc/passwd 2>&1)
if echo "$output" | grep -q "invalid number"; then
    echo "PASS: Invalid retries value properly rejected"
else
    echo "FAIL: Invalid retries value not properly rejected. Output: '$output'"
fi

echo "=== E2E Tests Completed ==="