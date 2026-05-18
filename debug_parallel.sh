#!/usr/bin/env bash
# Debug the parallel library

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
source "${SCRIPT_DIR}/lib/parallel.sh"

echo "Testing run_parallel with simple echo..."
result=$(run_parallel 5 "echo 'hello'")
echo "Result: [$result]"
echo "Length: ${#result}"
echo "Hex dump:"
echo -n "$result" | xxd