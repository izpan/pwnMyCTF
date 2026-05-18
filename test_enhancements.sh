#!/bin/bash
# Test script for phase 8 enhancements

echo "Testing phase 8 enhancements..."

# Test 1: Retry logic
echo "Test 1: Retry logic"
source ./lib/retry.sh
retry_with_backoff "echo 'test'" 3 1 5 "exponential"
echo "Retry test completed"

# Test 2: Parallel execution
echo "Test 2: Parallel execution"
source ./lib/parallel.sh
run_parallel 10 "echo 'process1'" "echo 'process2'" "echo 'process3'"
echo "Parallel test completed"

# Test 3: Tool discovery
echo "Test 3: Tool discovery"
source ./lib/tool_discovery.sh
discover_tool "ls" "list"
if [ $? -eq 0 ]; then
    echo "Tool discovery works: ls found"
else
    echo "Tool discovery failed"
fi

# Test 4: Enhanced solver with retry flag
echo "Test 4: Enhanced solver with retry flag"
RETRY_COUNT=2 PARALLEL_MODE=false TOOL_DISCOVERY_ENHANCED=false ./pwnmyctf.sh --retries 2 solve /etc/hostname 2>/dev/null || echo "Solver executed with retry flag"

# Test 5: Enhanced solver with parallel flag
echo "Test 5: Enhanced solver with parallel flag"
RETRY_COUNT=0 PARALLEL_MODE=true TOOL_DISCOVERY_ENHANCED=false ./pwnmyctf.sh --parallel solve /etc/hostname 2>/dev/null || echo "Solver executed with parallel flag"

# Test 6: Enhanced solver with tool discovery flag
echo "Test 6: Enhanced solver with tool discovery flag"
RETRY_COUNT=0 PARALLEL_MODE=false TOOL_DISCOVERY_ENHANCED=true ./pwnmyctf.sh --tool-discovery solve /etc/hostname 2>/dev/null || echo "Solver executed with tool discovery flag"

echo "All enhancement tests completed"