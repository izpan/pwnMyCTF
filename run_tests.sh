#!/usr/bin/env bash
# Test runner for pwnMyCTF phase 8 advanced patterns

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

echo "Running unit tests for retry.sh..."
cd "$SCRIPT_DIR/test/unit" && shunit2 test_retry.sh
RETRY_RESULT=$?

echo "Running unit tests for parallel.sh..."
cd "$SCRIPT_DIR/test/unit" && shunit2 test_parallel.sh
PARALLEL_RESULT=$?

echo "Running unit tests for tool_discovery.sh..."
cd "$SCRIPT_DIR/test/unit" && shunit2 test_tool_discovery.sh
TOOL_DISCOVERY_RESULT=$?

echo "Running E2E tests for retry integration..."
cd "$SCRIPT_DIR/test/e2e" && shunit2 test_retry_integration.sh
RETRY_INTEGRATION_RESULT=$?

echo "Running E2E tests for parallel integration..."
cd "$SCRIPT_DIR/test/e2e" && shunit2 test_parallel_integration.sh
PARALLEL_INTEGRATION_RESULT=$?

echo "Running E2E tests for tool discovery integration..."
cd "$SCRIPT_DIR/test/e2e" && shunit2 test_tool_discovery_integration.sh
TOOL_DISCOVERY_INTEGRATION_RESULT=$?

# Determine overall success
if [ $RETRY_RESULT -eq 0 ] && [ $PARALLEL_RESULT -eq 0 ] && [ $TOOL_DISCOVERY_RESULT -eq 0 ] && \
   [ $RETRY_INTEGRATION_RESULT -eq 0 ] && [ $PARALLEL_INTEGRATION_RESULT -eq 0 ] && [ $TOOL_DISCOVERY_INTEGRATION_RESULT -eq 0 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Some tests failed!"
    echo "Retry unit tests: $RETRY_RESULT"
    echo "Parallel unit tests: $PARALLEL_RESULT"
    echo "Tool discovery unit tests: $TOOL_DISCOVERY_RESULT"
    echo "Retry integration tests: $RETRY_INTEGRATION_RESULT"
    echo "Parallel integration tests: $PARALLEL_INTEGRATION_RESULT"
    echo "Tool discovery integration tests: $TOOL_DISCOVERY_INTEGRATION_RESULT"
    exit 1
fi