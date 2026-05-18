#!/usr/bin/env bash
source lib/timeout.sh 2>/dev/null || true

# Define the whois function locally for this test
whois() {
    if [[ "$1" == "example.com" ]]; then
        echo "Registrar: Example Registrar
Creation Date: 2020-01-01
flag{whois_test_flag}
Updated Date: 2024-01-01"
        return 0
    fi
    return 1
}

# Source the solver after defining the mock
source solvers/osint_whois.sh

# Test the solver
result=$(solve_osint_whois "example.com" 1 2>&1)
echo "Result: $result"
