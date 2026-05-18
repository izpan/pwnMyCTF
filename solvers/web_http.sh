#!/usr/bin/env bash
# Web HTTP solver for pwnMyCTF

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/http.sh" 2>/dev/null || true
source "${LIB_DIR}/encoding.sh" 2>/dev/null || true
source "${LIB_DIR}/timeout.sh" 2>/dev/null || true

# Web HTTP solver functions
solve_web_http() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "Attempting web HTTP solve on: $target"
    
    # Try to fetch the target with common headers that might reveal flags
    local headers=(
        "User-Agent: pwnMyCTF Web Solver"
        "Referer: https://google.com/"
        "X-Forwarded-For: 127.0.0.1"
        "X-Real-IP: 127.0.0.1"
    )
    
    # Try each header individually and in combination
    for header in "${headers[@]}"; do
        local response
        if response=$(http_get "$target" "$header" 2>/dev/null); then
            if echo "$response" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1; then
                return 0
            fi
        fi
    done
    
    # Try with all headers at once
    local response
    if response=$(http_get "$target" "${headers[@]}" 2>/dev/null); then
        if echo "$response" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1; then
            return 0
        fi
    fi
    
    return 1
}

# Export functions
export -f solve_web_http