#!/usr/bin/env bash
# OSINT Headers solver for pwnMyCTF

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/http.sh" 2>/dev/null || true

# OSINT Headers solver functions
solve_osint_headers() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "Analyzing HTTP headers for: $target"
    
    # Fetch headers from target (try to get just headers if possible)
    local headers=""
    local full_response=""
    
    if command -v curl &>/dev/null; then
        # Get headers only
        headers=$(curl -sI "$target" 2>/dev/null)
        # Also get full response for body analysis
        full_response=$(curl -sL "$target" 2>/dev/null)
    elif command -v wget &>/dev/null; then
        # wget doesn't have a good headers-only option, get full and extract headers
        full_response=$(wget -q -O - --server-response --timeout=10 "$target" 2>/dev/null)
        headers=$(echo "$full_response" | sed -n '/^HTTP/,/^$/p' | head -n -1)
        # Extract just the body for separate analysis
        full_response=$(echo "$full_response" | sed '1,/^$/d')
    else
        log_verbose 2 "No HTTP client available"
        return 1
    fi
    
    if [[ -z "$headers" && -z "$full_response" ]]; then
        log_verbose 2 "Failed to fetch target"
        return 1
    fi
    
    # Analyze headers for flags
    echo "$headers" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1 && return 0
    
    # Look for suspicious headers that might contain encoded flags
    echo "$headers" | while IFS= read -r line; do
        # Skip HTTP status line
        [[ "$line" =~ ^HTTP/ ]] && continue
        
        # Extract header value
        if [[ "$line" =~ ^[^:]+:[[:space:]]*(.*)$ ]]; then
            local value="${BASH_REMATCH[1]}"
            
            # Check if value looks like base64
            if echo "$value" | grep -qE '^[A-Za-z0-9+/]+=*$' && [[ ${#value} -gt 10 ]]; then
                if decoded=$(echo "$value" | base64 -d 2>/dev/null); then
                    if echo "$decoded" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1; then
                        return 0
                    fi
                fi
            fi
            
            # Check if value looks like hex
            if echo "$value" | grep -qE '^[0-9A-Fa-f]+$' && [[ $((${#value} % 2)) -eq 0 ]]; then
                if decoded=$(echo "$value" | xxd -r -p 2>/dev/null); then
                    if echo "$decoded" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1; then
                        return 0
                    fi
                fi
            fi
        fi
    done
    
    # Also check the response body for completeness
    if [[ -n "$full_response" ]]; then
        if echo "$full_response" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1; then
            return 0
        fi
    fi
    
    return 1
}

# Export functions
export -f solve_osint_headers