#!/usr/bin/env bash
# Web JSON solver for pwnMyCTF

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/http.sh" 2>/dev/null || true
source "${LIB_DIR}/encoding.sh" 2>/dev/null || true

# Check if jq is available
HAS_JQ=false
if command -v jq &>/dev/null; then
    HAS_JQ=true
fi

# Web JSON solver functions
solve_web_json() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "Attempting web JSON solve on: $target"
    
    # Fetch JSON data from target
    local json_data
    if ! json_data=$(http_get "$target" 2>/dev/null); then
        return 1
    fi
    
    # Check if we got valid JSON
    if ! echo "$json_data" | grep -q '^{.*}$\|^\[.*\]$'; then
        # Might be JSON embedded in text/jsonp
        # Extract JSON-like content
        json_data=$(echo "$json_data" | grep -o '{[^}]*}\|\[[^]]*\]' | head -1)
        if [[ -z "$json_data" ]]; then
            return 1
        fi
    fi
    
    # Extract flags from JSON
    local flag=""
    
    if [[ "$HAS_JQ" == "true" ]]; then
        # Use jq to recursively search for flag patterns
        flag=$(echo "$json_data" | jq -r '.. | select(type=="string") | select(test("flag\\{.*\\}|FLAG\\{.*\\}|CTF\\{.*\\}"))' 2>/dev/null | head -1)
    else
        # Fallback: grep for flag patterns in JSON string
        flag=$(echo "$json_data" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1)
    fi
    
    if [[ -n "$flag" ]]; then
        echo "$flag"
        return 0
    fi
    
    return 1
}

# Also solve by sending JSON payloads (for API endpoints)
solve_web_json_post() {
    local target="$1"
    local json_payload="$2"
    local verbose="${3:-0}"
    
    log_verbose 2 "Attempting web JSON POST solve on: $target"
    
    local headers=("Content-Type: application/json")
    local response
    
    if response=$(http_post "$target" "$json_payload" "${headers[@]}" 2>/dev/null); then
        local flag
        flag=$(echo "$response" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1)
        if [[ -n "$flag" ]]; then
            echo "$flag"
            return 0
        fi
    fi
    
    return 1
}

# Export functions
export -f solve_web_json
export -f solve_web_json_post