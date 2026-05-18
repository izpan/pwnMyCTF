#!/usr/bin/env bash
# OSINT WHOIS solver for pwnMyCTF

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/timeout.sh" 2>/dev/null || true

# OSINT WHOIS solver functions
solve_osint_whois() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "Attempting WHOIS lookup on: $target"
    
    # Extract domain from target if it's a URL
    local domain="$target"
    if [[ "$target" =~ ^https?://([^/]+) ]]; then
        domain="${BASH_REMATCH[1]}"
        # Remove port if present
        domain="${domain%%:*}"
    fi
    
    # Basic domain validation
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
        log_verbose 2 "Invalid domain format: $domain"
        return 1
    fi
    
    # Check if whois command is available
    if ! command -v whois &>/dev/null; then
        log_verbose 2 "whois command not found"
        return 1
    fi
    
    # Perform WHOIS query with timeout
    local whois_output
    if whois_output=$(timeout 10 whois "$domain" 2>/dev/null); then
        log_verbose 2 "WHOIS query successful"
        
        # Check if WHOIS output contains flag patterns
        local flag
        if flag=$(echo "$whois_output" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
            echo "$flag"
            return 0
        fi
        
        # Also check for common CTF WHOIS trick: flag in registrar or other fields
        # For now, just return success if we got WHOIS data (caller can inspect manually)
        if [[ -n "$whois_output" ]]; then
            log_verbose 2 "WHOIS data retrieved (no flag found in output)"
            return 0
        fi
    else
        log_verbose 2 "WHOIS query failed or timed out"
    fi
    
    return 1
}

# Export functions
export -f solve_osint_whois