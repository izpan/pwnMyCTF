#!/usr/bin/env bash
# OSINT DNS solver for pwnMyCTF

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/timeout.sh" 2>/dev/null || true

# OSINT DNS solver functions
solve_osint_dns() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "Attempting DNS reconnaissance on: $target"
    
    # Check if target looks like a domain/IP
    if [[ ! "$target" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
        # Might be a URL, extract hostname
        if [[ "$target" =~ ^https?://([^/]+) ]]; then
            target="${BASH_REMATCH[1]}"
        else
            return 1
        fi
    fi
    
    local results=""
    
    # Try different DNS tools
    local dns_tool=""
    if command -v dig &>/dev/null; then
        dns_tool="dig"
    elif command -v host &>/dev/null; then
        dns_tool="host"
    elif command -v nslookup &>/dev/null; then
        dns_tool="nslookup"
    else
        log_verbose 2 "No DNS tool available (dig, host, or nslookup required)"
        return 1
    fi
    
    # Forward lookup (A record)
    if [[ "$dns_tool" == "dig" ]]; then
        local a_record
        if a_record=$(dig +short "$target" A 2>/dev/null | head -5); then
            if [[ -n "$a_record" ]]; then
                results+="A records: $a_record\n"
                # Check if any A record contains a flag pattern
                local flag
                if flag=$(echo "$a_record" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    elif [[ "$dns_tool" == "host" ]]; then
        local a_record
        if a_record=$(host "$target" 2>/dev/null | grep "has address" | awk '{print $NF}' | head -5); then
            if [[ -n "$a_record" ]]; then
                results+="A records: $a_record\n"
                # Check if any A record contains a flag pattern
                local flag
                if flag=$(echo "$a_record" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    fi
    
    # Try TXT records (often used for flags in CTF)
    if [[ "$dns_tool" == "dig" ]]; then
        local txt_record
        if txt_record=$(dig +short "$target" TXT 2>/dev/null); then
            if [[ -n "$txt_record" ]]; then
                results+="TXT records: $txt_record\n"
                # Check if any TXT record contains a flag
                local flag
                if flag=$(echo "$txt_record" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    elif [[ "$dns_tool" == "host" ]]; then
        local txt_record
        if txt_record=$(host -t TXT "$target" 2>/dev/null); then
            if [[ -n "$txt_record" ]]; then
                results+="TXT records: $txt_record\n"
                # Check if any TXT record contains a flag
                local flag
                if flag=$(echo "$txt_record" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    fi
    
    # If we found interesting DNS info but no flag, return success with info
    # (In a real implementation, we might return the DNS info for manual inspection)
    if [[ -n "$results" ]]; then
        log_verbose 2 "DNS info found:\n$results"
        # For now, we'll just indicate we found something interesting
        # In a real CTF solver, we might return this info or continue testing
        return 0
    fi
    
    return 1
}

# Export functions
export -f solve_osint_dns