#!/usr/bin/env bash
# OSINT Web scraping solver for pwnMyCTF

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/http.sh" 2>/dev/null || true
source "${LIB_DIR}/timeout.sh" 2>/dev/null || true
source "${LIB_DIR}/encoding.sh" 2>/dev/null || true

# OSINT Web scraping solver functions
solve_osint_scrape() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "Attempting OSINT web scrape on: $target"
    
    # Fetch the target URL
    local html_content
    if ! html_content=$(http_get "$target" 2>/dev/null); then
        log_verbose 2 "Failed to fetch target: $target"
        return 1
    fi
    
    if [[ -z "$html_content" ]]; then
        log_verbose 2 "Empty response from target"
        return 1
    fi
    
    # Extract flags from HTML content directly
    local flag
    if flag=$(echo "$html_content" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
        echo "$flag"
        return 0
    fi
    
    # Look for flags in HTML comments
    if flag=$(echo "$html_content" | grep -o '<!--.*-->' | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
        echo "$flag"
        return 0
    fi
    
    # Look for flags in common HTML attributes that might hide data
    # Check value attributes
    if flag=$(echo "$html_content" | grep -o 'value="[^"]*"' | cut -d'"' -f2 | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
        echo "$flag"
        return 0
    fi
    
    # Check placeholder attributes
    if flag=$(echo "$html_content" | grep -o 'placeholder="[^"]*"' | cut -d'"' -f2 | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
        echo "$flag"
        return 0
    fi
    
    # Check title attributes
    if flag=$(echo "$html_content" | grep -o 'title="[^"]*"' | cut -d'"' -f2 | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
        echo "$flag"
        return 0
    fi
    
    # Extract and follow links (limited to same domain for safety)
    local domain=""
    if [[ "$target" =~ ^https?://([^/]+) ]]; then
        domain="${BASH_REMATCH[1]}"
        domain="${domain%%:*}"  # Remove port
    fi
    
    if [[ -n "$domain" ]]; then
        # Extract links from the page
        local links
        links=$(echo "$html_content" | grep -o 'href="[^"]*"' | cut -d'"' -f2 | grep -E "^https?://" | head -5)
        
        while IFS= read -r link; do
            # Skip if link is empty
            [[ -z "$link" ]] && continue
            
            # Only follow links to the same domain for basic SSRF protection
            local link_domain=""
            if [[ "$link" =~ ^https?://([^/]+) ]]; then
                link_domain="${BASH_REMATCH[1]}"
                link_domain="${link_domain%%:*}"
            fi
            
            if [[ "$link_domain" == "$domain" ]]; then
                log_verbose 2 "Following link to: $link"
                local link_content
                if link_content=$(http_get "$link" 2>/dev/null); then
                    if flag=$(echo "$link_content" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                        echo "$flag"
                        return 0
                    fi
                fi
            fi
        done <<< "$links"
    fi
    
    return 1
}

# Export functions
export -f solve_osint_scrape