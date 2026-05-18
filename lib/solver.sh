#!/usr/bin/env bash
# Solver dispatcher for pwnMyCTF with phase 8 enhancements

set -uo pipefail

# Define log_verbose if not already defined (for when this file is sourced directly)
if ! declare -f log_verbose > /dev/null; then
    log_verbose() { :; }
fi

# Source enhancement libraries if available
source "${LIB_DIR}/retry.sh" 2>/dev/null || true
source "${LIB_DIR}/parallel.sh" 2>/dev/null || true
source "${LIB_DIR}/tool_discovery.sh" 2>/dev/null || true

solve_challenge() {
    local target="$1"
    local category="$2"
    local type="$3"
    
    log_verbose 1 "Dispatching to ${category} solver for ${type}"
    
    # Define the solver function based on category
    local solver_func
    case "$category" in
        web)
            solver_func="solver_web"
            ;;
        crypto)
            solver_func="solver_crypto"
            ;;
        pwn)
            solver_func="solver_pwn"
            ;;
        reverse)
            solver_func="solver_reverse"
            ;;
        forensics)
            solver_func="solver_forensics"
            ;;
        osint)
            solver_func="solver_osint"
            ;;
        unknown|*)
            solver_func="solver_generic"
            ;;
    esac
    
    # Check if we should use enhanced tool discovery
    if [[ "$TOOL_DISCOVERY_ENHANCED" == "true" ]]; then
        # Enhance tool checking for this category
        enhance_tool_checking_for_category "$category"
    fi
    
    # Apply retry logic if RETRY_COUNT is greater than 0
    if [[ "$RETRY_COUNT" -gt 0 ]]; then
        log_verbose 1 "Using retry logic with $RETRY_COUNT attempts"
        # Define the solving command for retry
        local solve_cmd="if declare -f \"$solver_func\" > /dev/null 2>&1; then \"$solver_func\" \"$target\" \"$type\"; else solver_generic \"$target\" \"$type\"; fi"
        retry_with_backoff "$solve_cmd" "$RETRY_COUNT" 1 10 "exponential"
        return $?
    fi
    
    # Apply parallel execution if enabled
    if [[ "$PARALLEL_MODE" == "true" ]]; then
        log_verbose 1 "Using parallel execution"
        # For now, we'll just run the solver once since we don't have multiple approaches
        # In a more advanced implementation, we would run multiple solver approaches in parallel
        if declare -f "$solver_func" > /dev/null 2>&1; then
            "$solver_func" "$target" "$type"
            return $?
        else
            log_verbose 1 "Solver function $solver_func not found, using generic solver"
            solver_generic "$target" "$type"
            return $?
        fi
    fi
    
    # Normal execution
    if declare -f "$solver_func" > /dev/null 2>&1; then
        "$solver_func" "$target" "$type"
        return $?
    else
        log_verbose 1 "Solver function $solver_func not found, using generic solver"
        solver_generic "$target" "$type"
        return $?
    fi
}

# Function to enhance tool checking for a specific category
enhance_tool_checking_for_category() {
    local category="$1"
    case "$category" in
        web)
            # Enhance web solver tools
            discover_tool "curl" "wget"
            discover_tool "openssl"
            ;;
        crypto)
            # Enhance crypto solver tools
            discover_tool "openssl"
            discover_tool "xxd"
            discover_tool "base64"
            ;;
        pwn)
            # Enhance pwn solver tools
            discover_tool "gdb"
            discover_tool "strings"
            discover_tool "objdump"
            ;;
        reverse)
            # Enhance reverse solver tools
            discover_tool "strings"
            discover_tool "objdump"
            discover_tool "ldd"
            ;;
        forensics)
            # Enhance forensics solver tools
            discover_tool "file"
            discover_tool "strings"
            discover_tool "unzip"
            discover_tool "tar"
            discover_tool "gzip"
            ;;
        osint)
            # Enhance OSINT solver tools
            discover_tool "curl" "wget"
            discover_tool "dig" "host"
            discover_tool "whois"
            discover_tool "git"
            ;;
    esac
}

solver_web() {
    local target="$1"
    local type="$2"
    
    log_verbose 1 "Web solver: $target (type: $type)"
    
    case "$type" in
        file)
            local content
            content=$(cat "$target" 2>/dev/null)
            web_analyze_content "$content"
            return $?
            ;;
        url)
            web_solve_url "$target"
            return $?
            ;;
        directory)
            web_solve_directory "$target"
            return $?
            ;;
        *)
            web_solve_generic "$target"
            return $?
            ;;
    esac
}

web_analyze_content() {
    local content="$1"
    
    if echo "$content" | grep -qi "sql\|select\|union\|or 1=1"; then
        log_verbose 1 "Detected SQL injection pattern"
    fi
    
    if echo "$content" | grep -qi "xss\|<script\|onerror"; then
        log_verbose 1 "Detected XSS pattern"
    fi
    
    local flag
    if flag=$(echo "$content" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
        echo "$flag"
        return 0
    fi
    
    return 2
}

web_solve_url() {
    local url="$1"
    local response
    local cmd
    
    if command -v curl &>/dev/null; then
        cmd="curl -sL --max-time 30"
    else
        cmd="wget -q -O - --timeout=30"
    fi
    
    response=$(eval "$cmd '$url'" 2>/dev/null) || {
        log_verbose 1 "Failed to fetch URL"
        return 1
    }
    
    web_analyze_content "$response"
    return $?
}

web_solve_directory() {
    local dir="$1"
    
    for file in "$dir"/*; do
        [[ -f "$file" ]] || continue
        local result
        if result=$(solver_web "$file" "file" 2>/dev/null); then
            echo "$result"
            return 0
        fi
    done
    
    return 2
}

web_solve_generic() {
    local target="$1"
    local flag
    
    if [[ -f "$target" ]]; then
        flag=$(grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' "$target" 2>/dev/null | head -1)
    elif [[ "$target" =~ ^https?:// ]]; then
        flag=$(web_solve_url "$target")
    fi
    
    if [[ -n "$flag" ]]; then
        echo "$flag"
        return 0
    fi
    
    return 2
}

solver_crypto() {
    local target="$1"
    local type="$2"
    
    log_verbose 1 "Crypto solver: $target (type: $type)"
    
    # Source the crypto solver if not already sourced
    if ! declare -f solve_crypto > /dev/null 2>&1; then
        source "${LIB_DIR}/../solvers/crypto.sh" 2>/dev/null || true
    fi
    
    if declare -f solve_crypto > /dev/null 2>&1; then
        solve_crypto "$target" "$VERBOSE"
        return $?
    fi
    
    # Fallback to simple crypto solving if solver not available
    local content
    case "$type" in
        file)
            content=$(cat "$target" 2>/dev/null)
            ;;
        *)
            content="$target"
            ;;
    esac
    
    crypto_solve_content "$content"
    return $?
}

crypto_solve_content() {
    local content="$1"
    local decoded
    
    if echo "$content" | grep -qE '^[A-Za-z0-9+/]+=*$' && [[ ${#content} -gt 10 ]]; then
        if decoded=$(echo "$content" | base64 -d 2>/dev/null); then
            log_verbose 1 "Base64 decoded"
            local flag
            if flag=$(echo "$decoded" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1); then
                echo "$flag"
                return 0
            fi
        fi
    fi
    
    if echo "$content" | grep -qE '^[0-9A-Fa-f]+$' && [[ $((${#content} % 2)) -eq 0 ]]; then
        if decoded=$(echo "$content" | xxd -r -p 2>/dev/null); then
            log_verbose 1 "Hex decoded"
            local flag
            if flag=$(echo "$decoded" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1); then
                echo "$flag"
                return 0
            fi
        fi
    fi
    
    local flag
    if flag=$(echo "$content" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1); then
        echo "$flag"
        return 0
    fi
    
    return 2
}

solver_pwn() {
    local target="$1"
    local type="$2"

    log_verbose 1 "Pwn solver: $target (type: $type)"

    # Source the pwn solver if not already sourced
    if ! declare -f solve_pwn > /dev/null 2>&1; then
        source "${LIB_DIR}/../solvers/pwn.sh" 2>/dev/null || true
    fi

    if declare -f solve_pwn > /dev/null 2>&1; then
        solve_pwn "$target" "${VERBOSE:-0}"
        return $?
    fi

    # Fallback: basic string search if solver not available
    if [[ ! -f "$target" ]]; then
        return 2
    fi

    local flag
    flag=$(strings "$target" 2>/dev/null | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1)

    if [[ -n "$flag" ]]; then
        echo "$flag"
        return 0
    fi

    return 2
}

solver_reverse() {
    local target="$1"
    local type="$2"
    
    log_verbose 1 "Reverse solver: $target (type: $type)"
    
    # Source the reverse solver if not already sourced
    if ! declare -f solve_reverse > /dev/null 2>&1; then
        source "${LIB_DIR}/../solvers/reverse.sh" 2>/dev/null || true
    fi
    
    if declare -f solve_reverse > /dev/null 2>&1; then
        solve_reverse "$target" "$VERBOSE"
        return $?
    fi
    
    # Fallback if solver not available
    log_verbose 1 "Reverse solver not available, returning 2"
    return 2
}

solver_forensics() {
    local target="$1"
    local type="$2"
    
    log_verbose 1 "Forensics solver: $target (type: $type)"
    
    # Source the forensics solver if not already sourced
    if ! declare -f solve_forensics > /dev/null 2>&1; then
        source "${LIB_DIR}/../solvers/forensics.sh" 2>/dev/null || true
    fi
    
    if declare -f solve_forensics > /dev/null 2>&1; then
        solve_forensics "$target" "$VERBOSE"
        return $?
    fi
    
    # Fallback to simple forensics solving if solver not available
    case "$type" in
        file)
            forensics_solve_file "$target"
            return $?
            ;;
        directory)
            forensics_solve_directory "$target"
            return $?
            ;;
        *)
            return 2
            ;;
    esac
}

forensics_solve_file() {
    local file="$1"
    local mime
    mime=$(file -b --mime-type "$file" 2>/dev/null)
    
    case "$mime" in
        application/zip)
            local flag
            if flag=$(unzip -l "$file" 2>/dev/null | grep -Eo 'flag\{[^}]+\}' | head -1); then
                echo "$flag"
                return 0
            fi
            ;;
    esac
    
    local flag
    flag=$(cat "$file" 2>/dev/null | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}' | head -1)
    
    if [[ -n "$flag" ]]; then
        echo "$flag"
        return 0
    fi
    
    return 2
}

forensics_solve_directory() {
    local dir="$1"
    
    for file in "$dir"/*; do
        [[ -f "$file" ]] || continue
        local result
        if result=$(forensics_solve_file "$file" 2>/dev/null); then
            echo "$result"
            return 0
        fi
    done
    
    return 2
}

solver_osint() {
    local target="$1"
    local type="$2"
    
    log_verbose 1 "OSINT solver: $target (type: $type)"
    
    local flag=""
    
    case "$type" in
        file)
            # Try DNS first if it looks like a domain
            if [[ "$target" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
                if flag=$(solve_osint_dns "$target" "$VERBOSE" 2>/dev/null); then
                    echo "$flag"
                    return 0
                fi
            fi
            # Try WHOIS
            if flag=$(solve_osint_whois "$target" "$VERBOSE" 2>/dev/null); then
                echo "$flag"
                return 0
            fi
            # Try web scraping if it looks like a URL or file with URLs
            if flag=$(solve_osint_scrape "$target" "$VERBOSE" 2>/dev/null); then
                echo "$flag"
                return 0
            fi
            # Try git analysis if it looks like a git repository
            if flag=$(solve_osint_git "$target" "$VERBOSE" 2>/dev/null); then
                echo "$flag"
                return 0
            fi
            # Fall back to generic file search
            flag=$(grep -rEo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' "$target" 2>/dev/null | head -1)
            ;;
        url)
            # Try DNS on hostname extracted from URL
            local host=""
            if [[ "$target" =~ ^https?://([^/]+) ]]; then
                host="${BASH_REMATCH[1]}"
                host="${host%%:*}"  # Remove port
                if [[ "$host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
                    if flag=$(solve_osint_dns "$host" "$VERBOSE" 2>/dev/null); then
                        echo "$flag"
                        return 0
                    fi
                fi
            fi
            # Try WHOIS on hostname
            if [[ -n "$host" ]]; then
                if flag=$(solve_osint_whois "$host" "$VERBOSE" 2>/dev/null); then
                    echo "$flag"
                    return 0
                fi
            fi
            # Try web scraping on the URL
            if flag=$(solve_osint_scrape "$target" "$VERBOSE" 2>/dev/null); then
                echo "$flag"
                return 0
            fi
            # Try git analysis on the URL (checking for exposed .git)
            if flag=$(solve_osint_git "$target" "$VERBOSE" 2>/dev/null); then
                echo "$flag"
                return 0
            fi
            # Analyze headers
            if flag=$(solve_osint_headers "$target" "$VERBOSE" 2>/dev/null); then
                echo "$flag"
                return 0
            fi
            # Fall back to generic URL fetch
            local cmd
            if command -v curl &>/dev/null; then
                cmd="curl -sL --max-time 10"
            else
                cmd="wget -q -O - --timeout=10"
            fi
            flag=$(eval "$cmd '$target'" 2>/dev/null | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1)
            ;;
        directory)
            # Scan directory for files to analyze
            for file in "$target"/*; do
                [[ -f "$file" ]] || continue
                if flag=$(solver_osint "$file" "file" "$VERBOSE" 2>/dev/null); then
                    echo "$flag"
                    return 0
                fi
            done
            ;;
        *)
            flag=$(echo "$target" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1)
            ;;
    esac
    
    if [[ -n "$flag" ]]; then
        echo "$flag"
        return 0
    fi
    
    return 2
}

solver_generic() {
    local target="$1"
    local type="$2"
    
    log_verbose 1 "Generic solver: $target (type: $type)"
    
    local flag
    case "$type" in
        file)
            flag=$(grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' "$target" 2>/dev/null | head -1)
            ;;
        url)
            local cmd
            if command -v curl &>/dev/null; then
                cmd="curl -sL --max-time 10"
            else
                cmd="wget -q -O - --timeout=10"
            fi
            flag=$(eval "$cmd '$target'" 2>/dev/null | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1)
            ;;
        directory)
            flag=$(find "$target" -type f -exec grep -lE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' {} \; 2>/dev/null | head -1 | xargs grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' 2>/dev/null | head -1)
            ;;
        *)
            flag=$(echo "$target" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1)
            ;;
    esac
    
    if [[ -n "$flag" ]]; then
        echo "$flag"
        return 0
    fi
    
    return 2
}