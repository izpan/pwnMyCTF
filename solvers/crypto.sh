#!/usr/bin/env bash
# Crypto solver for pwnMyCTF

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/encoding.sh" 2>/dev/null || true
source "${LIB_DIR}/openssl.sh" 2>/dev/null || true
source "${LIB_DIR}/hash.sh" 2>/dev/null || true
source "${LIB_DIR}/timeout.sh" 2>/dev/null || true
source "${LIB_DIR}/cache.sh" 2>/dev/null || true

YOLO_MAX_PARALLEL="${YOLO_MAX_PARALLEL:-3}"
YOLO_TIMEOUT="${YOLO_TIMEOUT:-30}"

solve_crypto_yolo() {
    local target="$1"
    local verbose="${2:-0}"
    
    local content
    if [[ -f "$target" ]]; then
        content=$(cat "$target")
    else
        content="$target"
    fi
    
    local pids=()
    local results=()
    local temp_files=()
    
    solver_encoding() {
        local c="$1"
        auto_decode "$c" 2>/dev/null | grep -oE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1
    }
    
    solver_hash() {
        local c="$1"
        if [[ "$c" =~ ^[a-fA-F0-9]{32,128}$ ]]; then
            crack_hash "$c" 2>/dev/null
        fi
    }
    
    solver_custom() {
        local c="$1"
        solve_custom_cipher "$c" 2>/dev/null
    }
    
    solver_openssl() {
        local c="$1"
        if echo "$c" | grep -qE '^[A-Za-z0-9+/=]+$'; then
            for pw in "password" "secret" "key" "ctf" "flag" "123456"; do
                local dec
                dec=$(openssl_decrypt "$c" "$pw" 2>/dev/null) || continue
                echo "$dec" | grep -oE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1 && return 0
            done
        fi
    }
    
    export -f solver_encoding
    export -f solver_hash
    export -f solver_custom
    export -f solver_openssl
    
    local solver_funcs=("solver_encoding" "solver_hash" "solver_custom" "solver_openssl")
    
    local i=0
    for solver in "${solver_funcs[@]}"; do
        if [[ $i -ge $YOLO_MAX_PARALLEL ]]; then break; fi
        
        local result_file
        result_file=$(mktemp)
        temp_files+=("$result_file")
        
        (
            local result
            result=$($solver "$content")
            echo "$result" > "$result_file"
        ) &
        pids+=($!)
        ((i++))
    done
    
    local flag=""
    for pid in "${pids[@]}"; do
        wait $pid 2>/dev/null
    done
    
    for tf in "${temp_files[@]}"; do
        local r
        r=$(cat "$tf" 2>/dev/null)
        if [[ -n "$r" ]]; then
            flag="$r"
            break
        fi
        rm -f "$tf"
    done
    
    if [[ -n "$flag" ]]; then
        echo "$flag"
        return 0
    fi
    
    return 1
}

# Main crypto solving function
solve_crypto() {
    local target="$1"
    local verbose="${2:-0}"
    local yolo="${3:-false}"
    
    log_verbose 2 "Starting crypto solver for: $target (YOLO: $yolo)"
    
    # Check cache first
    local content
    if [[ -f "$target" ]]; then
        content=$(cat "$target")
    else
        content="$target"
    fi
    
    local cached
    if cached=$(cache_get "$content" 2>/dev/null); then
        log_verbose 2 "Cache hit!"
        echo "$cached"
        return 0
    fi
    
    local flag=""
    
    # YOLO mode: run solvers in parallel
    if [[ "$yolo" == "true" ]]; then
        log_verbose 2 "Running in YOLO mode (parallel solvers)"
        if flag=$(solve_crypto_yolo "$target" "$verbose" 2>/dev/null); then
            cache_set "$content" "$flag"
            echo "$flag"
            return 0
        fi
    else
        # Sequential solving (original logic)
        if flag=$(solve_crypto_sequential "$target" "$verbose" 2>/dev/null); then
            cache_set "$content" "$flag"
            echo "$flag"
            return 0
        fi
    fi
    
    return 2
}

solve_crypto_sequential() {
    local target="$1"
    local verbose="${2:-0}"
    
    local content
    if [[ -f "$target" ]]; then
        content=$(cat "$target")
    else
        content="$target"
    fi
    
    local flag=""
    
    # Try encoding detection and decoding first (base64, hex, URL, ROT13, Caesar)
    local decoded
    if decoded=$(auto_decode "$content" 2>/dev/null); then
        log_verbose 2 "Detected encoding: $decoded"
        
        # Extract flag from decoded content
        if flag=$(echo "$decoded" | grep -oE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
            echo "$flag"
            return 0
        fi
        
        # If decoded content looks promising, try solving it further
        if [[ ${#decoded} -lt 1000 ]]; then
            # Try custom ciphers on decoded content
            if flag=$(solve_custom_cipher "$decoded" 2>/dev/null); then
                echo "$flag"
                return 0
            fi
        fi
    fi
    
    # Check for hash in content
    if [[ "$content" =~ ^[a-fA-F0-9]{32,128}$ ]]; then
        local hash_type
        hash_type=$(identify_hash "$content")
        log_verbose 2 "Detected hash type: $hash_type"
        
        # Try to crack hash
        if flag=$(crack_hash "$content" 2>/dev/null); then
            echo "$flag"
            return 0
        fi
    fi
    
    # Try custom ciphers on original content
    if flag=$(solve_custom_cipher "$content" 2>/dev/null); then
        echo "$flag"
        return 0
    fi
    
    # If content looks like it might be encrypted (non-printable chars), try OpenSSL
    if echo "$content" | grep -qE '^[A-Za-z0-9+/=]+$'; then
        # Try common passwords with OpenSSL
        if command -v openssl &>/dev/null; then
            for password in "password" "secret" "key" "ctf" "flag" "123456"; do
                local decrypted
                if decrypted=$(openssl_decrypt "$content" "$password" 2>/dev/null); then
                    if flag=$(echo "$decrypted" | grep -oE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                        echo "$flag"
                        return 0
                    fi
                fi
            done
        fi
    fi
    
    # Fallback: look for any flag in the content itself
    if flag=$(echo "$content" | grep -oE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
        echo "$flag"
        return 0
    fi
    
    return 2
}

export -f solve_crypto