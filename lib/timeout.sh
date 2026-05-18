#!/usr/bin/env bash
# Timeout handling library for pwnMyCTF

set -euo pipefail

DEFAULT_TIMEOUT_WEB=45
DEFAULT_TIMEOUT_PWN=20
DEFAULT_TIMEOUT_CRYPTO=0
DEFAULT_TIMEOUT_GENERIC=30

run_with_timeout() {
    local timeout_sec="${1:-}"
    shift
    
    if [[ -z "$timeout_sec" ]] || [[ "$timeout_sec" == "0" ]]; then
        "$@"
        return $?
    fi
    
    if command -v timeout &>/dev/null; then
        timeout --signal=SIGTERM "$timeout_sec" "$@"
        local exit_code=$?
        
        if [[ $exit_code -eq 124 ]]; then
            timeout --signal=SIGKILL 5s sleep 1 2>/dev/null || true
            echo "Error: command timed out after ${timeout_sec}s" >&2
            return 124
        elif [[ $exit_code -eq 137 ]]; then
            echo "Error: command killed (timeout)" >&2
            return 137
        fi
        
        return $exit_code
    fi
    
    "$@"
    return $?
}

run_with_timeout_category() {
    local category="${1:-generic}"
    shift
    
    local timeout_val
    case "$category" in
        web)
            timeout_val="${TIMEOUT_WEB:-$DEFAULT_TIMEOUT_WEB}"
            ;;
        pwn)
            timeout_val="${TIMEOUT_PWN:-$DEFAULT_TIMEOUT_PWN}"
            ;;
        crypto)
            timeout_val="${TIMEOUT_CRYPTO:-$DEFAULT_TIMEOUT_CRYPTO}"
            ;;
        *)
            timeout_val="${TIMEOUT_GENERIC:-$DEFAULT_TIMEOUT_GENERIC}"
            ;;
    esac
    
    run_with_timeout "$timeout_val" "$@"
}

parse_timeout_arg() {
    local arg="$1"
    
    if [[ "$arg" =~ ^[0-9]+$ ]]; then
        echo "$arg"
        return 0
    fi
    
    echo "$DEFAULT_TIMEOUT_GENERIC"
    return 1
}