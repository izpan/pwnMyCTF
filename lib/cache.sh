#!/usr/bin/env bash
# Result caching for pwnMyCTF crypto solver

set -uo pipefail

CACHE_DIR="${HOME}/.pwnmyctf/cache"
CACHE_TTL="${CACHE_TTL:-3600}"

init_cache() {
    mkdir -p "$CACHE_DIR" 2>/dev/null || true
}

compute_hash() {
    echo -n "$1" | sha256sum | cut -d' ' -f1
}

cache_get() {
    local input="$1"
    init_cache
    
    local hash
    hash=$(compute_hash "$input")
    
    local cache_file="${CACHE_DIR}/${hash}.cache"
    
    if [[ -f "$cache_file" ]]; then
        local timestamp
        timestamp=$(stat -f "%m" "$cache_file" 2>/dev/null || stat -c "%Y" "$cache_file" 2>/dev/null)
        local now
        now=$(date +%s)
        local age=$((now - timestamp))
        
        if [[ $age -lt $CACHE_TTL ]]; then
            cat "$cache_file"
            return 0
        else
            rm -f "$cache_file"
        fi
    fi
    
    return 1
}

cache_set() {
    local input="$1"
    local result="$2"
    init_cache
    
    local hash
    hash=$(compute_hash "$input")
    
    local cache_file="${CACHE_DIR}/${hash}.cache"
    echo "$result" > "$cache_file"
}

cache_clear() {
    init_cache
    rm -f "${CACHE_DIR}"/*.cache 2>/dev/null || true
    echo "Cache cleared"
}

cache_stats() {
    init_cache
    local count
    count=$(ls -1 "${CACHE_DIR}"/*.cache 2>/dev/null | wc -l | tr -d ' ')
    local size
    size=$(du -sh "$CACHE_DIR" 2>/dev/null | cut -f1)
    echo "Cache: $count entries, $size"
}

export -f cache_get
export -f cache_set
export -f cache_clear
export -f cache_stats