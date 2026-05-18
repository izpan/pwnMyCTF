#!/usr/bin/env bash
# Flag extraction library for pwnMyCTF

set -euo pipefail

FLAG_PATTERN='flag\{[^}]+\}'
FLAG_PATTERN_ALT='FLAG\{[^}]+\}'
FLAG_PATTERN_CTF='CTF\{[^}]+\}'

extract_flag_from_file() {
    local file="$1"
    local flag=""

    if [[ ! -f "$file" ]]; then
        return 2
    fi

    if flag=$(grep -aEo "$FLAG_PATTERN" "$file" 2>/dev/null | head -1); then
        echo "$flag"
        return 0
    fi

    if flag=$(grep -aEo "$FLAG_PATTERN_ALT" "$file" 2>/dev/null | head -1); then
        echo "$flag"
        return 0
    fi

    if flag=$(grep -aEo "$FLAG_PATTERN_CTF" "$file" 2>/dev/null | head -1); then
        echo "$flag"
        return 0
    fi

    return 2
}

extract_flag_from_string() {
    local text="$1"
    local flag=""

    if flag=$(echo "$text" | grep -Eo "$FLAG_PATTERN" | head -1); then
        echo "$flag"
        return 0
    fi

    if flag=$(echo "$text" | grep -Eo "$FLAG_PATTERN_ALT" | head -1); then
        echo "$flag"
        return 0
    fi

    if flag=$(echo "$text" | grep -Eo "$FLAG_PATTERN_CTF" | head -1); then
        echo "$flag"
        return 0
    fi

    return 2
}

extract_flag_from_stdin() {
    extract_flag_from_string "$(cat)"
}

extract_flag_json() {
    local flag="$1"
    local success="${2:-true}"
    local error="${3:-}"
    
    if [[ "$success" == "true" ]]; then
        printf '{"success":true,"flag":"%s"}\n' "$flag"
    else
        printf '{"success":false,"error":"%s"}\n' "$error"
    fi
}

find_flags_in_directory() {
    local dir="$1"
    local found=0
    
    for file in $(find "$dir" -type f 2>/dev/null); do
        if [[ -r "$file" ]]; then
            if extract_flag_from_file "$file" >/dev/null 2>&1; then
                extract_flag_from_file "$file"
                found=1
                break
            fi
        fi
    done
    
    return $((found == 0 ? 2 : 0))
}