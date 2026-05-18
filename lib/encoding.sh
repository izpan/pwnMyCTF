#!/usr/bin/env bash
# Encoding/decoding utilities for pwnMyCTF

set -euo pipefail

# Detection functions
is_base64() {
    local input="$1"
    if echo "$input" | grep -qE '^[A-Za-z0-9+/]+=*$' && [[ ${#input} -ge 4 ]]; then
        if decode_base64 "$input" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

is_hex() {
    local input="$1"
    if echo "$input" | grep -qE '^[0-9A-Fa-f]+$' && [[ $((${#input} % 2)) -eq 0 ]] && [[ ${#input} -ge 2 ]]; then
        if decode_hex "$input" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

is_rot13() {
    local input="$1"
    local decoded
    decoded=$(rot13 "$input")
    if [[ "$decoded" != "$input" ]]; then
        # Check if decoded looks like text
        local pattern="^[A-Za-z0-9 ,.!?'-]+$"
        if echo "$decoded" | grep -qE "$pattern"; then
            return 0
        fi
    fi
    return 1
}

is_caesar() {
    local input="$1"
    local shift
    for shift in {0..25}; do
        local decoded
        decoded=$(caesar_decode "$input" "$shift")
        if [[ "$decoded" != "$input" ]]; then
            # Check if decoded looks like text
            local pattern="^[A-Za-z0-9 ,.!?'-]+$"
            if echo "$decoded" | grep -qE "$pattern"; then
                return 0
            fi
        fi
    done
    return 1
}

# Decoding functions (from Phase 1)
decode_base64() {
    local input="$1"
    echo "$input" | base64 -d 2>/dev/null || return 1
}

encode_base64() {
    local input="$1"
    echo "$input" | base64 2>/dev/null || return 1
}

decode_hex() {
    local input="$1"
    echo "$input" | xxd -r -p 2>/dev/null || return 1
}

encode_hex() {
    local input="$1"
    echo -n "$input" | xxd -p 2>/dev/null || return 1
}

url_decode() {
    local input="$1"
    printf '%b' "${input//%/\\x}" 2>/dev/null || return 1
}

url_encode() {
    local input="$1"
    local result=""
    local i
    for ((i=0; i<${#input}; i++)); do
        local c="${input:$i:1}"
        case "$c" in
            [a-zA-Z0-9._~-])
                result+="$c"
                ;;
            *)
                result+=$(printf '%%%02X' "'$c")
                ;;
        esac
    done
    echo "$result"
}

rot13() {
    local input="$1"
    echo "$input" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
}

caesar_decode() {
    local input="$1"
    local shift="${2:-13}"
    local result=""
    local i
    for ((i=0; i<${#input}; i++)); do
        local c="${input:$i:1}"
        if [[ "$c" =~ [a-z] ]]; then
            local ord=$(printf '%d' "'$c")
            ord=$(( (ord - 97 + shift) % 26 + 97 ))
            result+=$(printf "\\$(printf '%03o' $ord)")
        elif [[ "$c" =~ [A-Z] ]]; then
            local ord=$(printf '%d' "'$c")
            ord=$(( (ord - 65 + shift) % 26 + 65 ))
            result+=$(printf "\\$(printf '%03o' $ord)")
        else
            result+="$c"
        fi
    done
    echo "$result"
}

# Auto detection and decoding
auto_decode() {
    local input="$1"
    local decoded
    
    # Check hex first (common in CTF)
    if is_hex "$input"; then
        decoded=$(decode_hex "$input")
        echo "hex:$decoded"
        return 0
    fi
    
    if is_base64 "$input"; then
        decoded=$(decode_base64 "$input")
        echo "base64:$decoded"
        return 0
    fi
    
    if echo "$input" | grep -q '%[0-9A-Fa-f][0-9A-Fa-f]'; then
        if decoded=$(url_decode "$input") && [[ "$decoded" != "$input" ]]; then
            echo "url:$decoded"
            return 0
        fi
    fi
    
    if is_rot13 "$input"; then
        decoded=$(rot13 "$input")
        echo "rot13:$decoded"
        return 0
    fi
    
    # Try Caesar shifts (0-25) but skip 0 and 13 (rot13) to avoid duplicates
    local shift
    for shift in {0..25}; do
        if [[ $shift -eq 0 || $shift -eq 13 ]]; then
            continue
        fi
        if decoded=$(caesar_decode "$input" "$shift"); then
            if [[ "$decoded" != "$input" ]]; then
                echo "caesar:$shift:$decoded"
                return 0
            fi
        fi
    done
    
    echo "$input"
    return 1
}