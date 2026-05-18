#!/usr/bin/env bash
# XOR encryption/decryption utilities for pwnMyCTF

set -uo pipefail

xor_decrypt() {
    local ciphertext="$1"
    local key="$2"
    
    local result=""
    local key_len=${#key}
    local key_idx=0
    
    local i
    for ((i=0; i<${#ciphertext}; i++)); do
        local c="${ciphertext:$i:1}"
        local ord=$(printf '%d' "'$c")
        local key_byte=$(printf '%d' "'${key:$((key_idx % key_len)):1}")
        local plain_byte=$((ord ^ key_byte))
        result+=$(printf "\\$(printf '%03o' $plain_byte)")
        ((key_idx++))
    done
    
    echo "$result"
}

xor_brute_force() {
    local ciphertext="$1"
    local max_key_len="${2:-8}"
    local verbose="${3:-0}"
    
    log_verbose 2 "Starting XOR brute-force (max key length: $max_key_len)"
    
    local flag_pattern='flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}'
    
    local key_len
    for ((key_len=1; key_len<=max_key_len; key_len++)); do
        log_verbose 2 "Trying key length: $key_len"
        
        local charset="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        
        generate_keys() {
            local prefix="$1"
            local depth=$2
            if [[ $depth -eq 0 ]]; then
                echo "$prefix"
                return
            fi
            local char
            for char in a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9; do
                generate_keys "${prefix}${char}" $((depth - 1))
            done
        }
        
        local key
        while IFS= read -r key; do
            local decrypted
            decrypted=$(xor_decrypt "$ciphertext" "$key" 2>/dev/null)
            
            if echo "$decrypted" | grep -qE "$flag_pattern"; then
                echo "$decrypted" | grep -oE "$flag_pattern" | head -1
                return 0
            fi
        done < <(generate_keys "" $key_len)
    done
    
    return 1
}

xor_detect_key_length() {
    local ciphertext="$1"
    local max_len="${2:-8}"
    
    local i
    for ((i=2; i<=max_len; i++)); do
        local chunk1="${ciphertext:0:$i}"
        local chunk2="${ciphertext:$i:$i}"
        
        if [[ "$chunk1" == "$chunk2" ]]; then
            echo "$i"
            return 0
        fi
    done
    
    echo "1"
    return 1
}

export -f xor_decrypt
export -f xor_brute_force
export -f xor_detect_key_length