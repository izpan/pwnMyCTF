#!/usr/bin/env bash
# Custom cipher implementation for pwnMyCTF

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/encoding.sh" 2>/dev/null || true

# Vigenere cipher decryption
vigenere_decrypt() {
    local ciphertext="$1"
    local key="$2"
    
    local result=""
    local key_len=${#key}
    local key_index=0
    
    local i
    for ((i=0; i<${#ciphertext}; i++)); do
        local c="${ciphertext:$i:1}"
        
        if [[ "$c" =~ [a-z] ]]; then
            local cipher_val=$(printf '%d' "'$c")
            local key_val=$(printf '%d' "'${key:$((key_index % key_len)):1}")
            local plain_val=$(( (cipher_val - key_val + 26) % 26 + 97 ))
            result+=$(printf "\\$(printf '%03o' $plain_val)")
        elif [[ "$c" =~ [A-Z] ]]; then
            local cipher_val=$(printf '%d' "'$c")
            local key_val=$(printf '%d' "'${key:$((key_index % key_len)):1}")
            local plain_val=$(( (cipher_val - key_val + 26) % 26 + 65 ))
            result+=$(printf "\\$(printf '%03o' $plain_val)")
            ((key_index++))
        else
            result+="$c"
        fi
        
        if [[ "$c" =~ [a-zA-Z] ]]; then
            ((key_index++))
        fi
    done
    
    echo "$result"
}

# Simple substitution cipher decryption using frequency analysis
substitution_decrypt() {
    local ciphertext="$1"
    
    # Common English letters frequency: E T A O I N S H R D L U
    # Try simple substitution with most common mappings
    
    # For CTF challenges, often the substitution is simple
    # Try ROT variations first
    local i
    for ((i=1; i<26; i++)); do
        local decoded
        decoded=$(caesar_decode "$ciphertext" "$i")
        
        # Check if decoded text looks like English
        local word_count
        word_count=$(echo "$decoded" | grep -oE '\b(the|and|is|to|in|of|for|with|that|this)\b' | wc -l)
        
        if [[ $word_count -ge 2 ]]; then
            echo "shift:$i:$decoded"
            return 0
        fi
    done
    
    return 1
}

# XOR decryption
xor_decrypt() {
    local ciphertext="$1"
    local key="$2"
    
    # Convert hex ciphertext to binary if needed
    local data
    if [[ "$ciphertext" =~ ^[0-9A-Fa-f]+$ ]]; then
        data=$(echo "$ciphertext" | xxd -r -p)
    else
        data="$ciphertext"
    fi
    
    local result=""
    local key_len=${#key}
    local key_index=0
    
    local i
    for ((i=0; i<${#data}; i++)); do
        local byte=$(printf '%d' "'${data:$i:1}")
        local key_byte=$(printf '%d' "'${key:$((key_index % key_len)):1}")
        local plain_byte=$((byte ^ key_byte))
        result+=$(printf "\\$(printf '%03o' $plain_byte)")
        ((key_index++))
    done
    
    echo "$result"
}

# Brute force XOR with short keys
xor_brute_force() {
    local ciphertext="$1"
    local max_key_length="${2:-8}"
    
    # Try key lengths from 1 to max_key_length
    local key_length
    for ((key_length=1; key_length<=max_key_length; key_length++)); do
        # Try common printable characters for key
        local key_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        
        # Generate all combinations of key_length (simplified - just try common keys)
        local key
        for key in "a" "b" "x" "0" "1" "key" "ctf" "flag"; do
            if [[ ${#key} -eq $key_length ]]; then
                local decoded
                decoded=$(xor_decrypt "$ciphertext" "$key")
                
                # Check if decoded looks like text
                if echo "$decoded" | grep -qE '^[A-Za-z0-9 ,.!?]+$'; then
                    echo "key:$key:decoded"
                    return 0
                fi
            fi
        done
    done
    
    return 1
}

# Auto-detect and solve custom cipher
solve_custom_cipher() {
    local input="$1"
    local result=""
    
    # Try Vigenere with common keys
    local key
    for key in "key" "secret" "ctf" "flag" "password" "crypto"; do
        if result=$(vigenere_decrypt "$input" "$key"); then
            if echo "$result" | grep -qE 'flag|CTF'; then
                echo "vigenere:$key:$result"
                return 0
            fi
        fi
    done
    
    # Try substitution
    if result=$(substitution_decrypt "$input"); then
        echo "$result"
        return 0
    fi
    
    # Try XOR
    if result=$(xor_brute_force "$input" 4); then
        echo "$result"
        return 0
    fi
    
    return 1
}

export -f vigenere_decrypt
export -f substitution_decrypt
export -f xor_decrypt
export -f xor_brute_force
export -f solve_custom_cipher