#!/usr/bin/env bash
# OpenSSL wrapper for pwnMyCTF crypto operations

set -uo pipefail

# Check if openssl is available
openssl_check() {
    command -v openssl &>/dev/null
}

# Try to decrypt data with a given password
openssl_decrypt() {
    local input="$1"
    local password="$2"
    local algorithm="${3:-aes-256-cbc}"
    
    local result
    if result=$(echo "$input" | openssl "$algorithm" -d -pass pass:"$password" -base64 2>/dev/null); then
        echo "$result"
        return 0
    fi
    return 1
}

# Try multiple common passwords
openssl_brute_force() {
    local input="$1"
    local algorithm="${2:-aes-256-cbc}"
    local wordlist="${3:-/usr/share/wordlists/rockyou.txt}"
    
    if [[ ! -f "$wordlist" ]]; then
        # Fallback to small wordlist
        local passwords=("password" "123456" "admin" "test" "secret" "key" "ctf" "flag")
        for pass in "${passwords[@]}"; do
            if openssl_decrypt "$input" "$pass" "$algorithm" &>/dev/null; then
                echo "password:$pass"
                return 0
            fi
        done
        return 1
    fi
    
    while IFS= read -r password; do
        if openssl_decrypt "$input" "$password" "$algorithm" &>/dev/null; then
            echo "password:$password"
            return 0
        fi
    done < "$wordlist"
    
    return 1
}

# Decrypt AES with various key sizes
openssl_decrypt_aes() {
    local input="$1"
    local password="$2"
    
    for cipher in aes-256-cbc aes-128-cbc aes-192-cbc des-cbc des-ede-cbc; do
        local result
        if result=$(echo "$input" | openssl "$cipher" -d -pass pass:"$password" -base64 2>/dev/null); then
            echo "$result"
            return 0
        fi
    done
    return 1
}

# Decrypt with raw key (hex)
openssl_decrypt_hex_key() {
    local input="$1"
    local hex_key="$2"
    local algorithm="${3:-aes-256-cbc}"
    
    local result
    if result=$(echo "$input" | openssl "$algorithm" -d -K "$hex_key" -base64 2>/dev/null); then
        echo "$result"
        return 0
    fi
    return 1
}

# Try RSA decryption with private key
openssl_decrypt_rsa() {
    local input="$1"
    local private_key="$2"
    
    local result
    if result=$(echo "$input" | openssl rsautl -decrypt -inkey "$private_key" -keyform PEM 2>/dev/null); then
        echo "$result"
        return 0
    fi
    return 1
}

export -f openssl_check
export -f openssl_decrypt
export -f openssl_brute_force
export -f openssl_decrypt_aes
export -f openssl_decrypt_hex_key
export -f openssl_decrypt_rsa