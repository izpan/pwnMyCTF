#!/usr/bin/env bash
# Hash identification and cracking for pwnMyCTF

set -uo pipefail

# Identify hash type by length and character set
identify_hash() {
    local hash="$1"
    local len=${#hash}
    
    case "$len" in
        32)
            echo "md5"
            return 0
            ;;
        40)
            echo "sha1"
            return 0
            ;;
        56)
            echo "sha224"
            return 0
            ;;
        64)
            echo "sha256"
            return 0
            ;;
        96)
            echo "sha384"
            return 0
            ;;
        128)
            echo "sha512"
            return 0
            ;;
    esac
    
    return 1
}

# Try to crack hash with wordlist
crack_hash() {
    local hash="$1"
    local wordlist="${2:-/usr/share/wordlists/rockyou.txt}"
    
    local hash_type
    hash_type=$(identify_hash "$hash")
    
    if [[ -z "$hash_type" ]]; then
        return 1
    fi
    
    # Check if hashcat or john is available
    if command -v hashcat &>/dev/null; then
        local result
        if result=$(hashcat -m 0 --potfile-path /dev/null "$hash" "$wordlist" 2>/dev/null | grep -v "Hashmode" | head -1); then
            echo "$result"
            return 0
        fi
    fi
    
    if command -v john &>/dev/null; then
        echo "$hash" > /tmp/hash_to_crack.txt
        local result
        if result=$(john /tmp/hash_to_crack.txt --wordlist="$wordlist" 2>/dev/null | grep -v "Loaded" | head -1); then
            rm -f /tmp/hash_to_crack.txt
            echo "$result"
            return 0
        fi
        rm -f /tmp/hash_to_crack.txt
    fi
    
    # Fallback: simple dictionary attack with common tools
    if [[ "$hash_type" == "md5" ]]; then
        while IFS= read -r word; do
            local word_hash
            word_hash=$(echo -n "$word" | md5sum | cut -d' ' -f1)
            if [[ "$word_hash" == "$hash" ]]; then
                echo "password:$word"
                return 0
            fi
        done < "$wordlist" 2>/dev/null
    fi
    
    return 1
}

# Simple hash verification
verify_hash() {
    local password="$1"
    local hash="$2"
    local hash_type="${3:-md5}"
    
    local computed
    case "$hash_type" in
        md5)
            computed=$(echo -n "$password" | md5sum | cut -d' ' -f1)
            ;;
        sha1)
            computed=$(echo -n "$password" | sha1sum | cut -d' ' -f1)
            ;;
        sha256)
            computed=$(echo -n "$password" | sha256sum | cut -d' ' -f1)
            ;;
        *)
            return 1
            ;;
    esac
    
    if [[ "$computed" == "$hash" ]]; then
        echo "password:$password"
        return 0
    fi
    return 1
}

export -f identify_hash
export -f crack_hash
export -f verify_hash