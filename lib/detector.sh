#!/usr/bin/env bash
# Category detection library for pwnMyCTF

set -uo pipefail

detect_category() {
    local target="$1"
    local category=""
    
    if [[ -f "$target" ]]; then
        category=$(detect_from_file "$target")
    elif [[ -d "$target" ]]; then
        category=$(detect_from_directory "$target")
    elif [[ "$target" =~ ^https?:// ]]; then
        category=$(detect_from_url "$target")
    else
        echo "unknown"
        return 1
    fi
    
    echo "${category:-unknown}"
}

detect_from_file() {
    local file="$1"
    local mime
    local category="unknown"
    
    if [[ ! -f "$file" ]]; then
        echo "unknown"
        return 1
    fi
    
    mime=$(file -b --mime-type "$file" 2>/dev/null || echo "unknown")
    
    case "$mime" in
        application/x-executable|application/x-sharedlib|application/x-mach-binary|application/x-elf)
            category="reverse"
            ;;
        application/pdf)
            category="forensics"
            ;;
        application/zip|application/x-tar|application/gzip)
            category="forensics"
            ;;
        image/png|image/jpeg|image/gif|image/bmp)
            category="forensics"
            ;;
        text/html)
            category="web"
            ;;
        application/json)
            category="web"
            ;;
        text/plain)
            category=$(detect_from_content "$(cat "$file" 2>/dev/null | head -100)")
            ;;
        *)
            if [[ "$mime" == *"image"* ]]; then
                category="forensics"
            elif [[ "$mime" == *"application"* ]]; then
                category="pwn"
            fi
            ;;
    esac
    
    echo "$category"
}

detect_from_directory() {
    local dir="$1"
    local category="unknown"
    local file_count=0
    
    for f in "$dir"/*; do
        [[ -f "$f" ]] || continue
        ((file_count++))
        if [[ $file_count -gt 10 ]]; then
            break
        fi
    done
    
    if [[ $file_count -eq 0 ]]; then
        echo "unknown"
        return
    fi
    
    local first_file
    first_file=$(find "$dir" -type f | head -1)
    if [[ -n "$first_file" ]]; then
        detect_from_file "$first_file"
    else
        echo "unknown"
    fi
}

detect_from_url() {
    local url="$1"
    local category="unknown"
    
    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        echo "unknown"
        return 1
    fi
    
    local response
    local content_type
    
    if command -v curl &>/dev/null; then
        content_type=$(curl -sI "$url" 2>/dev/null | grep -i "content-type" | head -1 | cut -d: -f2 | tr -d ' \r\n')
        response=$(curl -sL --max-time 10 "$url" 2>/dev/null | head -c 10000)
    else
        content_type=$(wget -q --server-response --timeout=10 -O - "$url" 2>/dev/null | grep -i "content-type" | head -1 | cut -d: -f2 | tr -d ' \r\n')
        response=$(wget -q -O - --timeout=10 "$url" 2>/dev/null | head -c 10000)
    fi
    
    if [[ "$content_type" == *"html"* ]]; then
        category="web"
    elif [[ "$content_type" == *"json"* ]]; then
        category="web"
    elif [[ "$content_type" == *"image"* ]]; then
        category="forensics"
    elif echo "$response" | grep -qi "<html\|<body\|<div\|<script"; then
        category="web"
    elif echo "$response" | grep -qE '^\s*\{.*\}\s*$'; then
        category="web"
    else
        category=$(detect_from_content "$response")
    fi
    
    echo "$category"
}

detect_from_content() {
    local content="$1"
    local category="unknown"
    
    if echo "$content" | grep -qE '^[A-Za-z0-9+/]+=*$' && [[ ${#content} -ge 4 ]]; then
        if echo "$content" | base64 -d >/dev/null 2>&1; then
            category="crypto"
        fi
    fi
    
    if [[ "$category" == "unknown" ]] && echo "$content" | grep -qE '^[0-9A-Fa-f]+$' && [[ $((${#content} % 2)) -eq 0 ]]; then
        category="crypto"
    fi
    
    if [[ "$category" == "unknown" ]] && echo "$content" | grep -q '%[0-9A-Fa-f][0-9A-Fa-f]'; then
        category="web"
    fi
    
    if [[ "$category" == "unknown" ]] && echo "$content" | grep -qi "select.*from\|union.*select\|or 1=1\|' or "; then
        category="web"
    fi
    
    if [[ "$category" == "unknown" ]] && echo "$content" | grep -qi "\$\(|cat \|ls \|whoami\|wget\|curl"; then
        category="web"
    fi
    
    if [[ "$category" == "unknown" ]] && echo "$content" | grep -q "PK\x03\x04"; then
        category="forensics"
    fi
    
    if [[ "$category" == "unknown" ]] && echo "$content" | grep -qE "MIME-version|Content-type:"; then
        category="forensics"
    fi
    
    echo "${category:-unknown}"
}

force_category() {
    local category="$1"
    local valid_categories="web|crypto|pwn|reverse|forensics|osint"
    
    if [[ -z "$category" ]]; then
        echo "Error: --force requires a category" >&2
        return 1
    fi
    
    if echo "$category" | grep -qE "^(${valid_categories})$"; then
        echo "$category"
        return 0
    else
        echo "Error: Invalid category '$category'. Valid: $valid_categories" >&2
        return 1
    fi
}

get_detection_confidence() {
    local target="$1"
    local category
    local confidence="low"
    
    if [[ -f "$target" ]]; then
        local mime
        mime=$(file -b --mime-type "$target" 2>/dev/null || echo "unknown")
        if [[ "$mime" != "unknown" ]]; then
            confidence="high"
        fi
    elif [[ "$target" =~ ^https?:// ]]; then
        confidence="medium"
    fi
    
    echo "$confidence"
}