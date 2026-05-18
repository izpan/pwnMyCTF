#!/usr/bin/env bash
# Tool availability checking library for pwnMyCTF

set -euo pipefail

declare -a REQUIRED_TOOLS=()
declare -a OPTIONAL_TOOLS=()

init_tools() {
    REQUIRED_TOOLS=(
        "file"
        "strings"
    )
    
    OPTIONAL_TOOLS=(
        "curl"
        "wget"
        "openssl"
        "xxd"
        "objdump"
        "nc"
        "gdb"
        "nm"
        "readelf"
        "jq"
    )
}

check_tool() {
    local tool="$1"
    if command -v "$tool" &>/dev/null; then
        return 0
    fi
    return 1
}

check_required_tool() {
    local tool="$1"
    local capability="${2:-Unknown capability}"
    
    if ! check_tool "$tool"; then
        echo "Error: required tool '$tool' not found — $capability" >&2
        echo "Install it with: brew install $tool (macOS) or apt-get install $tool (Linux)" >&2
        return 1
    fi
    return 0
}

check_optional_tool() {
    local tool="$1"
    local capability="${2:-Unknown capability}"
    
    if ! check_tool "$tool"; then
        echo "Note: optional tool '$tool' not found — $capability disabled" >&2
        return 1
    fi
    return 0
}

check_all_required() {
    init_tools
    
    local failed=0
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! check_required_tool "$tool" "required for basic operations"; then
            ((failed++))
        fi
    done
    
    if [[ "$failed" -gt 0 ]]; then
        return 1
    fi
    return 0
}

check_all_optional() {
    init_tools
    
    local missing=0
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if ! check_optional_tool "$tool"; then
            ((missing++))
        fi
    done
}

get_tool_path() {
    local tool="$1"
    command -v "$tool" 2>/dev/null || echo ""
}

show_tool_status() {
    init_tools
    
    echo "=== Tool Status ==="
    echo "Required tools:"
    for tool in "${REQUIRED_TOOLS[@]}"; do
        local path
        path=$(get_tool_path "$tool")
        if [[ -n "$path" ]]; then
            echo "  ✓ $tool: $path"
        else
            echo "  ✗ $tool: NOT FOUND"
        fi
    done
    
    echo ""
    echo "Optional tools:"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        local path
        path=$(get_tool_path "$tool")
        if [[ -n "$path" ]]; then
            echo "  ✓ $tool: $path"
        else
            echo "  ○ $tool: not installed"
        fi
    done
}