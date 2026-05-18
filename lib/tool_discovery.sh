#!/bin/bash
# Tool discovery library for pwnMyCTF
# Provides enhanced tool discovery with PATH lookup, fallbacks, and version checking

set -uo pipefail

# Function: discover_tool
# Discovers a tool in PATH with optional alternative names
# Parameters:
#   $1 - tool name to discover
#   $2... - alternative names (optional)
# Returns: path to the tool if found, empty string otherwise
discover_tool() {
    local tool="$1"
    shift
    local alternatives=("${@:-}")
    
    # Check the primary tool name
    local path
    path=$(command -v "$tool" 2>/dev/null)
    if [ -n "$path" ] && [ -x "$path" ]; then
        echo "$path"
        return 0
    fi
    
    # Check alternative names
    for alt in "${alternatives[@]}"; do
        path=$(command -v "$alt" 2>/dev/null)
        if [ -n "$path" ] && [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    
    return 1
}

# Function: suggest_installation
# Suggests installation command for a missing tool based on OS
suggest_installation() {
    local tool="$1"
    local package="${2:-$1}"
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew >/dev/null 2>&1; then
            echo "To install $tool, run: brew install $package" >&2
        else
            echo "To install $tool, please use Homebrew: https://brew.sh" >&2
        fi
    elif command -v apt-get >/dev/null 2>&1; then
        echo "To install $tool, run: sudo apt-get install $package" >&2
    elif command -v yum >/dev/null 2>&1; then
        echo "To install $tool, run: sudo yum install $package" >&2
    else
        echo "To install $tool, please use your system's package manager" >&2
    fi
}

# Function: check_tool_version
# Checks if a tool meets a minimum version requirement
check_tool_version() {
    local tool_path="$1"
    local min_version="$2"
    local version_arg="${3:-"--version"}"
    
    if [ ! -x "$tool_path" ]; then
        return 1
    fi
    
    local version_string
    version_string=$("$tool_path" "$version_arg" 2>/dev/null | head -n1)
    
    if [ -z "$version_string" ]; then
        return 1
    fi
    
    local version_number
    version_number=$(echo "$version_string" | grep -oE '[0-9]+(\.[0-9]+)*' | head -n1)
    
    if [ -z "$version_number" ]; then
        return 1
    fi
    
    if printf '%s\n%s\n' "$min_version" "$version_number" | sort -V -C 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Function: get_tool_info
# Gets information about a discovered tool
get_tool_info() {
    local tool="$1"
    shift
    local alternatives=("$@")
    
    local path
    path=$(discover_tool "$tool" "${alternatives[@]}")
    
    if [ -z "$path" ]; then
        echo "{ \"found\": false, \"tool\": \"$tool\" }"
        return 1
    fi
    
    local version
    version=$("$path" --version 2>/dev/null | head -n1 | grep -oE '[0-9]+(\.[0-9]+)*' | head -n1 || echo "unknown")
    
    echo "{ \"found\": true, \"tool\": \"$tool\", \"path\": \"$path\", \"version\": \"$version\" }"
    return 0
}

export -f discover_tool
export -f suggest_installation
export -f check_tool_version
export -f get_tool_info