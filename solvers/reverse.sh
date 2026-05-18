#!/usr/bin/env bash
# Reverse engineering solver for pwnMyCTF
# Implements binary format identification, string extraction, symbol analysis,
# disassembly, library dependency analysis, and function signature identification

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/flag_extractor.sh" 2>/dev/null || true
source "${LIB_DIR}/check_tools.sh" 2>/dev/null || true
source "${LIB_DIR}/timeout.sh" 2>/dev/null || true

# Flag patterns from flag_extractor.sh
FLAG_PATTERN='flag\{[^}]+\}'
FLAG_PATTERN_ALT='FLAG\{[^}]+\}'
FLAG_PATTERN_CTF='CTF\{[^}]+\}'

# Logging helper (for verbose mode)
log_verbose() {
    local level="$1"
    shift
    if [[ "${VERBOSE:-0}" -ge "$level" ]]; then
        echo "[VERBOSE] $*" >&2
    fi
}

# Helper: search for flag patterns in any input
search_flag_patterns() {
    local content="$1"
    local flag=""

    if flag=$(echo "$content" | grep -Eo "$FLAG_PATTERN" | head -1); then
        echo "$flag"
        return 0
    fi
    if flag=$(echo "$content" | grep -Eo "$FLAG_PATTERN_ALT" | head -1); then
        echo "$flag"
        return 0
    fi
    if flag=$(echo "$content" | grep -Eo "$FLAG_PATTERN_CTF" | head -1); then
        echo "$flag"
        return 0
    fi
    return 1
}

# Helper: search for flag in a file
search_flag_in_file() {
    local file="$1"
    local flag=""

    if [[ ! -f "$file" ]] || [[ ! -r "$file" ]]; then
        return 1
    fi

    if flag=$(grep -Eo "$FLAG_PATTERN" "$file" 2>/dev/null | head -1); then
        echo "$flag"
        return 0
    fi
    if flag=$(grep -Eo "$FLAG_PATTERN_ALT" "$file" 2>/dev/null | head -1); then
        echo "$flag"
        return 0
    fi
    if flag=$(grep -Eo "$FLAG_PATTERN_CTF" "$file" 2>/dev/null | head -1); then
        echo "$flag"
        return 0
    fi
    return 1
}

# REV-01: Binary format identification (ELF, PE, Mach-O)
reverse_identify() {
    local target="$1"
    local verbose="${2:-0}"

    log_verbose 2 "REV-01: Identifying binary format for: $target"

    # Check file exists
    if [[ ! -f "$target" ]]; then
        log_verbose 2 "Error: File not found: $target"
        return 1
    fi

    # Use file command for format detection
    local file_output
    file_output=$(file -b "$target" 2>/dev/null)
    log_verbose 2 "File command output: $file_output"

    # Detect format type
    local format=""
    if echo "$file_output" | grep -qi "ELF"; then
        format="ELF"
        log_verbose 2 "Detected: ELF binary"

        # Get ELF header info with readelf
        if command -v readelf &>/dev/null; then
            local elf_header
            elf_header=$(readelf -h "$target" 2>/dev/null)
            local entry_point
            entry_point=$(echo "$elf_header" | grep "Entry point" | awk '{print $3}')
            local machine
            machine=$(echo "$elf_header" | grep "Machine:" | cut -d: -f2-)

            log_verbose 2 "Entry point: $entry_point"
            log_verbose 2 "Machine: $machine"

            echo "ELF Binary"
            echo "  Entry point: $entry_point"
            echo "  Machine: $machine"
        fi

    elif echo "$file_output" | grep -qi "PE"; then
        format="PE"
        log_verbose 2 "Detected: PE (Windows) binary"
        echo "PE (Windows) Binary"

    elif echo "$file_output" | grep -qi "Mach-O"; then
        format="Mach-O"
        log_verbose 2 "Detected: Mach-O (macOS) binary"
        echo "Mach-O (macOS) Binary"

    else
        log_verbose 2 "Unknown binary format"
        echo "Unknown binary format: $file_output"
        return 1
    fi

    return 0
}

# REV-02: String extraction from binaries
reverse_strings() {
    local target="$1"
    local verbose="${2:-0}"

    log_verbose 2 "REV-02: Extracting strings from: $target"

    local flag=""

    # Check file exists
    if [[ ! -f "$target" ]]; then
        log_verbose 2 "Error: File not found: $target"
        return 1
    fi

    # Use strings command with minimum 4 character length
    if command -v strings &>/dev/null; then
        local strings_output
        strings_output=$(strings -n 4 "$target" 2>/dev/null)

        # Search for flag patterns in strings output
        if flag=$(echo "$strings_output" | grep -Eo "$FLAG_PATTERN" | head -1); then
            log_verbose 2 "Found flag in strings: $flag"
            echo "$flag"
            return 0
        fi
        if flag=$(echo "$strings_output" | grep -Eo "$FLAG_PATTERN_ALT" | head -1); then
            log_verbose 2 "Found flag in strings: $flag"
            echo "$flag"
            return 0
        fi
        if flag=$(echo "$strings_output" | grep -Eo "$FLAG_PATTERN_CTF" | head -1); then
            log_verbose 2 "Found flag in strings: $flag"
            echo "$flag"
            return 0
        fi
    fi

    # Also try grep -a for binary files (more thorough)
    if flag=$(grep -aoE "$FLAG_PATTERN" "$target" 2>/dev/null | head -1); then
        log_verbose 2 "Found flag with grep -a: $flag"
        echo "$flag"
        return 0
    fi
    if flag=$(grep -aoE "$FLAG_PATTERN_ALT" "$target" 2>/dev/null | head -1); then
        log_verbose 2 "Found flag with grep -a: $flag"
        echo "$flag"
        return 0
    fi
    if flag=$(grep -aoE "$FLAG_PATTERN_CTF" "$target" 2>/dev/null | head -1); then
        log_verbose 2 "Found flag with grep -a: $flag"
        echo "$flag"
        return 0
    fi

    log_verbose 2 "No flag found in strings"
    return 1
}

# REV-03: Symbol analysis (nm, readelf)
reverse_symbols() {
    local target="$1"
    local verbose="${2:-0}"

    log_verbose 2 "REV-03: Analyzing symbols in: $target"

    # Check file exists
    if [[ ! -f "$target" ]]; then
        log_verbose 2 "Error: File not found: $target"
        return 1
    fi

    local symbols_output=""

    # Use nm -g for exported symbols (global/extern)
    if command -v nm &>/dev/null; then
        log_verbose 2 "Running nm -g on: $target"

        # Try nm -g (defined external symbols)
        local nm_output
        nm_output=$(nm -g "$target" 2>/dev/null || true)

        if [[ -n "$nm_output" ]]; then
            log_verbose 2 "nm output available"
            symbols_output="$nm_output"

            # Filter and display function symbols (type T, t)
            local functions
            functions=$(echo "$nm_output" | grep -E "^\S+\s+[Tt]\s+" | awk '{print $3}' | sort -u)

            if [[ -n "$functions" ]]; then
                log_verbose 2 "Found function symbols:"
                echo "Functions (nm -g):"
                echo "$functions" | while read -r func; do
                    echo "  - $func"
                done
            fi
        fi
    fi

    # Use readelf -s for full symbol table
    if command -v readelf &>/dev/null; then
        log_verbose 2 "Running readelf -s on: $target"

        local readelf_output
        readelf_output=$(readelf -s "$target" 2>/dev/null || true)

        if [[ -n "$readelf_output" ]]; then
            # Get function symbols from readelf (FUNC type)
            local funcs
            funcs=$(echo "$readelf_output" | grep -E "FUNC" | awk '{print $8}' | sort -u | grep -v "^\$" | head -20)

            if [[ -n "$funcs" ]]; then
                log_verbose 2 "Found function symbols from readelf:"
                echo "Functions (readelf -s):"
                echo "$funcs" | while read -r func; do
                    echo "  - $func"
                done
            fi
        fi
    fi

    # Check if we found any symbols
    if [[ -z "$symbols_output" ]]; then
        log_verbose 2 "No symbols found (possibly stripped)"
        echo "No symbols found (binary may be stripped)"
    fi

    return 0
}

# REV-04: Disassembly (objdump - tiered output)
reverse_disassemble() {
    local target="$1"
    local verbose="${2:-${VERBOSE:-0}}"

    log_verbose 2 "REV-04: Disassembling: $target (verbose: $verbose)"

    # Check file exists
    if [[ ! -f "$target" ]]; then
        log_verbose 2 "Error: File not found: $target"
        return 1
    fi

    # Check for objdump
    if ! command -v objdump &>/dev/null; then
        log_verbose 2 "Error: objdump not available"
        return 2
    fi

    # Tiered output approach:
    # Essential mode (default): Show entry point + exported symbols
    # Full mode (VERBOSE >= 2): Disassemble all functions

    if [[ "$verbose" -ge 2 ]]; then
        log_verbose 2 "Full disassembly mode"
        local disasm_output
        disasm_output=$(objdump -d "$target" 2>/dev/null)

        # Search for flags in disassembly
        local flag=""
        if flag=$(echo "$disasm_output" | grep -Eo "$FLAG_PATTERN" | head -1); then
            log_verbose 2 "Found flag in disassembly: $flag"
            echo "$flag"
            return 0
        fi
        if flag=$(echo "$disasm_output" | grep -Eo "$FLAG_PATTERN_ALT" | head -1); then
            log_verbose 2 "Found flag in disassembly: $flag"
            echo "$flag"
            return 0
        fi
        if flag=$(echo "$disasm_output" | grep -Eo "$FLAG_PATTERN_CTF" | head -1); then
            log_verbose 2 "Found flag in disassembly: $flag"
            echo "$flag"
            return 0
        fi

        # Show essential functions from disassembly
        local functions
        functions=$(objdump -d "$target" 2>/dev/null | grep -E "^[0-9a-f]+ <.*>:" | head -20)

        if [[ -n "$functions" ]]; then
            echo "Disassembled functions (objdump -d):"
            echo "$functions" | while read -r line; do
                echo "  $line"
            done
        fi
    else
        log_verbose 2 "Essential disassembly mode"

        # Show entry point (main, _start)
        local entry_funcs
        entry_funcs=$(objdump -d "$target" 2>/dev/null | grep -E "^[0-9a-f]+ <(main|_start)>:" | head -5)

        if [[ -n "$entry_funcs" ]]; then
            echo "Entry point functions:"
            echo "$entry_funcs" | while read -r line; do
                echo "  $line"
            done
        fi

        # Show some exported functions
        local export_funcs
        export_funcs=$(objdump -d "$target" 2>/dev/null | grep -E "^[0-9a-f]+ <[a-zA-Z_][a-zA-Z0-9_]*>:" | head -10)

        if [[ -n "$export_funcs" ]]; then
            echo "Exported functions:"
            echo "$export_funcs" | while read -r line; do
                echo "  $line"
            done
        fi
    fi

    return 0
}

# REV-05: Shared library analysis (ldd)
reverse_dependencies() {
    local target="$1"
    local verbose="${2:-0}"

    log_verbose 2 "REV-05: Analyzing shared library dependencies: $target"

    # Check file exists
    if [[ ! -f "$target" ]]; then
        log_verbose 2 "Error: File not found: $target"
        return 1
    fi

    local deps=""

    # Try ldd first (works for ELF on Linux)
    if command -v ldd &>/dev/null; then
        log_verbose 2 "Running ldd on: $target"

        local ldd_output
        ldd_output=$(ldd "$target" 2>/dev/null || true)

        if [[ -n "$ldd_output" ]]; then
            log_verbose 2 "ldd output: $ldd_output"

            # Extract library names
            local libraries
            libraries=$(echo "$ldd_output" | awk '{print $1}' | grep -v "^$" | sort -u)

            if [[ -n "$libraries" ]]; then
                echo "Shared library dependencies (ldd):"
                echo "$libraries" | while read -r lib; do
                    echo "  - $lib"
                done
                deps="found"
            fi
        fi
    fi

    # Fallback: use readelf -d for ELF dependencies
    if [[ -z "$deps" ]] && command -v readelf &>/dev/null; then
        log_verbose 2 "Using readelf -d as fallback"

        local readelf_deps
        readelf_deps=$(readelf -d "$target" 2>/dev/null | grep "NEEDED" || true)

        if [[ -n "$readelf_deps" ]]; then
            local libraries
            libraries=$(echo "$readelf_deps" | awk '{print $5}' | tr -d '[]' | sort -u)

            echo "Shared library dependencies (readelf -d):"
            echo "$libraries" | while read -r lib; do
                echo "  - $lib"
            done
            deps="found"
        fi
    fi

    if [[ -z "$deps" ]]; then
        log_verbose 2 "No dependencies found or not an ELF binary"
        echo "No shared library dependencies found"
    fi

    return 0
}

# REV-06: Function signature identification (combined approach)
reverse_functions() {
    local target="$1"
    local verbose="${2:-0}"

    log_verbose 2 "REV-06: Identifying function signatures: $target"

    # Check file exists
    if [[ ! -f "$target" ]]; then
        log_verbose 2 "Error: File not found: $target"
        return 1
    fi

    # Combined approach: Primary = nm/readelf symbols, Fallback = heuristics

    local functions=""

    # Primary: Use nm -g for exported symbols
    if command -v nm &>/dev/null; then
        local nm_output
        nm_output=$(nm -g "$target" 2>/dev/null || true)

        if [[ -n "$nm_output" ]]; then
            # Get function names (type T or t)
            local nm_funcs
            nm_funcs=$(echo "$nm_output" | grep -E "^\S+\s+[Tt]\s+" | awk '{print $3}' | sort -u)

            if [[ -n "$nm_funcs" ]]; then
                log_verbose 2 "Identified functions via nm:"
                echo "Function signatures (nm -g):"
                echo "$nm_funcs" | while read -r func; do
                    # Try to classify the function
                    local func_type=""
                    case "$func" in
                        main) func_type="(entry point)" ;;
                        _start) func_type="(program start)" ;;
                        init) func_type="(initialization)" ;;
                        fini) func_type="(finalization)" ;;
                        *_init) func_type="(constructor)" ;;
                        *_fini) func_type="(destructor)" ;;
                        _init) func_type="(constructor)" ;;
                        _fini) func_type="(destructor)" ;;
                        *) func_type="" ;;
                    esac
                    echo "  - $func $func_type"
                done
                functions="found"
            fi
        fi
    fi

    # Use readelf for additional symbols
    if command -v readelf &>/dev/null; then
        local readelf_output
        readelf_output=$(readelf -s "$target" 2>/dev/null || true)

        if [[ -n "$readelf_output" ]]; then
            local readelf_funcs
            readelf_funcs=$(echo "$readelf_output" | grep -E "FUNC" | awk '{print $8}' | sort -u | grep -v "^\$" | head -30)

            if [[ -n "$readelf_funcs" ]]; then
                # Show additional functions not found by nm
                log_verbose 2 "Additional functions from readelf:"
                echo "Additional symbols (readelf -s):"
                echo "$readelf_funcs" | while read -r func; do
                    echo "  - $func"
                done
            fi
        fi
    fi

    # Fallback: Heuristic pattern matching on common prologues
    if [[ -z "$functions" ]] && command -v objdump &>/dev/null; then
        log_verbose 2 "Using heuristic approach (no symbols found)"

        # Look for common function prologues in disassembly
        local disasm
        disasm=$(objdump -d "$target" 2>/dev/null | head -500)

        # Extract function-like patterns (address <func_name>:)
        local patterns
        patterns=$(echo "$disasm" | grep -E "^[0-9a-f]+ <[a-zA-Z_][a-zA-Z0-9_]*>:" | awk -F'<' '{print $2}' | awk -F'>' '{print $1}' | head -20)

        if [[ -n "$patterns" ]]; then
            echo "Function patterns (heuristic):"
            echo "$patterns" | while read -r func; do
                echo "  - $func (inferred)"
            done
            functions="found"
        fi
    fi

    if [[ -z "$functions" ]]; then
        log_verbose 2 "Could not identify any functions"
        echo "No function signatures identified"
    fi

    return 0
}

# Main entry point: solve_reverse
solve_reverse() {
    local target="$1"
    local verbose="${2:-0}"

    # Set global VERBOSE for log_verbose function
    export VERBOSE="$verbose"

    log_verbose 1 "Starting reverse engineering solver for: $target"

    local flag=""
    local result=""

    # Validate input
    if [[ ! -f "$target" ]]; then
        log_verbose 1 "Error: Target not found: $target"
        return 2
    fi

    # REV-01: Binary format identification
    log_verbose 1 "Step 1: Binary format identification"
    local binary_format
    binary_format=$(reverse_identify "$target" "$verbose")
    log_verbose 1 "Identified: $binary_format"

    # Check if it's a recognized binary format
    if [[ -z "$binary_format" ]] || [[ "$binary_format" == "Unknown"* ]]; then
        log_verbose 1 "Not a recognized binary format"
        return 2
    fi

    # REV-02: String extraction
    log_verbose 1 "Step 2: String extraction"
    if result=$(reverse_strings "$target" "$verbose"); then
        echo "$result"
        return 0
    fi

    # REV-03: Symbol analysis
    log_verbose 1 "Step 3: Symbol analysis"
    reverse_symbols "$target" "$verbose"

    # REV-04: Disassembly
    log_verbose 1 "Step 4: Disassembly"
    reverse_disassemble "$target" "$verbose"

    # REV-05: Dependency analysis
    log_verbose 1 "Step 5: Shared library analysis"
    reverse_dependencies "$target" "$verbose"

    # REV-06: Function signature identification
    log_verbose 1 "Step 6: Function signature identification"
    reverse_functions "$target" "$verbose"

    log_verbose 1 "No flag found in reverse engineering analysis"
    return 2
}

# Export functions for use by lib/solver.sh
export -f solve_reverse
export -f reverse_identify
export -f reverse_strings
export -f reverse_symbols
export -f reverse_disassemble
export -f reverse_dependencies
export -f reverse_functions
export -f log_verbose
export -f search_flag_patterns
export -f search_flag_in_file