#!/usr/bin/env bash
# pwnMyCTF - Autonomous CTF Challenge Solver
# Pure bash implementation

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"

log_verbose() {
    local level="$1"
    shift
    local msg="$*"
    if [[ "$VERBOSE" -ge "$level" ]]; then
        echo "debug: $msg" >&2
    fi
}

source "${LIB_DIR}/flag_extractor.sh" 2>/dev/null || true
source "${LIB_DIR}/check_tools.sh" 2>/dev/null || true
source "${LIB_DIR}/timeout.sh" 2>/dev/null || true
source "${LIB_DIR}/encoding.sh" 2>/dev/null || true
source "${LIB_DIR}/detector.sh" 2>/dev/null || true
source "${LIB_DIR}/solver.sh" 2>/dev/null || true
source "${LIB_DIR}/retry.sh" 2>/dev/null || true
source "${LIB_DIR}/parallel.sh" 2>/dev/null || true
source "${LIB_DIR}/tool_discovery.sh" 2>/dev/null || true

VERSION="0.1.0"
VERBOSE=0
QUIET=false
JSON_OUTPUT=false
TIMEOUT_OVERRIDE=0
FORCE_CATEGORY=""
YOLO_MODE=false
RETRY_COUNT=0
PARALLEL_MODE=false
TOOL_DISCOVERY_ENHANCED=false

VALID_CATEGORIES="web|crypto|pwn|reverse|forensics|osint"

usage() {
    cat <<EOF
pwnMyCTF - Autonomous CTF Challenge Solver

Usage: pwnmyctf [global-options] <command> [command-options] [arguments]

Global Options:
     -v, --verbose       Increase verbosity (stackable: -vvv)
     -q, --quiet         Suppress non-essential output
     -j, --json          JSON output format
     -t, --timeout N     Timeout in seconds (0 = no timeout)
     --force CATEGORY    Force category (web|crypto|pwn|reverse|forensics|osint)
     --yolo              YOLO mode - parallel execution, skip checks
     --retries N         Number of retry attempts for failed operations (default: 0)
     --parallel          Enable parallel execution for solver approaches
     --tool-discovery    Use enhanced tool discovery with PATH-based lookup
     --clear-cache       Clear the crypto solver result cache
     -h, --help          Show this help message
     --version           Show version

Commands:
    solve <target>      Solve a CTF challenge (file, directory, or URL)
    analyze <target>    Analyze a challenge without solving
    decode <data>      Decode encoded data (base64, hex, url, rot13)
    decode -e <enc> -i <data>  Decode with explicit encoding type
    info                Show tool version and environment info

Examples:
    pwnmyctf solve /path/to/binary
    pwnmyctf solve ./challenge/
    pwnmyctf solve https://ctf.example.com/challenges/1
    pwnmyctf -v solve /path/to/file
    pwnmyctf decode aGVsbG8=

EOF
}

version() {
    echo "pwnMyCTF version $VERSION"
    echo ""
    echo "Dependencies:"
    init_tools 2>/dev/null || true
    show_tool_status 2>/dev/null || true
}

log_status() {
    if [[ "$QUIET" == "false" ]]; then
        echo "$1" >&2
    fi
}

detect_input_type() {
    local target="$1"
    
    if [[ -f "$target" ]]; then
        echo "file"
    elif [[ -d "$target" ]]; then
        echo "directory"
    elif [[ "$target" =~ ^https?:// ]]; then
        echo "url"
    else
        echo "unknown"
    fi
}

solve_file() {
    local file="$1"
    local category="$2"
    local type="$3"
    
    log_verbose 1 "Processing file: $file"
    
    if declare -f solve_challenge > /dev/null 2>&1; then
        if solve_challenge "$file" "$category" "$type"; then
            return 0
        fi
    fi
    
    local flag
    if flag=$(extract_flag_from_file "$file" 2>/dev/null); then
        log_verbose 2 "Flag found: $flag"
        if [[ "$JSON_OUTPUT" == "true" ]]; then
            extract_flag_json "$flag" "true"
        else
            echo "$flag"
        fi
        return 0
    fi
    
    log_verbose 1 "No flag found in file"
    return 2
}

solve_directory() {
    local dir="$1"
    local category="$2"
    local type="$3"
    
    log_verbose 1 "Processing directory: $dir"
    
    if declare -f solve_challenge > /dev/null 2>&1; then
        if solve_challenge "$dir" "$category" "$type"; then
            return 0
        fi
    fi
    
    local flag
    if flag=$(find_flags_in_directory "$dir" 2>/dev/null); then
        log_verbose 2 "Flag found: $flag"
        if [[ "$JSON_OUTPUT" == "true" ]]; then
            extract_flag_json "$flag" "true"
        else
            echo "$flag"
        fi
        return 0
    fi
    
    log_verbose 1 "No flag found in directory"
    return 2
}

solve_url() {
    local url="$1"
    local category="$2"
    local type="$3"
    
    log_verbose 1 "Processing URL: $url"
    
    if declare -f solve_challenge > /dev/null 2>&1; then
        if solve_challenge "$url" "$category" "$type"; then
            return 0
        fi
    fi
    
    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        echo "Error: curl or wget required for URL handling" >&2
        return 1
    fi
    
    local response
    local cmd
    if command -v curl &>/dev/null; then
        cmd="curl -sL --max-time 30 '$url'"
    else
        cmd="wget -q -O - --timeout=30 '$url'"
    fi
    
    response=$(eval "$cmd" 2>/dev/null) || {
        echo "Error: failed to fetch URL" >&2
        return 1
    }
    
    local flag
    if flag=$(echo "$response" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
        log_verbose 2 "Flag found: $flag"
        if [[ "$JSON_OUTPUT" == "true" ]]; then
            extract_flag_json "$flag" "true"
        else
            echo "$flag"
        fi
        return 0
    fi
    
    log_verbose 1 "No flag found in URL response"
    return 2
}

cmd_solve() {
    local target="${1:-}"
    
    if [[ -z "$target" ]]; then
        echo "Error: target required" >&2
        echo "Usage: pwnmyctf solve <file|directory|url>" >&2
        return 1
    fi
    
    local type
    type=$(detect_input_type "$target")
    
    log_verbose 1 "Input type: $type"
    
    local category="$FORCE_CATEGORY"
    local confidence="low"
    
    if [[ -z "$category" ]]; then
        log_verbose 1 "Auto-detecting category..."
        if category=$(detect_category "$target" 2>/dev/null); then
            confidence=$(get_detection_confidence "$target")
            log_verbose 1 "Detected category: $category (confidence: $confidence)"
        else
            category="unknown"
            log_verbose 1 "Detection failed, using unknown"
        fi
    else
        log_verbose 1 "Using forced category: $category"
        confidence="forced"
    fi
    
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "{\"target\":\"$target\",\"type\":\"$type\",\"category\":\"$category\",\"confidence\":\"$confidence\"}"
    else
        log_status "Target: $target"
        log_status "Type: $type"
        log_status "Category: $category (${confidence})"
    fi
    
    case "$type" in
        file)
            solve_file "$target" "$category" "$type"
            return $?
            ;;
        directory)
            solve_directory "$target" "$category" "$type"
            return $?
            ;;
        url)
            solve_url "$target" "$category" "$type"
            return $?
            ;;
        *)
            echo "Error: cannot determine input type: $target" >&2
            return 1
            ;;
    esac
}

cmd_analyze() {
    local target="${1:-}"
    
    if [[ -z "$target" ]]; then
        echo "Error: target required" >&2
        echo "Usage: pwnmyctf analyze <file|directory>" >&2
        return 1
    fi
    
    local type
    type=$(detect_input_type "$target")
    
    echo "=== Analysis ==="
    echo "Target: $target"
    echo "Type: $type"
    
    case "$type" in
        file)
            local size
            size=$(stat -f%z "$target" 2>/dev/null || stat -c%s "$target" 2>/dev/null || echo 'unknown')
            echo "Size: $size"
            echo "File type: $(file "$target" | cut -d: -f2)"
            ;;
        directory)
            echo "File count: $(find "$target" -type f 2>/dev/null | wc -l)"
            ;;
        url)
            echo "Note: Full analysis requires curl/wget"
            ;;
    esac
}

cmd_decode() {
    local encoding=""
    local data=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -e|--encoding)
                encoding="$2"
                shift 2
                ;;
            -i|--input)
                data="$2"
                shift 2
                ;;
            -*)
                echo "Unknown option: $1" >&2
                echo "Usage: pwnmyctf decode [-e encoding] [-i data] <data>" >&2
                return 1
                ;;
            *)
                if [[ -z "$data" ]]; then
                    data="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$data" ]]; then
        echo "Error: data required" >&2
        echo "Usage: pwnmyctf decode [-e encoding] [-i data] <data>" >&2
        return 1
    fi
    
    if [[ -n "$encoding" ]]; then
        case "$encoding" in
            base64)
                echo "$data" | base64 -d 2>/dev/null || { echo "Error: invalid base64 input" >&2; return 1; }
                echo
                ;;
            hex)
                echo "$data" | xxd -r -p 2>/dev/null || { echo "Error: invalid hex input" >&2; return 1; }
                echo
                ;;
            url)
                python3 -c "import urllib.parse, sys; print(urllib.parse.unquote(sys.argv[1]))" "$data" 2>/dev/null || { echo "Error: invalid URL-encoded input" >&2; return 1; }
                ;;
            rot13)
                echo "$data" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
                ;;
            *)
                echo "Error: unknown encoding '$encoding'. Supported: base64, hex, url, rot13" >&2
                return 1
                ;;
        esac
    else
        auto_decode "$data"
    fi
}

parse_options() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)
                VERBOSE=$((VERBOSE + 1))
                shift
                ;;
            -vv)
                VERBOSE=2
                shift
                ;;
            -vvv)
                VERBOSE=3
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -j|--json)
                JSON_OUTPUT=true
                shift
                ;;
            -t|--timeout)
                TIMEOUT_OVERRIDE="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --version)
                version
                exit 0
                ;;
            --force)
                local validated
                if validated=$(force_category "$2" 2>&1); then
                    FORCE_CATEGORY="$validated"
                else
                    echo "$validated" >&2
                    exit 1
                fi
                shift 2
                ;;
            --retries)
                RETRY_COUNT="$2"
                shift 2
                ;;
            --parallel)
                PARALLEL_MODE=true
                shift
                ;;
            --tool-discovery)
                TOOL_DISCOVERY_ENHANCED=true
                shift
                ;;
            --yolo)
                YOLO_MODE=true
                shift
                ;;
            -*)
                echo "Unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done
    
    echo "$@"
}

main() {
    local remaining_args=()
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)
                VERBOSE=$((VERBOSE + 1))
                shift
                ;;
            -vv)
                VERBOSE=2
                shift
                ;;
            -vvv)
                VERBOSE=3
                shift
                ;;
            -q|--quiet)
                QUIET=true
                shift
                ;;
            -j|--json)
                JSON_OUTPUT=true
                shift
                ;;
            -t|--timeout)
                TIMEOUT_OVERRIDE="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --version)
                version
                exit 0
                ;;
            --force)
                local validated
                if validated=$(force_category "$2" 2>&1); then
                    FORCE_CATEGORY="$validated"
                else
                    echo "$validated" >&2
                    exit 1
                fi
                shift 2
                ;;
            --retries)
                RETRY_COUNT="$2"
                shift 2
                ;;
            --parallel)
                PARALLEL_MODE=true
                shift
                ;;
            --tool-discovery)
                TOOL_DISCOVERY_ENHANCED=true
                shift
                ;;
            --yolo)
                YOLO_MODE=true
                shift
                ;;
            --clear-cache)
                source lib/cache.sh 2>/dev/null && cache_clear
                exit 0
                ;;
            -e|--encoding|-i|--input)
                remaining_args+=("$1")
                if [[ $# -gt 1 ]]; then
                    remaining_args+=("$2")
                fi
                shift $(( $# >= 2 ? 2 : 1 ))
                ;;
            -*)
                echo "Unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
            *)
                remaining_args+=("$1")
                shift
                ;;
        esac
    done
    
    if [[ ${#remaining_args[@]} -gt 0 ]]; then
        set -- "${remaining_args[@]}"
    else
        set --
    fi
    
    if [[ $# -lt 1 ]]; then
        usage
        exit 1
    fi
    
    local command="${1:-}"
    shift || true
    
    case "$command" in
        solve)
            cmd_solve "$@"
            exit $?
            ;;
        analyze)
            cmd_analyze "$@"
            exit $?
            ;;
        decode)
            cmd_decode "$@"
            exit $?
            ;;
        info)
            version
            exit 0
            ;;
        help)
            usage
            exit 0
            ;;
        "")
            usage
            exit 1
            ;;
        *)
            echo "Unknown command: $command" >&2
            usage >&2
            exit 1
            ;;
    esac
}

main "$@"