#!/usr/bin/env bash
# OSINT Git repository analysis solver for pwnMyCTF

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/http.sh" 2>/dev/null || true
source "${LIB_DIR}/timeout.sh" 2>/dev/null || true

# OSINT Git repository analysis solver functions
solve_osint_git() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "Attempting OSINT git analysis on: $target"
    
    # Check if target is a directory or URL
    if [[ -d "$target/.git" ]]; then
        # Local git repository
        return analyze_git_repo "$target" "$verbose"
    elif [[ "$target" =~ ^https?:// ]]; then
        # URL - check if it's a git repository URL or web root
        local git_url="$target"
        
        # If it looks like a direct git repo URL (.git at end)
        if [[ "$target" =~ \.git/?$ ]]; then
            git_url="$target"
        else
            # Assume web root and check for .git directory
            git_url="${target%/}/.git"
        fi
        
        # Try to fetch git info from URL
        if analyze_git_url "$git_url" "$verbose"; then
            return 0
        fi
        
        # Also try common git web interfaces
        local gitweb_urls=(
            "${target%/}/.git/HEAD"
            "${target%/}/.git/config"
            "${target%/}/.git/logs/HEAD"
            "${target%/}/.git/objects/info/packs"
            "${target%/}/.git/refs/heads/master"
            "${target%/}/.git/refs/heads/main"
        )
        
        for url in "${gitweb_urls[@]}"; do
            if http_get "$url" 2>/dev/null | grep -qE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}'; then
                if flag=$(http_get "$url" 2>/dev/null | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                    echo "$flag"
                    return 0
                fi
            fi
        done
        
        return 1
    else
        # Treat as path - check if it's a git repo or contains one
        if [[ -d "$target" ]]; then
            # Directory - look for .git subdirectory
            if [[ -d "$target/.git" ]]; then
                return analyze_git_repo "$target" "$verbose"
            fi
            
            # Search for .git directories in subdirectories (limited depth)
            while IFS= read -r -d '' gitdir; do
                if [[ -d "$gitdir" ]]; then
                    local repo_dir="${gitdir%/.git}"
                    if analyze_git_repo "$repo_dir" "$verbose"; then
                        return 0
                    fi
                fi
            done < <(find "$target" -type d -name ".git" -print0 2>/dev/null | head -z)
        fi
        
        return 1
    fi
}

# Analyze a local git repository
analyze_git_repo() {
    local repo_path="$1"
    local verbose="$2"
    
    log_verbose 2 "Analyzing git repository at: $repo_path"
    
    # Check for flags in git config
    if [[ -f "$repo_path/.git/config" ]]; then
        if flag=$(grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' "$repo_path/.git/config" 2>/dev/null | head -1); then
            echo "$flag"
            return 0
        fi
    fi
    
    # Check for flags in git HEAD
    if [[ -f "$repo_path/.git/HEAD" ]]; then
        if flag=$(grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' "$repo_path/.git/HEAD" 2>/dev/null | head -1); then
            echo "$flag"
            return 0
        fi
    fi
    
    # Check for flags in git index
    if [[ -f "$repo_path/.git/index" ]]; then
        # Binary file, use strings
        if flag=$(strings "$repo_path/.git/index" 2>/dev/null | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
            echo "$flag"
            return 0
        fi
    fi
    
    # Check for flags in git logs (limited to recent commits)
    if git -C "$repo_path" log --oneline -10 2>/dev/null | grep -qE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}'; then
        if flag=$(git -C "$repo_path" log --oneline -10 2>/dev/null | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
            echo "$flag"
            return 0
        fi
    fi
    
    # Check for flags in git diff (staged changes)
    if git -C "$repo_path" diff --cached 2>/dev/null | grep -qE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}'; then
        if flag=$(git -C "$repo_path" diff --cached 2>/dev/null | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
            echo "$flag"
            return 0
        fi
    fi
    
    # Check for flags in working tree (untracked and modified files)
    if git -C "$repo_path" ls-files --others --exclude-standard 2>/dev/null | while read file; do
        if [[ -f "$repo_path/$file" ]]; then
            if grep -qE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' "$repo_path/$file" 2>/dev/null; then
                if flag=$(grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' "$repo_path/$file" 2>/dev/null | head -1); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    done; then
        return 0  # Flag found and echoed in the loop
    fi
    
    # Check for flags in committed files (limited to prevent excessive scanning)
    if git -C "$repo_path" ls-tree -r HEAD --name-only 2>/dev/null | head -20 | while read file; do
        if [[ -f "$repo_path/$file" ]]; then
            if grep -qE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' "$repo_path/$file" 2>/dev/null; then
                if flag=$(grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' "$repo_path/$file" 2>/dev/null | head -1); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    done; then
        return 0  # Flag found and echoed in the loop
    fi
    
    return 1
}

# Analyze a git repository via HTTP (exposed .git directory)
analyze_git_url() {
    local git_url="$1"
    local verbose="$2"
    
    log_verbose 2 "Analyzing git repository at URL: $git_url"
    
    # Check if we can access the git directory
    if ! http_head "$git_url" 2>/dev/null; then
        return 1
    fi
    
    # Try to fetch HEAD reference
    if head_ref=$(http_get "$git_url/HEAD" 2>/dev/null); then
        if echo "$head_ref" | grep -qE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}'; then
            if flag=$(echo "$head_ref" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                echo "$flag"
                return 0
            fi
        fi
    fi
    
    # Try to fetch config
    if config=$(http_get "$git_url/config" 2>/dev/null); then
        if echo "$config" | grep -qE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}'; then
            if flag=$(echo "$config" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                echo "$flag"
                return 0
            fi
        fi
    fi
    
    # Try to fetch packed-refs
    if packed_refs=$(http_get "$git_url/packed-refs" 2>/dev/null); then
        if echo "$packed_refs" | grep -qE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}'; then
            if flag=$(echo "$packed_refs" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                echo "$flag"
                return 0
            fi
        fi
    fi
    
    # Try to fetch some loose objects (limited)
    # First get objects info/packs to know what packs exist
    if packs_info=$(http_get "$git_url/objects/info/packs" 2>/dev/null); then
        # Extract pack filenames
        while IFS= read -r pack_line; do
            if [[ "$pack_line" =~ P\s+([0-9a-f]{40})\.pack ]]; then
                pack_hash="${BASH_REMATCH[1]}"
                # Try to fetch the pack file (might be large, so just try index first)
                if pack_idx=$(http_get "$git_url/objects/pack/${pack_hash}.idx" 2>/dev/null | head -c 100); then
                    if echo "$pack_idx" | grep -qE 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}'; then
                        if flag=$(echo "$pack_idx" | grep -Eo 'flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\}' | head -1); then
                            echo "$flag"
                            return 0
                        fi
                    fi
                fi
            fi
        done <<< "$packs_info"
    fi
    
    return 1
}

# HEAD request helper (since http.sh doesn't have one)
http_head() {
    local url="$1"
    shift
    
    local client
    client=$(get_http_client)
    
    if [[ "$client" == "none" ]]; then
        echo "Error: No HTTP client available (curl or wget required)" >&2
        return 1
    fi
    
    local headers=("$@")
    local header_args=()
    
    # Build header arguments
    for header in "${headers[@]}"; do
        header_args+=("-H" "$header")
    done
    
    # Add User-Agent header
    header_args+=("-H" "User-Agent: $HTTP_USER_AGENT")
    
    # Add cookie jar if specified
    local cookie_args=()
    if [[ -n "$HTTP_COOKIE_JAR" && -f "$HTTP_COOKIE_JAR" ]]; then
        if [[ "$client" == "curl" ]]; then
            cookie_args=("--cookie" "$HTTP_COOKIE_JAR" "--cookie-jar" "$HTTP_COOKIE_JAR")
        elif [[ "$client" == "wget" ]]; then
            cookie_args=("--load-cookies" "$HTTP_COOKIE_JAR" "--save-cookies" "$HTTP_COOKIE_JAR" "--keep-session-cookies")
        fi
    fi
    
    # Add timeout
    local timeout_args=()
    if [[ "$HTTP_TIMEOUT" -gt 0 ]]; then
        if [[ "$client" == "curl" ]]; then
            timeout_args=("--max-time" "$HTTP_TIMEOUT")
        elif [[ "$client" == "wget" ]]; then
            timeout_args=("--timeout=$HTTP_TIMEOUT")
        fi
    fi
    
    # Add redirect handling
    local redirect_args=()
    if [[ "$HTTP_FOLLOW_REDIRECTS" == "true" ]]; then
        if [[ "$client" == "curl" ]]; then
            redirect_args=("-L" "--max-redirs" "$HTTP_MAX_REDIRECTS")
        elif [[ "$client" == "wget" ]]; then
            redirect_args=("--max-redirect=$HTTP_MAX_REDIRECTS")
        fi
    fi
    
    # Execute HEAD request
    if [[ "$client" == "curl" ]]; then
        curl -sI "${timeout_args[@]}" "${redirect_args[@]}" "${cookie_args[@]}" "${header_args[@]}" "$url" >/dev/null
    elif [[ "$client" == "wget" ]]; then
        wget -q --spider "${timeout_args[@]}" "${redirect_args[@]}" "${cookie_args[@]}" "${header_args[@]}" "$url" 2>/dev/null
    fi
}

# Get HTTP client (duplicate from http.sh for independence)
get_http_client() {
    if command -v curl &>/dev/null; then
        echo "curl"
    elif command -v wget &>/dev/null; then
        echo "wget"
    else
        echo "none"
    fi
}

# Export functions
export -f solve_osint_git
export -f analyze_git_repo
export -f analyze_git_url