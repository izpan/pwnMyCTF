#!/usr/bin/env bash
# HTTP client library for pwnMyCTF

set -uo pipefail

# HTTP client configuration
HTTP_TIMEOUT="${HTTP_TIMEOUT:-30}"
HTTP_USER_AGENT="${HTTP_USER_AGENT:-"pwnMyCTF/0.1.0"}"
HTTP_FOLLOW_REDIRECTS="${HTTP_FOLLOW_REDIRECTS:-true}"
HTTP_MAX_REDIRECTS="${HTTP_MAX_REDIRECTS:-5}"
HTTP_COOKIE_JAR="${HTTP_COOKIE_JAR:-""}"

# Initialize HTTP client
http_init() {
    # Reset cookie jar if specified
    if [[ -n "$HTTP_COOKIE_JAR" ]]; then
        : > "$HTTP_COOKIE_JAR"
    fi
}

# Detect available HTTP client
get_http_client() {
    if command -v curl &>/dev/null; then
        echo "curl"
    elif command -v wget &>/dev/null; then
        echo "wget"
    else
        echo "none"
    fi
}

# Perform HTTP GET request
http_get() {
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
    
    # Execute request
    if [[ "$client" == "curl" ]]; then
        curl -s "${timeout_args[@]}" "${redirect_args[@]}" "${cookie_args[@]}" "${header_args[@]}" "$url"
    elif [[ "$client" == "wget" ]]; then
        wget -q -O - "${timeout_args[@]}" "${redirect_args[@]}" "${cookie_args[@]}" "${header_args[@]}" "$url"
    fi
}

# Perform HTTP POST request
http_post() {
    local url="$1"
    shift
    
    local client
    client=$(get_http_client)
    
    if [[ "$client" == "none" ]]; then
        echo "Error: No HTTP client available (curl or wget required)" >&2
        return 1
    fi
    
    local data="$1"
    shift
    
    local headers=("$@")
    local header_args=()
    
    # Build header arguments
    for header in "${headers[@]}"; do
        header_args+=("-H" "$header")
    done
    
    # Add User-Agent header
    header_args+=("-H" "User-Agent: $HTTP_USER_AGENT")
    
    # Add Content-Type for POST data
    header_args+=("-H" "Content-Type: application/x-www-form-urlencoded")
    
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
    
    # Execute request
    if [[ "$client" == "curl" ]]; then
        curl -s -X POST "${timeout_args[@]}" "${redirect_args[@]}" "${cookie_args[@]}" "${header_args[@]}" -d "$data" "$url"
    elif [[ "$client" == "wget" ]]; then
        wget -q -O - --post-data="$data" "${timeout_args[@]}" "${redirect_args[@]}" "${cookie_args[@]}" "${header_args[@]}" "$url"
    fi
}

# Perform HTTP PUT request
http_put() {
    local url="$1"
    shift
    
    local client
    client=$(get_http_client)
    
    if [[ "$client" == "none" ]]; then
        echo "Error: No HTTP client available (curl or wget required)" >&2
        return 1
    fi
    
    local data="$1"
    shift
    
    local headers=("$@")
    local header_args=()
    
    # Build header arguments
    for header in "${headers[@]}"; do
        header_args+=("-H" "$header")
    done
    
    # Add User-Agent header
    header_args+=("-H" "User-Agent: $HTTP_USER_AGENT")
    
    # Add Content-Type for PUT data
    header_args+=("-H" "Content-Type: application/x-www-form-urlencoded")
    
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
    
    # Execute request
    if [[ "$client" == "curl" ]]; then
        curl -s -X PUT "${timeout_args[@]}" "${redirect_args[@]}" "${cookie_args[@]}" "${header_args[@]}" -d "$data" "$url"
    elif [[ "$client" == "wget" ]]; then
        wget -q -O - --put-method --body-data="$data" "${timeout_args[@]}" "${redirect_args[@]}" "${cookie_args[@]}" "${header_args[@]}" "$url"
    fi
}

# Perform HTTP DELETE request
http_delete() {
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
    
    # Execute request
    if [[ "$client" == "curl" ]]; then
        curl -s -X DELETE "${timeout_args[@]}" "${redirect_args[@]}" "${cookie_args[@]}" "${header_args[@]}" "$url"
    elif [[ "$client" == "wget" ]]; then
        wget -q -O - --method DELETE "${timeout_args[@]}" "${redirect_args[@]}" "${cookie_args[@]}" "${header_args[@]}" "$url"
    fi
}

# URL encode a string
url_encode() {
    local input="$1"
    local encoded=""
    
    # Use printf %b to escape backslashes, then use sed to URL encode
    encoded=$(printf '%s' "$input" | sed 's/[^a-zA-Z0-9._~-]/\\&/g' | xxd -plain | tr -d '\n' | sed 's/\(..\)/%\1/g')
    
    echo "$encoded"
}

# URL decode a string
url_decode() {
    local input="$1"
    local decoded=""
    
    # Replace + with space, then decode %xx sequences
    decoded=$(echo "$input" | sed 's/+/ /g' | sed 's/%/\\x/g' | xargs -0 printf "%b" 2>/dev/null || echo "$input")
    
    echo "$decoded"
}

# Parse query string into key-value pairs
parse_query_string() {
    local query="$1"
    
    # Split by & and process each pair
    echo "$query" | tr '&' '\n' | while IFS='=' read -r key value; do
        if [[ -n "$key" ]]; then
            key=$(url_decode "$key")
            value=$(url_decode "$value")
            echo "$key=$value"
        fi
    done
}

# Build query string from key-value pairs
build_query_string() {
    local params=("$@")
    local query_parts=()
    
    for param in "${params[@]}"; do
        IFS='=' read -r key value <<< "$param"
        key=$(url_encode "$key")
        value=$(url_encode "$value")
        query_parts+=("$key=$value")
    done
    
    # Join with &
    IFS='&'
    echo "${query_parts[*]}"
}

# Extract cookies from HTTP response headers
extract_cookies_from_headers() {
    local headers="$1"
    local cookie_jar="$2"
    
    if [[ -z "$cookie_jar" ]]; then
        return 0
    fi
    
    # Extract Set-Cookie headers and append to cookie jar
    echo "$headers" | grep -i "^set-cookie:" | while IFS= read -r line; do
        # Extract cookie name=value part (before first semicolon)
        cookie=$(echo "$line" | cut -d':' -f2- | cut -d';' -f1)
        if [[ -n "$cookie" ]]; then
            echo "$cookie" >> "$cookie_jar"
        fi
    done
}

# Get cookies for a domain from cookie jar
get_cookies_for_domain() {
    local domain="$1"
    local cookie_jar="$2"
    
    if [[ -z "$cookie_jar" || ! -f "$cookie_jar" ]]; then
        return 0
    fi
    
    # For simplicity, we'll just return all cookies
    # A more sophisticated implementation would filter by domain/path
    cat "$cookie_jar" 2>/dev/null || return 0
}

# Initialize on source
http_init