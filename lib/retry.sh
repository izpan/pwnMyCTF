#!/bin/bash
# Retry logic library for pwnMyCTF
# Provides retry mechanisms with backoff strategies

# Function: retry_with_backoff
# Retries a command with exponential backoff and jitter
# Parameters:
#   $1 - command to execute (as string)
#   $2 - max attempts (default: 3)
#   $3 - base delay in seconds (default: 1)
#   $4 - max delay in seconds (default: 10)
#   $5 - strategy: fixed, exponential, jitter (default: exponential)
# Returns: exit code of the command (0 on success, last attempt's code on failure)
retry_with_backoff() {
    local cmd="$1"
    local max_attempts="${2:-3}"
    local base_delay="${3:-1}"
    local max_delay="${4:-10}"
    local strategy="${5:-exponential}"
    local attempt=1
    local delay
    
    while [ $attempt -le $max_attempts ]; do
        if [ $attempt -gt 1 ]; then
            # Calculate delay based on strategy
            case "$strategy" in
                fixed)
                    delay=$base_delay
                    ;;
                exponential)
                    delay=$((base_delay * 2 ** (attempt - 2)))
                    if [ $delay -gt $max_delay ]; then
                        delay=$max_delay
                    fi
                    ;;
                jitter)
                    # Base exponential with random jitter (±25%)
                    local base=$((base_delay * 2 ** (attempt - 2)))
                    if [ $base -gt $max_delay ]; then
                        base=$max_delay
                    fi
                    local jitter=$((RANDOM % (base / 2) - base / 4))
                    delay=$((base + jitter))
                    if [ $delay -lt 0 ]; then
                        delay=0
                    fi
                    if [ $delay -gt $max_delay ]; then
                        delay=$max_delay
                    fi
                    ;;
                *)
                    delay=$base_delay
                    ;;
            esac
            
            # Sleep for calculated delay
            sleep $delay
        fi
        
        # Execute the command
        eval "$cmd"
        local exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            return 0
        fi
        
        attempt=$((attempt + 1))
    done
    
    return $exit_code
}

# Function: retry_with_history
# Retries a command while tracking history to avoid repeating same approach
# Parameters:
#   $1 - command to execute (as string)
#   $2 - max attempts (default: 3)
#   $3 - history file to track attempts (default: /tmp/retry_history)
# Returns: exit code of the command (0 on success, last attempt's code on failure)
retry_with_history() {
    local cmd="$1"
    local max_attempts="${2:-3}"
    local history_file="${3:-/tmp/retry_history}"
    local attempt=1
    
    # Clear history file at start
    > "$history_file"
    
    while [ $attempt -le $max_attempts ]; do
        if [ $attempt -gt 1 ]; then
            # Read history to avoid repeating same approach
            if [ -f "$history_file" ] && [ -s "$history_file" ]; then
                # In a real implementation, we would modify the command based on history
                # For now, we just note that we're checking history
                :
            fi
        fi
        
        # Execute the command
        eval "$cmd"
        local exit_code=$?
        
        # Record attempt in history
        echo "Attempt $attempt: $cmd (exit code: $exit_code)" >> "$history_file"
        
        if [ $exit_code -eq 0 ]; then
            return 0
        fi
        
        attempt=$((attempt + 1))
    done
    
    return $exit_code
}

# Export functions for use in other scripts
export -f retry_with_backoff
export -f retry_with_history