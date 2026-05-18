#!/bin/bash
# Parallel execution library for pwnMyCTF
# Provides mechanisms for running commands in parallel

# Function: run_parallel
# Runs multiple commands in parallel and returns the first successful result
# Parameters:
#   $1 - timeout in seconds (default: 30)
#   $2... - commands to execute
# Returns: exit code of the first successful command (0), or last command's code if all fail
run_parallel() {
    local timeout="${1:-30}"
    shift
    local commands=("$@")
    local num_commands=${#commands[@]}
    local pids=()
    local results=()
    local success=false
    
    # Temporary files for storing results
    local temp_dir=$(mktemp -d)
    local result_files=()
    
    # Start all commands in background
    for i in "${!commands[@]}"; do
        local result_file="${temp_dir}/result_${i}"
        result_files+=("$result_file")
        
        # Execute command and capture both stdout and exit code
        {
            local output
            output=$(${commands[$i]} 2>&1)
            local exit_code=$?
            
            # Store output and exit code
            echo "EXIT_CODE:$exit_code" > "$result_file"
            echo "OUTPUT_START" >> "$result_file"
            echo "$output" >> "$result_file"
            echo "OUTPUT_END" >> "$result_file"
        } &
        pids+=($!)
    done
    
    # Wait for completion or timeout
    local completed=0
    local start_time=$(date +%s)
    
    while [ $completed -lt $num_commands ] && [ $(( $(date +%s) - start_time )) -lt $timeout ]; do
        completed=0
        for pid in "${pids[@]}"; do
            if ! kill -0 "$pid" 2>/dev/null; then
                completed=$((completed + 1))
            fi
        done
        if [ $completed -lt $num_commands ]; then
            sleep 0.1
        fi
    done
    
    # Kill any remaining processes
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
        fi
    done
    
    # Check results for first success
    for i in "${!result_files[@]}"; do
        local result_file="${result_files[$i]}"
        if [ -f "$result_file" ]; then
            local exit_code
            exit_code=$(grep "^EXIT_CODE:" "$result_file" | cut -d: -f2)
            if [ "$exit_code" -eq 0 ]; then
                # Found successful result, output it and clean up
                sed -n '/^OUTPUT_START$/,/^OUTPUT_END$/p' "$result_file" | sed '1d;$d'
                success=true
                break
            fi
        fi
    done
    
    # If no success found, output last result for debugging
    if [ "$success" = false ] && [ ${#result_files[@]} -gt 0 ]; then
        local last_result="${result_files[-1]}"
        if [ -f "$last_result" ]; then
            sed -n '/^OUTPUT_START$/,/^OUTPUT_END$/p' "$last_result" | sed '1d;$d'
        fi
    fi
    
    # Clean up
    rm -rf "$temp_dir"
    
    if [ "$success" = true ]; then
        return 0
    else
        return 1
    fi
}

# Function: run_parallel_limited
# Runs multiple commands in parallel with a limit on concurrent processes
# Parameters:
#   $1 - max concurrent processes (default: 3)
#   $2 - timeout in seconds (default: 30)
#   $3... - commands to execute
# Returns: exit code of the last command (0 if all succeeded, non-zero otherwise)
run_parallel_limited() {
    local max_concurrent="${1:-3}"
    local timeout="${2:-30}"
    shift 2
    local commands=("$@")
    local num_commands=${#commands[@]}
    local pids=()
    local results=()
    local running=0
    local next=0
    local success_count=0
    
    # Temporary files for storing results
    local temp_dir=$(mktemp -d)
    local result_files=()
    
    # Function to check and reap completed processes
    reap_completed() {
        local i=0
        while [ $i -lt ${#pids[@]} ]; do
            local pid="${pids[$i]}"
            if ! kill -0 "$pid" 2>/dev/null; then
                wait "$pid" 2>/dev/null
                local exit_code=$?
                if [ $exit_code -eq 0 ]; then
                    success_count=$((success_count + 1))
                fi
                # Remove completed process from arrays
                unset 'pids[$i]'
                unset 'results[$i]'
                # Reindex arrays
                pids=("${pids[@]}")
                results=("${results[@]}")
            else
                i=$((i + 1))
            fi
        done
    }
    
    # Start initial batch of processes
    while [ $next -lt $num_commands ] && [ $running -lt $max_concurrent ]; do
        local result_file="${temp_dir}/result_${next}"
        result_files+=("$result_file")
        
        {
            local output
            output=$(${commands[$next]} 2>&1)
            local exit_code=$?
            
            # Store output and exit code
            echo "EXIT_CODE:$exit_code" > "$result_file"
            echo "OUTPUT_START" >> "$result_file"
            echo "$output" >> "$result_file"
            echo "OUTPUT_END" >> "$result_file"
        } &
        pids+=($!)
        results+=(1)  # Mark as running
        running=$((running + 1))
        next=$((next + 1))
    done
    
    # Wait for all processes to complete
    while [ $running -gt 0 ] || [ $next -lt $num_commands ]; do
        reap_completed
        
        # Start new processes if we have capacity
        while [ $next -lt $num_commands ] && [ $running -lt $max_concurrent ]; do
            local result_file="${temp_dir}/result_${next}"
            result_files+=("$result_file")
            
            {
                local output
                output=$(${commands[$next]} 2>&1)
                local exit_code=$?
                
                # Store output and exit code
                echo "EXIT_CODE:$exit_code" > "$result_file"
                echo "OUTPUT_START" >> "$result_file"
                echo "$output" >> "$result_file"
                echo "OUTPUT_END" >> "$result_file"
            } &
            pids+=($!)
            results+=(1)  # Mark as running
            running=$((running + 1))
            next=$((next + 1))
        done
        
        if [ $running -gt 0 ] || [ $next -lt $num_commands ]; then
            sleep 0.1
        fi
    done
    
    # Reap any remaining processes
    reap_completed
    
    # Collect results (for debugging if needed)
    local all_success=true
    for i in "${!result_files[@]}"; do
        local result_file="${result_files[$i]}"
        if [ -f "$result_file" ]; then
            local exit_code
            exit_code=$(grep "^EXIT_CODE:" "$result_file" | cut -d: -f2)
            if [ "$exit_code" -ne 0 ]; then
                all_success=false
                break
            fi
        fi
    done
    
    # Clean up
    rm -rf "$temp_dir"
    
    if [ "$all_success" = true ]; then
        return 0
    else
        return 1
    fi
}

# Export functions for use in other scripts
export -f run_parallel
export -f run_parallel_limited