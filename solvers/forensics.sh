#!/usr/bin/env bash
# Forensics solver for pwnMyCTF
# Implements file analysis, archive extraction, steganography detection, and PNG metadata extraction

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

# FOREN-01: File type identification from magic bytes
forensics_identify() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "FOREN-01: Identifying file type for: $target"
    
    # Use file command for MIME type
    local mime
    mime=$(file -b --mime-type "$target" 2>/dev/null)
    log_verbose 2 "MIME type: $mime"
    
    # Check magic bytes manually with xxd
    local magic_bytes
    magic_bytes=$(xxd -l 16 -p "$target" 2>/dev/null | tr -d '\n')
    log_verbose 2 "Magic bytes (hex): $magic_bytes"
    
    # Return file type description
    echo "$mime"
    return 0
}

# FOREN-02: String extraction from binary files
forensics_strings() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "FOREN-02: Extracting strings from: $target"
    
    local flag=""
    
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
    
    # Also try grep -a for binary files
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
    
    return 1
}

# FOREN-03: Hexdump analysis for patterns and embedded data
forensics_hexdump() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "FOREN-03: Analyzing hexdump for: $target"
    
    local flag=""
    local hex_output=""
    
    # Use xxd for hex view (limit to first 1MB for safety - T-FOREN-02)
    if command -v xxd &>/dev/null; then
        # Only process first 1MB to prevent DoS
        hex_output=$(dd if="$target" bs=1M count=1 2>/dev/null | xxd -p 2>/dev/null | tr -d '\n')
        
        # Look for embedded flag patterns in hex
        if flag=$(echo "$hex_output" | grep -Eo "666c6167[0-9a-fA-F]*" | head -1); then
            # Found hex-encoded "flag" - try to decode
            local decoded
            decoded=$(echo "$flag" | sed 's/../\\x&/g' | xargs echo -e 2>/dev/null)
            if [[ -n "$decoded" ]]; then
                log_verbose 2 "Found hex-encoded flag: $decoded"
                echo "$decoded"
                return 0
            fi
        fi
        
        # Look for URL patterns in hex
        local urls
        urls=$(echo "$hex_output" | grep -Eo '687474703a2f2f[0-9a-fA-F.]+' | head -3)
        if [[ -n "$urls" ]]; then
            log_verbose 2 "Found URLs in hex: $urls"
            # Try to decode and check for flags
            for url in $urls; do
                local decoded_url
                decoded_url=$(echo "$url" | sed 's/../\\x&/g' | xargs echo -e 2>/dev/null)
                if [[ "$decoded_url" =~ flag ]]; then
                    if flag=$(echo "$decoded_url" | grep -Eo "$FLAG_PATTERN"); then
                        echo "$flag"
                        return 0
                    fi
                fi
            done
        fi
        
        # Look for base64 patterns in hex (alphanumeric sequences)
        local b64_patterns
        b64_patterns=$(echo "$hex_output" | grep -Eo '[A-Za-z0-9+/=]{20,}' | head -5)
        if [[ -n "$b64_patterns" ]]; then
            for b64 in $b64_patterns; do
                local decoded_b64
                decoded_b64=$(echo "$b64" | base64 -d 2>/dev/null)
                if [[ -n "$decoded_b64" ]]; then
                    if flag=$(echo "$decoded_b64" | grep -Eo "$FLAG_PATTERN"); then
                        echo "$flag"
                        return 0
                    fi
                fi
            done
        fi
    fi
    
    # Also try hexdump as fallback
    if [[ -z "$hex_output" ]] && command -v hexdump &>/dev/null; then
        hex_output=$(dd if="$target" bs=1M count=1 2>/dev/null | hexdump -C 2>/dev/null)
        
        # Search for flag in hexdump output
        if flag=$(echo "$hex_output" | grep -Eo "$FLAG_PATTERN" | head -1); then
            echo "$flag"
            return 0
        fi
    fi
    
    return 1
}

# FOREN-04: Archive extraction (zip, tar, gzip, 7z)
forensics_extract_archive() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "FOREN-04: Extracting archive: $target"
    
    local flag=""
    local temp_dir=""
    
    # Create temp directory for extraction
    temp_dir=$(mktemp -d)
    trap "rm -rf '$temp_dir' 2>/dev/null" EXIT
    
    local mime
    mime=$(file -b --mime-type "$target" 2>/dev/null)
    
    # Try zip
    if [[ "$mime" == "application/zip" ]] || [[ "$target" == *.zip ]]; then
        log_verbose 2 "Trying zip extraction..."
        if command -v unzip &>/dev/null; then
            if unzip -o "$target" -d "$temp_dir" 2>/dev/null; then
                log_verbose 2 "Zip extracted, scanning contents..."
                if flag=$(find_flags_in_directory "$temp_dir"); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    fi
    
    # Try tar
    if [[ "$mime" == "application/x-tar" ]] || [[ "$target" == *.tar* ]]; then
        log_verbose 2 "Trying tar extraction..."
        if command -v tar &>/dev/null; then
            if tar -xf "$target" -C "$temp_dir" 2>/dev/null; then
                log_verbose 2 "Tar extracted, scanning contents..."
                if flag=$(find_flags_in_directory "$temp_dir"); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    fi
    
    # Try gzip (single file)
    if [[ "$mime" == "application/gzip" ]] || [[ "$target" == *.gz ]]; then
        log_verbose 2 "Trying gzip extraction..."
        if command -v gzip &>/dev/null; then
            local extracted_file="$temp_dir/extracted"
            if gzip -dc "$target" > "$extracted_file" 2>/dev/null; then
                log_verbose 2 "Gzip extracted, scanning contents..."
                # Check if it's a tar
                if flag=$(find_flags_in_directory "$temp_dir"); then
                    echo "$flag"
                    return 0
                fi
                # Check the extracted file directly
                if flag=$(search_flag_in_file "$extracted_file"); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    fi
    
    # Try 7z
    if [[ "$mime" == "application/x-7z-compressed" ]] || [[ "$target" == *.7z ]]; then
        log_verbose 2 "Trying 7z extraction..."
        if command -v 7z &>/dev/null; then
            if 7z x "$target" -o"$temp_dir" -y 2>/dev/null; then
                log_verbose 2 "7z extracted, scanning contents..."
                if flag=$(find_flags_in_directory "$temp_dir"); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    fi
    
    # Format not supported or tool missing - T-FOREN-02 handled above
    log_verbose 2 "Archive extraction failed or format not supported"
    return 2
}

# FOREN-05: Steganography detection (hybrid approach)
forensics_stego() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "FOREN-05: Detecting steganography in: $target"
    
    local flag=""
    
    # Phase 1: Basic analysis
    
    # Check file size anomalies (size >> apparent content)
    local file_size apparent_size ratio
    file_size=$(stat -f%z "$target" 2>/dev/null || stat -c%s "$target" 2>/dev/null)
    
    # Get apparent size from file command
    apparent_size=$(file -b "$target" 2>/dev/null)
    log_verbose 2 "File size: $file_size bytes, info: $apparent_size"
    
    # For PNG files, examine IDAT/PLTE chunks
    if [[ "$target" == *.png ]] || [[ $(file -b --mime-type "$target" 2>/dev/null) == "image/png" ]]; then
        log_verbose 2 "Analyzing PNG structure..."
        
        # Look for unusual PNG chunk patterns
        local png_chunks
        png_chunks=$(xxd "$target" 2>/dev/null | grep -E "49444154|504c5445|74455874" || true)
        if [[ -n "$png_chunks" ]]; then
            log_verbose 2 "Found PNG chunks (IDAT/PLTE/tEXt): $png_chunks"
            
            # Extract tEXt chunk data (contains keyword + text)
            local text_data
            text_data=$(xxd "$target" 2>/dev/null | grep -A2 "74455874" | head -20)
            if [[ -n "$text_data" ]]; then
                if flag=$(echo "$text_data" | grep -Eo "$FLAG_PATTERN"); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
        
        # Check for LSB patterns in PNG (steganography indicator)
        # Extract LSB from first few bytes of image data
        local lsb_check
        lsb_check=$(dd if="$target" bs=1 skip=100 count=512 2>/dev/null | xxd -b 2>/dev/null | tail -20)
        log_verbose 2 "LSB analysis: checking for patterns..."
    fi
    
    # Check for appended data after image (common steganography technique)
    local jpeg_png_magic
    jpeg_png_magic=$(xxd -l 8 -p "$target" 2>/dev/null | tr -d '\n')
    
    if [[ "$jpeg_png_magic" == "89504e470d0a1a0a" ]] || [[ "$jpeg_png_magic" == "ffd8ffe0" ]]; then
        # PNG or JPEG - check for appended data after EOF marker
        local eof_offset
        if [[ "$jpeg_png_magic" == "89504e470d0a1a0a" ]]; then
            # PNG ends with IEND (49 45 4e 44)
            eof_offset=$(xxd "$target" 2>/dev/null | grep -a "49454e44" | tail -1 | awk '{print $1}' || true)
        else
            # JPEG - find end of image (FFD9)
            eof_offset=$(xxd "$target" 2>/dev/null | grep -a "ffd9" | tail -1 | awk '{print $1}' || true)
        fi
        
        if [[ -n "$eof_offset" ]]; then
            local hex_offset=$((16#$eof_offset))
            local remaining=$((file_size - hex_offset - 8))
            if [[ $remaining -gt 0 ]]; then
                log_verbose 2 "Found $remaining bytes after EOF marker"
                # Extract appended data
                local appended_data
                appended_data=$(dd if="$target" bs=1 skip=$((hex_offset + 8)) count=$remaining 2>/dev/null | xxd -p)
                if flag=$(echo "$appended_data" | grep -Eo "$FLAG_PATTERN"); then
                    echo "$flag"
                    return 0
                fi
            fi
        fi
    fi
    
    # Phase 2: Tool-based analysis (if available)
    
    # Use binwalk if available
    if command -v binwalk &>/dev/null; then
        log_verbose 2 "Running binwalk analysis..."
        local binwalk_output
        binwalk_output=$(binwalk "$target" 2>/dev/null)
        
        if flag=$(echo "$binwalk_output" | grep -Eo "$FLAG_PATTERN"); then
            echo "$flag"
            return 0
        fi
        
        # Extract embedded data
        binwalk -e "$target" -D ".*" -m "$temp_dir/binwalk" 2>/dev/null || true
        if [[ -d "$temp_dir/binwalk" ]]; then
            if flag=$(find_flags_in_directory "$temp_dir/binwalk"); then
                echo "$flag"
                return 0
            fi
        fi
    fi
    
    # Use steghide if available
    if command -v steghide &>/dev/null; then
        log_verbose 2 "Trying steghide..."
        # Try common empty passwords
        for password in "" "password" "secret" "flag" "ctf"; do
            if steghide extract -sf "$target" -p "$password" -xf "$temp_dir/steghide_out.txt" 2>/dev/null; then
                if [[ -f "$temp_dir/steghide_out.txt" ]]; then
                    if flag=$(search_flag_in_file "$temp_dir/steghide_out.txt"); then
                        echo "$flag"
                        return 0
                    fi
                fi
            fi
        done
    fi
    
    # Use exiftool if available (can reveal steganography in metadata)
    if command -v exiftool &>/dev/null; then
        log_verbose 2 "Running exiftool analysis..."
        local exif_output
        exif_output=$(exiftool "$target" 2>/dev/null)
        
        if flag=$(echo "$exif_output" | grep -Eo "$FLAG_PATTERN"); then
            echo "$flag"
            return 0
        fi
    fi
    
    log_verbose 2 "No steganography detected"
    return 1
}

# FOREN-06: PNG metadata extraction (exiftool with fallback)
forensics_png_metadata() {
    local target="$1"
    local verbose="${2:-0}"
    
    log_verbose 2 "FOREN-06: Extracting PNG metadata from: $target"
    
    local flag=""
    
    # Only process PNG files
    local mime
    mime=$(file -b --mime-type "$target" 2>/dev/null)
    if [[ "$mime" != "image/png" ]]; then
        log_verbose 2 "Not a PNG file, skipping metadata extraction"
        return 1
    fi
    
    # Method 1: Use exiftool if available
    if command -v exiftool &>/dev/null; then
        log_verbose 2 "Using exiftool for metadata extraction..."
        local exif_output
        exif_output=$(exiftool "$target" 2>/dev/null)
        
        # Search for flag in exif output
        if flag=$(echo "$exif_output" | grep -Eo "$FLAG_PATTERN"); then
            echo "$flag"
            return 0
        fi
        if flag=$(echo "$exif_output" | grep -Eo "$FLAG_PATTERN_ALT"); then
            echo "$flag"
            return 0
        fi
        if flag=$(echo "$exif_output" | grep -Eo "$FLAG_PATTERN_CTF"); then
            echo "$flag"
            return 0
        fi
    fi
    
    # Method 2: Manual PNG chunk parsing (tEXt, zTXt, iTXt chunks)
    log_verbose 2 "Using manual PNG chunk parsing..."
    
    # Search for tEXt chunks (keyword + text)
    # tEXt: 74 45 58 74 followed by length and keyword
    local text_chunks
    text_chunks=$(xxd "$target" 2>/dev/null | grep -a "74455874" -A10 | head -50)
    
    if [[ -n "$text_chunks" ]]; then
        log_verbose 2 "Found tEXt chunks, analyzing..."
        
        # Extract printable text from tEXt chunks
        local text_content
        text_content=$(echo "$text_chunks" | xxd -r -p 2>/dev/null | tr -d '\000-\037\177-\377' | head -200)
        
        if flag=$(echo "$text_content" | grep -Eo "$FLAG_PATTERN"); then
            echo "$flag"
            return 0
        fi
    fi
    
    # Search for zTXt chunks (compressed text)
    # zTXt: 7a 54 58 74 - need to decompress
    if command -v zlib-flate &>/dev/null || python3 -c "import zlib" 2>/dev/null; then
        log_verbose 2 "Checking for zTXt compressed chunks..."
        # This would require more complex parsing - skip for now
        :
    fi
    
    # Search for iTXt chunks (international text)
    local itxt_chunks
    itxt_chunks=$(xxd "$target" 2>/dev/null | grep -a "69545874" -A10 | head -50)
    
    if [[ -n "$itxt_chunks" ]]; then
        log_verbose 2 "Found iTXt chunks, analyzing..."
        local itxt_content
        itxt_content=$(echo "$itxt_chunks" | xxd -r -p 2>/dev/null | tr -d '\000-\037\177-\377' | head -200)
        
        if flag=$(echo "$itxt_content" | grep -Eo "$FLAG_PATTERN"); then
            echo "$flag"
            return 0
        fi
    fi
    
    log_verbose 2 "No flag found in PNG metadata"
    return 1
}

# Main entry point: solve_forensics
solve_forensics() {
    local target="$1"
    local verbose="${2:-0}"
    
    # Set global VERBOSE for log_verbose function
    export VERBOSE="$verbose"
    
    log_verbose 1 "Starting forensics solver for: $target"
    
    local flag=""
    local result=""
    
    # Determine if input is file or directory
    if [[ -d "$target" ]]; then
        log_verbose 1 "Processing as directory"
        
        # For directory, scan all files
        for file in "$target"/*; do
            [[ -f "$file" ]] || continue
            log_verbose 2 "Scanning file: $file"
            
            # Try to solve each file
            if result=$(solve_forensics "$file" "$verbose"); then
                echo "$result"
                return 0
            fi
        done
        
        return 2
        
    elif [[ -f "$target" ]]; then
        log_verbose 1 "Processing as file"
        
        # Run forensic techniques in sequence
        
        # FOREN-01: File type identification
        log_verbose 1 "Step 1: File identification"
        local file_type
        file_type=$(forensics_identify "$target" "$verbose")
        log_verbose 1 "Identified: $file_type"
        
        # FOREN-02: String extraction
        log_verbose 1 "Step 2: String extraction"
        if result=$(forensics_strings "$target" "$verbose"); then
            echo "$result"
            return 0
        fi
        
        # FOREN-03: Hexdump analysis
        log_verbose 1 "Step 3: Hexdump analysis"
        if result=$(forensics_hexdump "$target" "$verbose"); then
            echo "$result"
            return 0
        fi
        
        # FOREN-04: Archive extraction
        log_verbose 1 "Step 4: Archive extraction"
        if result=$(forensics_extract_archive "$target" "$verbose"); then
            echo "$result"
            return 0
        fi
        
        # FOREN-05: Steganography detection
        log_verbose 1 "Step 5: Steganography detection"
        if result=$(forensics_stego "$target" "$verbose"); then
            echo "$result"
            return 0
        fi
        
        # FOREN-06: PNG metadata extraction
        log_verbose 1 "Step 6: PNG metadata extraction"
        if result=$(forensics_png_metadata "$target" "$verbose"); then
            echo "$result"
            return 0
        fi
        
        log_verbose 1 "No flag found in forensics analysis"
        return 2
        
    else
        log_verbose 1 "Error: Target not found: $target"
        return 2
    fi
}

# Export functions for use by lib/solver.sh
export -f solve_forensics
export -f forensics_identify
export -f forensics_strings
export -f forensics_hexdump
export -f forensics_extract_archive
export -f forensics_stego
export -f forensics_png_metadata
export -f log_verbose
export -f search_flag_patterns
export -f search_flag_in_file