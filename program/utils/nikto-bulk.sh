#!/usr/bin/env bash
set -euo pipefail

# Running as root is not recommended, but not fatal
if [[ "$(id -u)" -eq 0 ]]; then
  echo "WARNING: Running this script as root is not recommended." >&2
fi

############################
# SPDX-License-Identifier: GPL-3.0-only
# PURPOSE: Run multiple copies of Nikto against a list of targets
#          on a *nix system with the screen utility.
############################
# Paths / config
############################
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
: "${NIKTO_BIN:="${SCRIPT_DIR}/../nikto.pl"}"

# Where Nikto writes scan results (must be "." per your requirement)
NIKTO_OUT_DIR="."
# Where this script writes logs (also "." per your requirement)
LOG_DIR="."

############################
# Runner configuration
############################
INPUT=""
MAX_CONCURRENT=""
FORMAT="html"

usage() {
  cat >&2 <<EOF
Usage: $0 [-l <targets.txt>] [-F <format>] [-c <max_concurrent>] [targets.txt] [max_concurrent]

  -l <file>    File containing target list (one per line, # for comments)
  -F <format>  Output format passed through to Nikto's -Format (default: html)
  -c <n>       Maximum concurrent scans (default: 5, warns above 10)
  -h           Show this help

The target file and max concurrent may also be given positionally:
  $0 targets.txt
  $0 targets.txt 10
EOF
  exit 1
}

while getopts ":l:F:c:h" opt; do
  case "$opt" in
    l) INPUT="$OPTARG" ;;
    F) FORMAT="$OPTARG" ;;
    c) MAX_CONCURRENT="$OPTARG" ;;
    h) usage ;;
    :) echo "ERROR: -$OPTARG requires an argument." >&2; usage ;;
    \?) echo "ERROR: Unknown option -$OPTARG" >&2; usage ;;
  esac
done
shift $((OPTIND - 1))

# Positional fallbacks: <targets.txt> [max_concurrent]
[[ -z "$INPUT" && $# -ge 1 ]] && { INPUT="$1"; shift; }
[[ -z "$MAX_CONCURRENT" && $# -ge 1 ]] && { MAX_CONCURRENT="$1"; shift; }
: "${MAX_CONCURRENT:=5}"

# Nikto flags (customize here)
#  "-S ."
NIKTO_FLAGS=(
  "-ask" "no"
  "-F" "$FORMAT"
)

############################
# Safety checks
############################
if [[ -z "${INPUT}" || ! -f "${INPUT}" ]]; then
  [[ -n "${INPUT}" ]] && echo "ERROR: target file not found: ${INPUT}" >&2
  usage
fi
if ! [[ "$MAX_CONCURRENT" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: max concurrent must be a positive integer, got: $MAX_CONCURRENT" >&2
  exit 1
fi
if [[ "$MAX_CONCURRENT" -gt 10 ]]; then
  echo "WARNING: ${MAX_CONCURRENT} concurrent scans is a lot; expect heavy CPU, memory and network load." >&2
fi
if ! [[ "$FORMAT" =~ ^[A-Za-z0-9,._-]+$ ]]; then
  echo "ERROR: invalid format string: $FORMAT" >&2
  exit 1
fi
command -v screen >/dev/null 2>&1 || { echo "Error: 'screen' not found." >&2; exit 1; }
[[ -f "$NIKTO_BIN" ]] || { echo "Error: nikto.pl not found at: $NIKTO_BIN" >&2; exit 1; }

############################
# Helpers
############################
count_running() {
  local count
  count=$(screen -ls 2>/dev/null | grep -c 'nikbulk_' 2>/dev/null)
  # Strip all whitespace and ensure it's just a number
  count="${count//[[:space:]]/}"
  # Default to 0 if empty or invalid
  if [[ -z "$count" ]] || ! [[ "$count" =~ ^[0-9]+$ ]]; then
    count=0
  fi
  printf "%d" "$count"
}

sanitize() {
  echo "$1" | tr -c 'A-Za-z0-9._-`' '_' | tr -s '_' | sed 's/^_//;s/_$//'
}

############################
# Main loop
############################
# First pass: count total valid targets
total_targets=0
while IFS= read -r raw || [[ -n "$raw" ]]; do
  line="$(echo "$raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -z "$line" || "$line" =~ ^# ]] && continue
  total_targets=$((total_targets + 1))
done < "$INPUT"

# Second pass: launch scans with progress indicator
linenum=0

while IFS= read -r raw || [[ -n "$raw" ]]; do
  line="$(echo "$raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -z "$line" || "$line" =~ ^# ]] && continue

  linenum=$((linenum+1))

  while [[ "$(count_running)" -ge "$MAX_CONCURRENT" ]]; do
    sleep 2
  done

  url="$line"
  safe_name="$(sanitize "$url")"
  screen_name="nikbulk_${safe_name}_${linenum}"
  log_file="${LOG_DIR}/${screen_name}.log"

  echo "[${linenum} of ${total_targets}] Scanning: $url"
  echo "  screen: $screen_name"
  echo "  log:    $log_file"

  # Build a safely-quoted command string (no login shell)
  cmd="$(printf '%q ' "$NIKTO_BIN" -h "$url" -o "$NIKTO_OUT_DIR" "${NIKTO_FLAGS[@]}")"

  # Redirect *inside* screen so logs actually capture Nikto stdout/stderr
  screen -S "$screen_name" -d -m bash -c "$cmd >> $(printf '%q' "$log_file") 2>&1"

done < "$INPUT"

echo "******************************************"
echo "All targets queued."
echo ""

# Monitor screen sessions with live status updates
monitor_scans() {
  # Temporarily disable exit on error within monitor to prevent premature exits
  set +e
  local total_scans=$linenum
  local running=0
  local last_count=-1
  local consecutive_zeros=0
  
  if [[ "$total_scans" -eq 0 ]]; then
    echo "No scans to monitor."
    set -e
    return 0
  fi
  
  # Give sessions a moment to initialize and start launching
  sleep 2
  
  # Show initial message before clearing
  echo "Monitoring ${total_scans} scan session(s)..."
  echo "Press Ctrl+C to stop monitoring (scans will continue)"
  sleep 0.5
  
  # Trap to ensure we can exit cleanly
  trap 'echo ""; echo "Monitor stopped. Scans continue in background."; set -e; exit 0' INT TERM
  
  while true; do
    # Get running count with error handling
    running=$(count_running 2>/dev/null || echo "0")
    # Strip any whitespace/newlines
    running="${running//[[:space:]]/}"
    # Ensure it's a valid number
    if ! [[ "$running" =~ ^[0-9]+$ ]]; then
      running=0
    fi
    
    # Always update display for live feedback - try multiple clear methods
    if command -v tput >/dev/null 2>&1; then
      tput clear 2>/dev/null || true
    else
      clear 2>/dev/null || printf '\033[2J\033[H' 2>/dev/null || true
    fi
    
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║          Nikto Bulk Scan Monitor                       ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Total sessions:  ${total_scans}"
    echo "  Running:         ${running}"
    completed=$((total_scans - running)) || completed=0
    echo "  Completed:       ${completed}"
    echo ""
    
    if [[ "$running" -gt 0 ]]; then
      echo "  Active sessions:"
      # Get screen sessions and process them without subshell
      IFS=$'\n'
      sessions=($(screen -ls 2>/dev/null | grep 'nikbulk_' 2>/dev/null || true))
      unset IFS
      for line in "${sessions[@]}"; do
        [[ -z "$line" ]] && continue
        session_name=$(echo "$line" | awk '{print $1}' | sed 's/^[0-9]*\.//' 2>/dev/null || echo "unknown")
        status=$(echo "$line" | awk '{for(i=2;i<NF;i++) printf "%s ", $i; print $NF}' 2>/dev/null || echo "unknown")
        echo "    • ${session_name} - ${status}"
      done
    else
      if [[ "$consecutive_zeros" -lt 2 ]]; then
        echo "  Waiting for sessions to start..."
      else
        echo "  ✓ All scans completed!"
      fi
    fi
    
    echo ""
    echo "  (Press Ctrl+C to exit monitor)"
    
    last_count=$running
    
    # Exit if all scans are done (wait a few checks to be sure)
    if [[ "$running" -eq 0 ]] && [[ "$total_scans" -gt 0 ]]; then
      consecutive_zeros=$((consecutive_zeros + 1))
      if [[ "$consecutive_zeros" -ge 3 ]]; then
        sleep 1
        clear
        echo "╔════════════════════════════════════════════════════════╗"
        echo "║          All Scans Completed!                          ║"
        echo "╚════════════════════════════════════════════════════════╝"
        echo ""
        echo "  Total sessions:  ${total_scans}"
        echo "  Completed:       ${total_scans}"
        echo ""
        set -e
        break
      fi
    else
      consecutive_zeros=0
    fi
    
    # Always sleep to prevent tight loop - this is critical for the loop to continue
    sleep 2 || sleep 1 || sleep 0.5 || true
  done
  
  # Clear trap on exit and re-enable error handling
  trap - INT TERM
  set -e
}

# Start monitoring (with error handling to prevent script exit)
monitor_scans || {
  echo ""
  echo "Monitor exited. Check screen sessions manually: screen -ls | grep nikbulk_"
  exit 0
}
