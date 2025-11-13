#!/usr/bin/env bash
# ===============================================
# Full Diagnostic System & User Management Tool
# Organized Numeric Menu
# Linux Mint / Ubuntu / Debian
# ===============================================

set -euo pipefail
ADMIN_GROUP="sudo"
last_high_perm_scan=""
declare -A PERM_BACKUP

echo "[DEBUG] Script started."
echo "[DEBUG] Bash version: $BASH_VERSION"
echo "[DEBUG] EUID: $EUID"

# --- Detect root ---
if [[ $EUID -eq 0 ]]; then
    SUDO_CMD=""
    echo "[DEBUG] Running as root."
else
    SUDO_CMD="sudo"
    echo "[DEBUG] Running as non-root; using sudo."
fi

# -------------------
# Startup checks
# -------------------

# Null-password authentication check
check_null_password_status() {
    local file="/etc/pam.d/common-auth"
    if [[ ! -f "$file" ]]; then
        echo "[WARNING] $file not found. Cannot check null-password status."
        return
    fi

    if grep -qE 'pam_unix.*nullok' "$file"; then
        echo "[WARNING] Null-password authentication IS currently ENABLED in $file."
        echo "You can use option 20 to disable it safely."
    else
        echo "[INFO] Null-password authentication is currently DISABLED."
    fi
}

# SSH root login check
check_ssh_root_login() {
    local sshd_file="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_file" ]]; then
        echo "[WARNING] $sshd_file not found; cannot check SSH root login."
        return
    fi

    local root_status
    root_status=$(grep -Ei '^\s*PermitRootLogin' "$sshd_file" | awk '{print $2}' | tr -d '\r\n' || true)
    root_status=${root_status:-prohibit-password}

    if [[ "$root_status" == "yes" ]]; then
        echo "[WARNING] SSH root login is ENABLED. Consider disabling it for security."
    else
        echo "[INFO] SSH root login is disabled."
    fi
}

# World-writable files check
check_world_writable_files() {
    echo "[INFO] Scanning / for world-writable files (this may take a while)..."
    local results
    results=$($SUDO_CMD find / -xdev -type f -perm -o=w \
        \( -path /proc -o -path /sys -o -path /dev \) -prune -o -print 2>/dev/null || true)

    if [[ -n "$results" ]]; then
        echo "[WARNING] Some world-writable files exist on the system. Consider reviewing their permissions."
        last_high_perm_scan="$results"
    else
        echo "[INFO] No world-writable files found at startup."
    fi
}

# IPv4 forwarding check
check_ipv4_forwarding() {
    echo "[DEBUG] Checking IPv4 forwarding status..."
    if sysctl -n net.ipv4.ip_forward 2>/dev/null | grep -q '^1$'; then
        echo "[WARNING] IPv4 forwarding is ENABLED (net.ipv4.ip_forward=1)."
    else
        echo "[INFO] IPv4 forwarding is DISABLED."
    fi
}

# vsftpd check
check_vsftpd_status() {
    echo "[DEBUG] Checking vsftpd service status..."
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet vsftpd 2>/dev/null; then
        echo "[WARNING] FTP (vsftpd) service is running."
    else
        echo "[INFO] FTP (vsftpd) service is not running."
    fi
}

# Run startup checks
check_null_password_status
check_ssh_root_login
check_world_writable_files
check_ipv4_forwarding
check_vsftpd_status

# --- Helper functions ---
user_exists() { getent passwd "$1" >/dev/null 2>&1; }
group_exists() { getent group "$1" >/dev/null 2>&1; }

# ==============================================
# 1-3) File and System Search
# ==============================================
search_file() {
    read -r -p "Enter filename to search for (or Enter to skip): " filename
    [[ -z "$filename" ]] && { echo "[DEBUG] Skipped file search"; return; }

    if ! command -v locate >/dev/null 2>&1; then
        echo "[DEBUG] 'locate' command not found. Installing mlocate..."
        ${SUDO_CMD} apt update
        ${SUDO_CMD} apt install -y mlocate
    fi

    echo "[DEBUG] Updating locate database..."
    ${SUDO_CMD} updatedb

    echo "[DEBUG] Searching for '$filename' using locate..."
    results=$(locate "$filename" 2>/dev/null || true)
    if [[ -z "$results" ]]; then
        echo "No results found for '$filename'."
    else
        echo "$results"
    fi
}

handle_pups() {
    echo "[DEBUG] Scanning for potentially unwanted packages..."
    PUP_PATTERNS="game|example|demo|adware|pup|snap"

    pup_list=$(${SUDO_CMD} apt list --installed 2>/dev/null | grep -Ei "$PUP_PATTERNS" | awk -F/ '{print $1}' || true)

    if [[ -z "$pup_list" ]]; then
        echo "No potentially unwanted packages found."
        return
    fi

    echo "Potentially unwanted packages detected:"
    echo "----------------------------------------"
    echo "$pup_list"
    echo "----------------------------------------"

    read -r -p "Do you want to remove any? Enter package names (comma-separated) or press Enter to skip: " pkgs
    [[ -z "$pkgs" ]] && { echo "[DEBUG] Skipped removal"; return; }

    IFS=',' read -ra arr <<< "$pkgs"
    for pkg in "${arr[@]}"; do
        pkg=$(echo "$pkg" | xargs)
        if echo "$pup_list" | grep -qx "$pkg"; then
            ${SUDO_CMD} apt remove -y "$pkg" && echo "Removed $pkg"
        else
            echo "Package $pkg not found in PUP list. Skipped."
        fi
    done
}

search_high_permissions() {
    echo
    echo "[INFO] Searching for files with world-writable or overly permissive permissions..."
    read -r -p "Enter directory to scan (default '/'): " scan_dir
    scan_dir=${scan_dir:-/}

    read -r -p "Enter filename pattern to search for (optional, press Enter to skip): " pattern

    echo "[DEBUG] Scanning $scan_dir ... this may take a while."

    results=$($SUDO_CMD find "$scan_dir" -xdev -type f -perm -o=w \
        \( -path /proc -o -path /sys -o -path /dev \) -prune -o -print 2>/dev/null || true)

    if [[ -n "$pattern" ]]; then
        results=$(echo "$results" | grep -i "$pattern" || true)
    fi

    if [[ -z "$results" ]]; then
        echo "No files found matching criteria."
        last_high_perm_scan=""
    else
        echo "Files with world-writable permissions:"
        echo "--------------------------------------"
        echo "$results"
        echo "--------------------------------------"
        last_high_perm_scan="$results"

        read -r -p "Do you want to reset permissions of any of these files? (yes/no): " fix_ans
        if [[ "$fix_ans" == "yes" ]]; then
            read -r -p "Enter filenames (comma-separated) to chmod 644: " files
            IFS=',' read -ra arr <<< "$files"
            for f in "${arr[@]}"; do
                f=$(echo "$f" | xargs)
                if [[ -f "$f" ]]; then
                    ${SUDO_CMD} chmod 644 "$f" && echo "Permissions of $f set to 644."
                else
                    echo "File $f not found. Skipped."
                fi
            done
        fi
    fi
}

# ==============================================
# 4-13) User and Group Management
# ==============================================
list_users() {
    echo "--------------------------------------------"
    echo "System Users (UID ≥ 1000), Groups, Admin?"
    echo "--------------------------------------------"
    getent passwd | awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' | while read -r username; do
        groups_list=$(id -nG "$username" 2>/dev/null || echo "(none)")
        if id -nG "$username" 2>/dev/null | grep -qw "$ADMIN_GROUP"; then
            status="Admin"
        else
            status="User"
        fi
        printf "%-15s | %-40s | %-6s\n" "$username" "$groups_list" "$status"
    done
    echo "--------------------------------------------"
}

remove_admin() {
    read -r -p "Enter username to remove from '$ADMIN_GROUP' (or Enter to skip): " username
    [[ -z "$username" ]] && { echo "Skipped."; return; }
    if ! user_exists "$username"; then echo "User not found."; return; fi
    ${SUDO_CMD} gpasswd -d "$username" "$ADMIN_GROUP" && echo "Removed $username from $ADMIN_GROUP."
}

add_admin() {
    read -r -p "Enter username to add to '$ADMIN_GROUP' (or Enter to skip): " username
    [[ -z "$username" ]] && { echo "Skipped."; return; }
    if ! user_exists "$username"; then echo "User not found."; return; fi
    ${SUDO_CMD} usermod -aG "$ADMIN_GROUP" "$username" && echo "Added $username to $ADMIN_GROUP."
}

change_password() {
    read -r -p "Enter username to change password for (or Enter to skip): " username
    [[ -z "$username" ]] && { echo "Skipped."; return; }
    if ! user_exists "$username"; then echo "User not found."; return; fi
    ${SUDO_CMD} passwd "$username"
}

remove_from_group() {
    read -r -p "Enter username (or Enter to skip): " username
    [[ -z "$username" ]] && { echo "Skipped."; return; }
    read -r -p "Enter group name: " group
    [[ -z "$group" ]] && { echo "Skipped."; return; }
    if ! user_exists "$username" || ! group_exists "$group" ]; then echo "User or group not found."; return; fi
    ${SUDO_CMD} gpasswd -d "$username" "$group" && echo "Removed $username from $group."
}

add_to_group() {
    read -r -p "Enter username (or Enter to skip): " username
    [[ -z "$username" ]] && { echo "Skipped."; return; }
    read -r -p "Enter group name: " group
    [[ -z "$group" ]] && { echo "Skipped."; return; }
    if ! user_exists "$username"; then echo "User not found."; return; fi
    if ! group_exists "$group"; then
        ${SUDO_CMD} groupadd "$group"
        echo "[DEBUG] Created group $group"
    fi
    ${SUDO_CMD} usermod -aG "$group" "$username" && echo "Added $username to $group."
}

create_group() {
    read -r -p "Enter new group name (or Enter to skip): " groupname
    [[ -z "$groupname" ]] && { echo "Skipped."; return; }
    if group_exists "$groupname"; then
        echo "Group already exists."
    else
        ${SUDO_CMD} groupadd "$groupname" && echo "Created $groupname."
    fi
    read -r -p "Enter comma-separated usernames to add (or Enter to skip): " users
    [[ -z "$users" ]] && return
    IFS=',' read -ra arr <<< "$users"
    for u in "${arr[@]}"; do
        u=$(echo "$u" | xargs)
        if user_exists "$u"; then ${SUDO_CMD} usermod -aG "$groupname" "$u" && echo "Added $u to $groupname."; else echo "User $u does not exist. Skipped."; fi
    done
}

remove_group() {
    read -r -p "Enter group name to remove (or Enter to skip): " groupname
    [[ -z "$groupname" ]] && { echo "Skipped."; return; }
    if ! group_exists "$groupname"; then
        echo "Group not found."
        return
    fi
    read -r -p "Type 'yes' to confirm deletion: " confirm
    [[ "$confirm" == "yes" ]] && ${SUDO_CMD} groupdel "$groupname" && echo "Removed $groupname." || echo "Cancelled."
}

create_user() {
    read -r -p "Enter new username: " username
    [[ -z "$username" ]] && { echo "Skipped."; return; }
    ${SUDO_CMD} adduser "$username"
}

delete_user() {
    read -r -p "Enter username to delete: " username
    [[ -z "$username" ]] && { echo "Skipped."; return; }
    read -r -p "Type 'yes' to confirm deletion: " confirm
    [[ "$confirm" == "yes" ]] && ${SUDO_CMD} deluser --remove-home "$username" && echo "User deleted."
}

# ==============================================
# 14-19) System Management
# ==============================================
update_system() {
    ${SUDO_CMD} apt update && ${SUDO_CMD} apt upgrade -y
    echo "[DEBUG] System update completed."
}

set_min_password_sysctl() {
    local minlen
    read -r -p "Enter minimum password length to store via sysctl (numeric): " minlen
    [[ -z "$minlen" ]] && { echo "Skipped."; return; }
    if ! [[ "$minlen" =~ ^[0-9]+$ ]]; then
        echo "Invalid input; must be an integer. Skipping."
        return
    fi

    ${SUDO_CMD} sed -i '/^security.pass_min_len/d' /etc/sysctl.conf || true
    echo "security.pass_min_len = $minlen" | ${SUDO_CMD} tee -a /etc/sysctl.conf >/dev/null
    ${SUDO_CMD} sysctl -p >/dev/null 2>&1 || true

    echo "Minimum password length stored in sysctl (security.pass_min_len) = $minlen."
    echo "Note: This writes a sysctl key for your tooling; system PAM must be configured separately to enforce it."
}

toggle_service() {
    read -r -p "Enter service name (e.g., ssh): " service
    [[ -z "$service" ]] && { echo "Skipped."; return; }
    read -r -p "Enter 'enable' or 'disable': " action
    case "$action" in
        enable) ${SUDO_CMD} systemctl enable "$service"; ${SUDO_CMD} systemctl start "$service"; echo "Service $service enabled." ;;
        disable) ${SUDO_CMD} systemctl stop "$service"; ${SUDO_CMD} systemctl disable "$service"; echo "Service $service disabled." ;;
        *) echo "Invalid action. Skipped." ;;
    esac
}

remove_program() {
    read -r -p "Enter program/package name to remove: " prog
    [[ -z "$prog" ]] && { echo "Skipped."; return; }
    ${SUDO_CMD} apt remove -y "$prog" && echo "Program $prog removed."
}

manage_firewall() {
    ${SUDO_CMD} ufw status
    read -r -p "Do you want to enable the firewall? (yes/no): " ans
    [[ "$ans" == "yes" ]] && ${SUDO_CMD} ufw enable && echo "Firewall enabled."
}

edit_sysctl() {
    local file="/etc/sysctl.conf"
    ${SUDO_CMD} nano "$file"
}

# ==============================================
# 20-21) Null-Password Authentication Control
# ==============================================
disable_null_password_auth() {
    local file="/etc/pam.d/common-auth"
    local ts
    ts=$(date +%Y%m%d%H%M%S)
    local backup="${file}.bak.${ts}"

    echo
    echo "WARNING: modifying PAM configuration can lock you out."
    echo "This operation will create a backup: ${backup}"
    read -r -p "Type 'yes' to proceed with removing null-password authentication (or press Enter to cancel): " confirm
    [[ "$confirm" != "yes" ]] && { echo "Cancelled."; return; }

    if [[ ! -f "$file" ]]; then
        echo "Error: $file not found." >&2
        return 1
    fi

    ${SUDO_CMD} cp -a "$file" "$backup" && echo "Backup created at: ${backup}"

    echo
    echo "Current lines containing 'pam_unix' and 'nullok' (if any):"
    ${SUDO_CMD} grep -nE 'pam_unix.*nullok' "$file" || echo "None found."

    ${SUDO_CMD} sed -i -E 's/\bnullok(_secure)?\b//g; s/[[:space:]]{2,}/ /g; s/[[:space:]]+$//g' "$file" \
        && echo "Removed 'nullok' / 'nullok_secure' tokens from $file." \
        || { echo "Failed to modify $file"; ${SUDO_CMD} cp -a "$backup" "$file"; echo "Original restored."; return 1; }

    echo "$backup" | ${SUDO_CMD} tee /var/lib/null_password_backup.txt >/dev/null

    echo
    echo "Done. Please TEST authentication in a separate session before logging out."
}

restore_null_password_auth() {
    local file="/etc/pam.d/common-auth"
    local backup_file

    if [[ ! -f /var/lib/null_password_backup.txt ]]; then
        echo "No backup found. Cannot restore."
        return 1
    fi

    backup_file=$(${SUDO_CMD} cat /var/lib/null_password_backup.txt)
    if [[ ! -f "$backup_file" ]]; then
        echo "Backup file $backup_file not found. Cannot restore."
        return 1
    fi

    echo
    read -r -p "Type 'yes' to restore null-password authentication from backup: " confirm
    [[ "$confirm" != "yes" ]] && { echo "Cancelled."; return 1; }

    ${SUDO_CMD} cp -a "$backup_file" "$file" && echo "Restored null-password authentication from backup: $backup_file"
}

# ==============================================
# 22-24) GRUB Options
# ==============================================
edit_grub_cfg() {
    local grub_file="/boot/grub/grub.cfg"
    if [[ ! -f "$grub_file" ]]; then
        echo "[ERROR] $grub_file not found."
        return
    fi
    echo "WARNING: Editing grub.cfg incorrectly can make your system unbootable."
    read -r -p "Type 'yes' to proceed with editing $grub_file: " confirm
    [[ "$confirm" != "yes" ]] && { echo "Cancelled."; return; }
    ${SUDO_CMD} nano "$grub_file"
    echo "Editing complete."
}

edit_default_grub() {
    local grub_file="/etc/default/grub"
    if [[ ! -f "$grub_file" ]]; then
        echo "[ERROR] $grub_file not found."
        return
    fi
    echo "WARNING: Editing /etc/default/grub incorrectly can prevent proper boot configuration."
    read -r -p "Type 'yes' to proceed with editing $grub_file: " confirm
    [[ "$confirm" != "yes" ]] && { echo "Cancelled."; return; }
    ${SUDO_CMD} nano "$grub_file"
    echo "Editing complete."
    echo "Remember to run 'sudo update-grub' after saving changes."
}

update_grub() {
    echo "Running 'sudo update-grub'..."
    ${SUDO_CMD} update-grub && echo "GRUB update completed successfully."
}

# ==============================================
# 25-30) Additional Options
# ==============================================
chmod_600_file() {
    read -r -p "Enter full path to file to chmod 600 (or Enter to skip): " file
    [[ -z "$file" ]] && { echo "Skipped."; return; }
    if [[ -f "$file" ]]; then
        PERM_BACKUP["$file"]=$(${SUDO_CMD} stat -c "%a" "$file")
        ${SUDO_CMD} chmod 600 "$file" && echo "Permissions of $file set to 600."
    else
        echo "File not found. Skipped."
    fi
}

chmod_640_file() {
    read -r -p "Enter full path to file to chmod 640 (or Enter to skip): " file
    [[ -z "$file" ]] && { echo "Skipped."; return; }
    if [[ -f "$file" ]]; then
        PERM_BACKUP["$file"]=$(${SUDO_CMD} stat -c "%a" "$file")
        ${SUDO_CMD} chmod 640 "$file" && echo "Permissions of $file set to 640."
    else
        echo "File not found. Skipped."
    fi
}

reverse_chmod_changes() {
    if [[ ${#PERM_BACKUP[@]} -eq 0 ]]; then
        echo "No chmod changes have been made yet."
        return
    fi

    echo "Reversing previously changed file permissions..."
    for file in "${!PERM_BACKUP[@]}"; do
        if [[ -f "$file" ]]; then
            ${SUDO_CMD} chmod "${PERM_BACKUP[$file]}" "$file" && echo "Restored $file to ${PERM_BACKUP[$file]}"
        else
            echo "File $file no longer exists. Skipped."
        fi
    done

    PERM_BACKUP=()
    echo "All reversible chmod changes restored."
}

toggle_ssh_root_login() {
    local sshd_file="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_file" ]]; then
        echo "sshd_config not found. Cannot modify SSH settings."
        return
    fi

    root_status=$(grep -Ei '^PermitRootLogin' "$sshd_file" | awk '{print $2}')
    root_status=${root_status:-prohibit-password}

    echo "Current SSH root login status: $root_status"
    read -r -p "Do you want to 'enable' or 'disable' root login via SSH? (Enter to skip): " action
    [[ -z "$action" ]] && { echo "Skipped."; return; }

    case "$action" in
        enable)
            ${SUDO_CMD} sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' "$sshd_file"
            ${SUDO_CMD} systemctl restart ssh
            echo "SSH root login ENABLED and service restarted." ;;
        disable)
            ${SUDO_CMD} sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$sshd_file"
            # restart safely (ignore failure)
            ${SUDO_CMD} systemctl restart ssh || true
            echo "SSH root login DISABLED and service restarted." ;;
        *)
            echo "Invalid input. Skipped." ;;
    esac
}

enable_automatic_updates() {
    if ! command -v unattended-upgrades >/dev/null 2>&1; then
        echo "'unattended-upgrades' not installed. Installing..."
        ${SUDO_CMD} apt update
        ${SUDO_CMD} apt install -y unattended-upgrades apt-listchanges
    fi

    echo "[DEBUG] Configuring automatic daily updates..."
    ${SUDO_CMD} dpkg-reconfigure -plow unattended-upgrades || true

    # Force daily update schedule
    ${SUDO_CMD} bash -c 'cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF'

    echo "Automatic updates are now enabled and scheduled DAILY."
}

list_active_services() {
    echo "Active systemd services:"
    ${SUDO_CMD} systemctl list-units --type=service --state=active
}

# ==============================================
# 31-41) New System & Security Options
# ==============================================
apt_autoremove() {
    echo "[INFO] Running 'sudo apt autoremove'..."
    ${SUDO_CMD} apt autoremove -y
    echo "Autoremove completed."
}

install_program() {
    read -r -p "Enter package/program name to install (or Enter to skip): " pkg
    [[ -z "$pkg" ]] && { echo "Skipped."; return; }
    ${SUDO_CMD} apt update
    ${SUDO_CMD} apt install -y "$pkg" && echo "$pkg installed successfully."
}

search_games() {
    echo "[INFO] Searching for installed games..."
    GAME_PATTERNS="game|solitaire|sudoku|chess|minesweeper|puzzle|card|tetris|arcade|adventure|pacman|mahjong|snake|2048"
    ${SUDO_CMD} apt list --installed 2>/dev/null | grep -Ei "$GAME_PATTERNS" | awk -F/ '{print $1}' || echo "No games found."
}

chmod_shadow_640() {
    if [[ -f "/etc/shadow" ]]; then
        ${SUDO_CMD} chmod 640 /etc/shadow && echo "Permissions of /etc/shadow set to 640."
    else
        echo "/etc/shadow not found."
    fi
}

enable_tcp_syn_cookies() {
    echo "Enabling IPv4 TCP SYN cookies..."
    ${SUDO_CMD} sysctl -w net.ipv4.tcp_syncookies=1 || true
    ${SUDO_CMD} sed -i '/^net.ipv4.tcp_syncookies/d' /etc/sysctl.conf || true
    echo "net.ipv4.tcp_syncookies = 1" | ${SUDO_CMD} tee -a /etc/sysctl.conf >/dev/null
    echo "TCP SYN cookies enabled and made persistent."
}

# Account lockout (PAM faillock) configuration (option 37)
configure_account_lockout() {
    local config_file="/usr/share/pam-configs/faillock"
    echo "WARNING: This will configure account lockout for failed login attempts."
    read -r -p "Type 'yes' to proceed (or press Enter to cancel): " confirm
    [[ "$confirm" != "yes" ]] && { echo "Cancelled."; return; }

    read -r -p "Maximum failed attempts before lockout (default 3): " deny
    deny=${deny:-3}
    read -r -p "Unlock time in seconds (default 900 = 15 min): " unlock_time
    unlock_time=${unlock_time:-900}
    read -r -p "Fail interval seconds (default 900 = 15 min): " fail_interval
    fail_interval=${fail_interval:-900}

    echo "Creating/updating $config_file..."
    ${SUDO_CMD} tee "$config_file" >/dev/null <<EOL
Name: faillock
Default: yes
Priority: 900
Auth-Type: Primary
Auth:
    required pam_faillock.so preauth silent audit deny=$deny unlock_time=$unlock_time fail_interval=$fail_interval
    sufficient pam_unix.so
Account-Type: System
Account:
    required pam_faillock.so
EOL

    echo "Applying PAM configuration..."
    ${SUDO_CMD} pam-auth-update --package || true

    echo "Account lockout policy applied: deny=$deny, unlock_time=$unlock_time, fail_interval=$fail_interval."
}

# Disable IPv4 forwarding (option 38)
disable_ipv4_forwarding() {
    echo "Disabling IPv4 forwarding..."
    ${SUDO_CMD} sysctl -w net.ipv4.ip_forward=0 || true
    ${SUDO_CMD} sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf || true
    echo "net.ipv4.ip_forward = 0" | ${SUDO_CMD} tee -a /etc/sysctl.conf >/dev/null
    echo "IPv4 forwarding disabled and persisted."
}

# Check nginx (option 39)
check_nginx_status() {
    if dpkg -l 2>/dev/null | grep -qw nginx; then
        echo "Nginx is installed."
        if systemctl is-active --quiet nginx 2>/dev/null; then
            echo "Nginx service is running."
        else
            echo "Nginx service is installed but NOT running."
        fi
    else
        echo "Nginx is not installed."
    fi
}

# Disable FTP vsftpd (option 40)
disable_vsftpd() {
    if systemctl is-active --quiet vsftpd 2>/dev/null; then
        ${SUDO_CMD} systemctl stop vsftpd
        ${SUDO_CMD} systemctl disable vsftpd
        echo "vsftpd service stopped and disabled."
    else
        echo "vsftpd is not running or not installed."
    fi
}

# ==============================================
# Replace previous netcat routine with the targeted working function (option 41)
# ==============================================
remove_netcat_backdoor() {
    echo "[INFO] Scanning for listening sockets owned by netcat (nc.traditional/nc)..."
    # Look for processes listening with nc/nc.traditional/ncat/netcat
    listening=$($SUDO_CMD ss -tlnp 2>/dev/null | grep -E "nc\.traditional|(^|\s)nc\b|ncat|netcat" || true)

    if [[ -z "$listening" ]]; then
        echo "[INFO] No netcat-like listening processes detected via ss."
    else
        echo "[WARNING] Detected netcat-like listening sockets/processes:"
        echo "$listening"
    fi

    read -r -p "Proceed to kill detected netcat processes and remove binary if present? (yes/no): " confirm
    [[ "$confirm" != "yes" ]] && { echo "Cancelled."; return; }

    # Kill processes (by name patterns)
    echo "[DEBUG] Killing processes matching nc.traditional, nc, ncat, netcat..."
    $SUDO_CMD pkill -f nc.traditional 2>/dev/null || true
    $SUDO_CMD pkill -f '\bnc\b' 2>/dev/null || true
    $SUDO_CMD pkill -f ncat 2>/dev/null || true
    $SUDO_CMD pkill -f netcat 2>/dev/null || true

    # Attempt to locate common netcat binaries and remove them
    candidates=("nc.traditional" "nc" "ncat" "netcat" "netcat-openbsd" "netcat-traditional")
    for name in "${candidates[@]}"; do
        path=$($SUDO_CMD which "$name" 2>/dev/null || true)
        if [[ -n "$path" && -f "$path" ]]; then
            echo "[DEBUG] Found binary: $path — removing..."
            $SUDO_CMD rm -f "$path" && echo "Removed $path" || echo "Failed to remove $path"
        fi
    done

    # Check for persistence in /etc/crontab and remove lines invoking netcat
    crontab_file="/etc/crontab"
    if [[ -f "$crontab_file" ]] && grep -qE "nc\.traditional|/usr/bin/nc|/usr/bin/netcat|/usr/bin/ncat|/bin/nc" "$crontab_file"; then
        echo "[WARNING] Found netcat invocation in $crontab_file. Removing lines..."
        $SUDO_CMD sed -i -E '/nc\.traditional|\/usr\/bin\/nc|\/usr\/bin\/netcat|\/usr\/bin\/ncat|\/bin\/nc/d' "$crontab_file" && echo "[DEBUG] Removed netcat lines from $crontab_file"
    else
        echo "[INFO] No netcat entries found in $crontab_file"
    fi

    # Also search common system locations for scripts referencing netcat (report only)
    echo "[INFO] Searching common locations for scripts referencing nc/ncat/netcat (reporting matches)..."
    $SUDO_CMD sh -c 'grep -RIlE "(^|[[:space:]])(nc|ncat|netcat)([[:space:]]|$|-l|-e)" /etc /usr /var 2>/dev/null || true' | while read -r file; do
        echo "Potential netcat usage found in: $file"
    done

    echo "[INFO] Netcat cleanup finished. Review reported files for further investigation."
}

# ==============================================
# Main Menu
# ==============================================
main_menu() {
    while true; do
        echo
        echo "========== System & User Management Tool =========="
        echo "1) Search for a file (locate-based)"
        echo "2) Search/remove PUPs"
        echo "3) Search for files with unusually high permissions"
        echo
        echo "4) List users and admin status"
        echo "5) Remove user from admin group"
        echo "6) Add user to admin group"
        echo "7) Change a user password"
        echo "8) Remove user from a group"
        echo "9) Add user to a group"
        echo "10) Create a new group and add users"
        echo "11) Remove an existing group"
        echo "12) Create a new user"
        echo "13) Delete a user"
        echo
        echo "14) Update system (apt update & upgrade)"
        echo "15) Set minimum password length via sysctl"
        echo "16) Enable/disable a service"
        echo "17) Remove a program"
        echo "18) Check and enable firewall"
        echo "19) View/edit sysctl.conf"
        echo
        echo "20) Disable null-password authentication"
        echo "21) Restore null-password authentication from backup"
        echo
        echo "22) Edit /boot/grub/grub.cfg"
        echo "23) Edit /etc/default/grub"
        echo "24) Update GRUB"
        echo
        echo "25) Set file permissions to 600"
        echo "26) Set file permissions to 640"
        echo "27) Reverse chmod 600/640 changes"
        echo "28) Check if SSH root login is enabled"
        echo "29) Enable/disable SSH root login"
        echo "30) Enable automatic updates (Ubuntu, daily)"
        echo "31) List active systemd services"
        echo "32) Run 'sudo apt autoremove'"
        echo "33) Install a program/package"
        echo "34) Search for installed games"
        echo "35) Set /etc/shadow permissions to 640"
        echo "36) Enable IPv4 TCP SYN cookies"
        echo "37) Configure account lockout (PAM faillock)"
        echo "38) Disable IPv4 forwarding"
        echo "39) Check Nginx installation & status"
        echo "40) Disable FTP (vsftpd)"
        echo "41) Remove netcat backdoor (kill & remove common packages)"
        echo
        echo "0) Exit"
        echo "=================================================="

        read -r -p "Select an option: " choice
        choice="${choice//[$'\r\n\t ']}"

        case "$choice" in
            1) search_file ;;
            2) handle_pups ;;
            3) search_high_permissions ;;
            4) list_users ;;
            5) remove_admin ;;
            6) add_admin ;;
            7) change_password ;;
            8) remove_from_group ;;
            9) add_to_group ;;
            10) create_group ;;
            11) remove_group ;;
            12) create_user ;;
            13) delete_user ;;
            14) update_system ;;
            15) set_min_password_sysctl ;;
            16) toggle_service ;;
            17) remove_program ;;
            18) manage_firewall ;;
            19) edit_sysctl ;;
            20) disable_null_password_auth ;;
            21) restore_null_password_auth ;;
            22) edit_grub_cfg ;;
            23) edit_default_grub ;;
            24) update_grub ;;
            25) chmod_600_file ;;
            26) chmod_640_file ;;
            27) reverse_chmod_changes ;;
            28) check_ssh_root_login ;;
            29) toggle_ssh_root_login ;;
            30) enable_automatic_updates ;;
            31) list_active_services ;;
            32) apt_autoremove ;;
            33) install_program ;;
            34) search_games ;;
            35) chmod_shadow_640 ;;
            36) enable_tcp_syn_cookies ;;
            37) configure_account_lockout ;;
            38) disable_ipv4_forwarding ;;
            39) check_nginx_status ;;
            40) disable_vsftpd ;;
            41) remove_netcat_backdoor ;;
            0) echo "[DEBUG] Exiting program"; break ;;
            *) echo "Invalid option. Try again." ;;
        esac
    done
}

# --- Run Main Menu ---
main_menu

