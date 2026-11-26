#!/usr/bin/env bash
# ==============================================================================
# Linux Server Hardening & Security Audit Script
# Author: Elton Gremi (https://eltongremi.github.io/)
# Description: Lightweight, zero-dependency security posture audit for Linux
#              servers (Debian/Ubuntu & RHEL-based). Checks SSH hardening,
#              firewall status, critical file permissions, kernel network
#              parameters, pending security updates, and listening ports.
# License: MIT
# ==============================================================================

set -uo pipefail

# --- Colors & Formatting ---
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# --- Counters & Report Storage ---
PASS_COUNT=0
WARN_COUNT=0
CRIT_COUNT=0
REPORT_FILE=""
REPORT_LINES=()

# --- Parse Arguments ---
usage() {
    echo "Usage: $0 [-o report.md] [-h]"
    echo "  -o <file>   Export audit results to a Markdown report file"
    echo "  -h          Show this help message"
    exit 0
}

while getopts "o:h" opt; do
    case "$opt" in
        o) REPORT_FILE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# --- Helper Functions ---
log_section() {
    echo -e "\n${CYAN}${BOLD}=== $1 ===${NC}"
    REPORT_LINES+=("" "## $1" "")
}

log_pass() {
    echo -e "  [${GREEN}PASS${NC}] $1"
    ((PASS_COUNT++))
    REPORT_LINES+=("- **[PASS]** $1")
}

log_warn() {
    echo -e "  [${YELLOW}WARN${NC}] $1"
    ((WARN_COUNT++))
    REPORT_LINES+=("- **[WARN]** $1")
}

log_crit() {
    echo -e "  [${RED}CRIT${NC}] $1"
    ((CRIT_COUNT++))
    REPORT_LINES+=("- **[CRIT]** $1")
}

# --- Header ---
HOSTNAME_STR=$(hostname -f 2>/dev/null || hostname)
OS_STR=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)
KERNEL_STR=$(uname -r)
DATE_STR=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

echo -e "${BOLD}================================================================${NC}"
echo -e "${BOLD} Linux Server Security Hardening Audit${NC}"
echo -e "${BOLD}================================================================${NC}"
echo -e " Hostname : ${HOSTNAME_STR}"
echo -e " OS       : ${OS_STR}"
echo -e " Kernel   : ${KERNEL_STR}"
echo -e " Date     : ${DATE_STR}"

if [[ $EUID -ne 0 ]]; then
    echo -e " ${YELLOW}Note: Running as non-root user. Some checks may be limited.${NC}"
fi

REPORT_LINES+=(
    "# Linux Server Hardening Audit Report"
    ""
    "- **Hostname:** \`${HOSTNAME_STR}\`"
    "- **Operating System:** ${OS_STR}"
    "- **Kernel:** \`${KERNEL_STR}\`"
    "- **Timestamp:** ${DATE_STR}"
)

# ==============================================================================
# 1. SSH Daemon Configuration Audit
# ==============================================================================
log_section "1. SSH Configuration"

SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ -r "$SSHD_CONFIG" ]]; then
    # Helper to extract effective sshd setting (last non-commented match or sshd -T)
    get_ssh_param() {
        local param="$1"
        if command -v sshd >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
            sshd -T 2>/dev/null | awk -v p="${param,,}" '$1 == p {print $2; exit}'
        else
            grep -Ei "^[[:space:]]*${param}[[:space:]]+" "$SSHD_CONFIG" | awk '{print $2}' | tail -n 1
        fi
    }

    ROOT_LOGIN=$(get_ssh_param "PermitRootLogin")
    case "${ROOT_LOGIN,,}" in
        no)
            log_pass "PermitRootLogin is disabled (no)"
            ;;
        prohibit-password|without-password)
            log_warn "PermitRootLogin allows key-based root login (${ROOT_LOGIN})"
            ;;
        "")
            log_warn "PermitRootLogin not explicitly set (verify distro default)"
            ;;
        *)
            log_crit "PermitRootLogin is enabled (${ROOT_LOGIN})"
            ;;
    esac

    PASS_AUTH=$(get_ssh_param "PasswordAuthentication")
    if [[ "${PASS_AUTH,,}" == "no" ]]; then
        log_pass "PasswordAuthentication is disabled (key-based auth enforced)"
    else
        log_warn "PasswordAuthentication is enabled or default (${PASS_AUTH:-yes})"
    fi

    EMPTY_PASS=$(get_ssh_param "PermitEmptyPasswords")
    if [[ "${EMPTY_PASS,,}" == "yes" ]]; then
        log_crit "PermitEmptyPasswords is enabled"
    else
        log_pass "PermitEmptyPasswords is disabled"
    fi

    MAX_TRIES=$(get_ssh_param "MaxAuthTries")
    if [[ -n "$MAX_TRIES" && "$MAX_TRIES" -le 4 ]]; then
        log_pass "MaxAuthTries is restricted (${MAX_TRIES})"
    else
        log_warn "MaxAuthTries is high or default (${MAX_TRIES:-6})"
    fi

    X11_FWD=$(get_ssh_param "X11Forwarding")
    if [[ "${X11_FWD,,}" == "no" ]]; then
        log_pass "X11Forwarding is disabled"
    else
        log_warn "X11Forwarding is enabled or default (${X11_FWD:-yes})"
    fi
else
    log_warn "Cannot read ${SSHD_CONFIG} (OpenSSH server not installed or insufficient permissions)"
fi

# ==============================================================================
# 2. Firewall & Network Filtering
# ==============================================================================
log_section "2. Firewall Status"

FW_ACTIVE=false

if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        log_pass "UFW firewall is active"
        FW_ACTIVE=true
    fi
fi

if [[ "$FW_ACTIVE" == false ]] && command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --state 2>/dev/null | grep -q "running"; then
        log_pass "firewalld service is running"
        FW_ACTIVE=true
    fi
fi

if [[ "$FW_ACTIVE" == false ]] && command -v nft >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -q "chain"; then
        log_pass "nftables ruleset is configured"
        FW_ACTIVE=true
    fi
fi

if [[ "$FW_ACTIVE" == false ]] && command -v iptables >/dev/null 2>&1; then
    RULE_COUNT=$(iptables -S 2>/dev/null | grep -cv "^-P " || true)
    if [[ "$RULE_COUNT" -gt 0 ]]; then
        log_pass "iptables has ${RULE_COUNT} active rules"
        FW_ACTIVE=true
    fi
fi

if [[ "$FW_ACTIVE" == false ]]; then
    log_crit "No active host firewall detected (UFW, firewalld, nftables, or iptables)"
fi

# ==============================================================================
# 3. Critical File Permissions
# ==============================================================================
log_section "3. Critical System File Permissions"

check_file_perm() {
    local filepath="$1"
    local expected_max="$2"
    if [[ -e "$filepath" ]]; then
        local actual_perm
        actual_perm=$(stat -c "%a" "$filepath" 2>/dev/null)
        if [[ "$actual_perm" -le "$expected_max" ]]; then
            log_pass "${filepath} permissions are secure (${actual_perm})"
        else
            log_crit "${filepath} permissions are too permissive (${actual_perm}, expected <= ${expected_max})"
        fi
    fi
}

check_file_perm "/etc/passwd" 644
check_file_perm "/etc/group" 644
check_file_perm "/etc/shadow" 640
check_file_perm "/etc/gshadow" 640
check_file_perm "/etc/ssh/sshd_config" 600

# Check for UID 0 accounts other than root
EXTRA_UID0=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
if [[ -z "$EXTRA_UID0" ]]; then
    log_pass "Only 'root' has UID 0"
else
    log_crit "Non-root account(s) with UID 0 detected: ${EXTRA_UID0}"
fi

# ==============================================================================
# 4. Kernel & Network Sysctl Hardening
# ==============================================================================
log_section "4. Kernel Network Parameters (sysctl)"

check_sysctl() {
    local key="$1"
    local expected="$2"
    local desc="$3"
    local current
    current=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    if [[ "$current" == "$expected" ]]; then
        log_pass "${desc} (${key}=${current})"
    else
        log_warn "${desc} is suboptimal (${key}=${current}, recommended=${expected})"
    fi
}

check_sysctl "net.ipv4.ip_forward" "0" "IPv4 forwarding disabled (unless acting as router/VPN)"
check_sysctl "net.ipv4.conf.all.accept_redirects" "0" "ICMP redirects ignored"
check_sysctl "net.ipv4.conf.all.send_redirects" "0" "ICMP send redirects disabled"
check_sysctl "net.ipv4.tcp_syncookies" "1" "TCP SYN cookies enabled (SYN flood protection)"
check_sysctl "net.ipv4.conf.all.rp_filter" "1" "Reverse path filtering enabled (anti-spoofing)"

# ==============================================================================
# 5. Listening Network Services & Security Updates
# ==============================================================================
log_section "5. Exposed Services & Patch Status"

if command -v ss >/dev/null 2>&1; then
    PUBLIC_PORTS=$(ss -tuln | awk 'NR>1 && ($5 ~ /^0\.0\.0\.0:/ || $5 ~ /^\*:/ || $5 ~ /^\[::\]:/) {print $1 " " $5}' | sort -u)
    if [[ -n "$PUBLIC_PORTS" ]]; then
        COUNT_PORTS=$(echo "$PUBLIC_PORTS" | wc -l)
        log_warn "${COUNT_PORTS} socket(s) listening on all interfaces (0.0.0.0 / ::) — verify firewall rules"
        while IFS= read -r line; do
            echo -e "         -> ${line}"
            REPORT_LINES+=("  - Exposed socket: \`${line}\`")
        done <<< "$PUBLIC_PORTS"
    else
        log_pass "No services bound indiscriminately to all interfaces"
    fi
fi

# Check pending updates (Debian/Ubuntu or RHEL/DNF)
if command -v apt-get >/dev/null 2>&1; then
    UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst " || true)
    if [[ "$UPDATES" -eq 0 ]]; then
        log_pass "System packages are up to date (apt)"
    else
        log_warn "${UPDATES} pending package upgrade(s) detected via apt"
    fi
elif command -v dnf >/dev/null 2>&1; then
    dnf check-update -q >/dev/null 2>&1
    EXIT_CODE=$?
    if [[ "$EXIT_CODE" -eq 0 ]]; then
        log_pass "System packages are up to date (dnf)"
    elif [[ "$EXIT_CODE" -eq 100 ]]; then
        log_warn "Pending package updates available via dnf"
    fi
fi

# ==============================================================================
# Summary & Exit Code
# ==============================================================================
echo -e "\n${BOLD}================================================================${NC}"
echo -e "${BOLD} Audit Summary:${NC}${GREEN}${PASS_COUNT} PASS${NC} | ${YELLOW}${WARN_COUNT} WARN${NC} \vert{}${RED}${CRIT_COUNT} CRIT${NC}"
echo -e "${BOLD}================================================================${NC}"

REPORT_LINES+=(
    ""
    "---"
    "## Summary"
    "- **PASS:** ${PASS_COUNT}"
    "- **WARN:** ${WARN_COUNT}"
    "- **CRIT:** ${CRIT_COUNT}"
)

if [[ -n "$REPORT_FILE" ]]; then
    printf "%s\n" "${REPORT_LINES[@]}" > "$REPORT_FILE"
    echo -e "Markdown report saved to: ${BOLD}${REPORT_FILE}${NC}"
fi

if [[ "$CRIT_COUNT" -gt 0 ]]; then
    exit 2
elif [[ "$WARN_COUNT" -gt 0 ]]; then
    exit 1
else
    exit 0
fi
