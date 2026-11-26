# Linux Server Hardening & Security Audit

A lightweight, zero-dependency Bash auditing script designed for Systems Administrators and Security Engineers to quickly assess the security posture of Linux servers (**Debian/Ubuntu** and **RHEL/Rocky/AlmaLinux**).

## Key Features

- **Zero External Dependencies:** Runs using standard POSIX/Linux utilities (`awk`, `grep`, `stat`, `sysctl`, `ss`).
- **SSH Daemon Hardening Checks:** Verifies `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `MaxAuthTries`, and `X11Forwarding`.
- **Host Firewall Verification:** Automatically detects active rules across `UFW`, `firewalld`, `nftables`, and `iptables`.
- **Critical File & Identity Integrity:** Audits permissions on `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, and `sshd_config`, plus checks for unauthorized `UID 0` accounts.
- **Kernel Network Hardening (`sysctl`):** Validates anti-spoofing (`rp_filter`), SYN flood protection (`tcp_syncookies`), IP forwarding, and ICMP redirect policies.
- **Exposure & Patch Posture:** Lists sockets bound to all network interfaces (`0.0.0.0` / `::`) and checks for pending package updates (`apt` / `dnf`).
- **Automation-Ready:** Returns deterministic exit codes (`0` = clean, `1` = warnings, `2` = critical findings) and supports exporting results to Markdown (`-o`).

## Quick Start

```bash
git clone [https://github.com/eltongremi/linux-server-hardening-audit.git](https://github.com/eltongremi/linux-server-hardening-audit.git)
cd linux-server-hardening-audit
chmod +x audit.sh
sudo ./audit.sh

## Export Report to Markdown

```bash
sudo ./audit.sh -o security-audit-report.md
