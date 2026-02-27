# Lynis Security Hardening Report Generator

A single Python script that:
1. Installs **Lynis** automatically (if not present)
2. Runs a full **Lynis audit**
3. Collects **system data** directly from the OS (users, services, ports, firewall, sysctl, SSH config, disk, cron, login history, etc.)
4. Generates a professional **self-contained HTML report**

## Usage

```bash
# Full run (recommended — run as root for complete data)
sudo python3 generate-report.py

# Use existing Lynis .dat file (no scan)
sudo python3 generate-report.py --report /path/to/report.dat --report-only

# Custom output path and logo
sudo python3 generate-report.py --output /tmp/report.html --logo /path/to/logo.png
```

## Requirements

- Python 3.8+
- Linux system (Debian/Ubuntu/RHEL/Arch/Alpine)
- Root privileges recommended (for complete data collection)

## Report Sections

### Machine Information tab
- System overview (hostname, OS, kernel, CPU, RAM, uptime)
- Security controls (Secure Boot, TPM, LUKS, AppArmor/SELinux, NTP)
- Users & authentication (password state, SSH keys, UID 0 check)
- Password aging policy
- Services (all systemd units with status and enablement)
- Network & open ports (from `ss -tulpen`)
- Firewall rules (nftables, iptables, UFW)
- Filesystem & storage (disk usage, mounts, permissions, SUID/SGID)
- Hardening baseline (sysctl compliance, SSH config, audit rules)
- Login activity (successful and failed logins)
- Scheduled tasks (cron, systemd timers)
- Critical configuration files (content preview)

### Lynis Scan Results tab
- Hardening score ring
- Priority action plan (P1/P2/P3)
- Key warnings
- Full test results (filterable/searchable)
- Recommendations
- Skipped tests

## Output

The report is saved to `results/report_<hostname>_<date>.html` by default.
