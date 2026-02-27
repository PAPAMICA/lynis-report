#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_DIR="${SCRIPT_DIR}/reports"
RESULTS_DIR="${SCRIPT_DIR}/results"
DATE_STAMP="$(date +%F)"
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname || echo "unknown-host")"
REPORT_FILE="${REPORTS_DIR}/report_${HOSTNAME_SHORT}_${DATE_STAMP}.dat"
LOG_FILE="${RESULTS_DIR}/lynis_${HOSTNAME_SHORT}_${DATE_STAMP}.log"
SYSTEM_SNAPSHOT_FILE="${REPORTS_DIR}/system_${HOSTNAME_SHORT}_${DATE_STAMP}.dat"

require_sudo() {
  if command -v sudo >/dev/null 2>&1; then
    echo "sudo"
  else
    echo ""
  fi
}

detect_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  elif command -v zypper >/dev/null 2>&1; then
    echo "zypper"
  elif command -v pacman >/dev/null 2>&1; then
    echo "pacman"
  elif command -v apk >/dev/null 2>&1; then
    echo "apk"
  else
    echo "unknown"
  fi
}

install_lynis() {
  if command -v lynis >/dev/null 2>&1; then
    echo "[INFO] Lynis is already installed."
    return
  fi

  local as_root
  as_root="$(require_sudo)"
  echo "[INFO] Lynis not found. Attempting installation..."

  if command -v apt-get >/dev/null 2>&1; then
    ${as_root} apt-get update
    ${as_root} apt-get install -y lynis
  elif command -v dnf >/dev/null 2>&1; then
    ${as_root} dnf install -y lynis
  elif command -v yum >/dev/null 2>&1; then
    ${as_root} yum install -y lynis
  elif command -v zypper >/dev/null 2>&1; then
    ${as_root} zypper --non-interactive install lynis
  elif command -v pacman >/dev/null 2>&1; then
    ${as_root} pacman -Sy --noconfirm lynis
  elif command -v apk >/dev/null 2>&1; then
    ${as_root} apk add --no-cache lynis
  elif command -v emerge >/dev/null 2>&1; then
    ${as_root} emerge --ask=n app-admin/lynis
  else
    echo "[ERROR] Unsupported Linux distribution: no known package manager found."
    echo "[ERROR] Please install Lynis manually and run this script again."
    exit 1
  fi

  if ! command -v lynis >/dev/null 2>&1; then
    echo "[ERROR] Lynis installation failed."
    exit 1
  fi
}


run_audit() {
  local as_root
  as_root="$(require_sudo)"

  mkdir -p "${REPORTS_DIR}" "${RESULTS_DIR}"
  echo "[INFO] Running the most complete Lynis audit profile..."
  echo "[INFO] Report file: ${REPORT_FILE}"
  echo "[INFO] Log file: ${LOG_FILE}"

  # Do not use --quick: this keeps the scan as complete as possible.
  # Running through sudo/root improves coverage on most systems.
  ${as_root} lynis audit system \
    --report-file "${REPORT_FILE}" \
    --logfile "${LOG_FILE}"

  echo "[INFO] Audit completed successfully."
  echo "[INFO] Generated report: ${REPORT_FILE}"
}


collect_system_snapshot() {
  local as_root
  as_root="$(require_sudo)"

  mkdir -p "${REPORTS_DIR}" "${RESULTS_DIR}"
  echo "[INFO] Collecting additional system snapshot..."
  echo "[INFO] System snapshot file: ${SYSTEM_SNAPSHOT_FILE}"

  local timezone
  local keyboard_layout
  local keyboard_model
  local locale_value
  local package_manager
  local secure_boot_status
  local tpm_status
  local encryption_summary

  timezone="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
  if [[ -z "${timezone}" ]]; then
    timezone="$(readlink -f /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||' || true)"
  fi
  [[ -z "${timezone}" ]] && timezone="Unknown"

  keyboard_layout="$(localectl status 2>/dev/null | awk -F: '/X11 Layout/{gsub(/^[ \t]+/, "", $2); print $2; exit}')"
  keyboard_model="$(localectl status 2>/dev/null | awk -F: '/X11 Model/{gsub(/^[ \t]+/, "", $2); print $2; exit}')"
  locale_value="$(localectl status 2>/dev/null | awk -F: '/System Locale/{gsub(/^[ \t]+/, "", $2); print $2; exit}')"

  [[ -z "${keyboard_layout}" ]] && keyboard_layout="Unknown"
  [[ -z "${keyboard_model}" ]] && keyboard_model="Unknown"
  [[ -z "${locale_value}" ]] && locale_value="${LANG:-Unknown}"
  package_manager="$(detect_package_manager)"

  secure_boot_status="Unknown"
  if command -v mokutil >/dev/null 2>&1; then
    secure_boot_status="$(mokutil --sb-state 2>/dev/null | tr -s ' ' | sed 's/[[:space:]]*$//')"
    [[ -z "${secure_boot_status}" ]] && secure_boot_status="Unknown"
  elif [[ -d /sys/firmware/efi ]]; then
    secure_boot_status="UEFI detected (Secure Boot state unavailable without mokutil)"
  else
    secure_boot_status="Legacy/BIOS mode (UEFI not detected)"
  fi

  if [[ -c /dev/tpm0 || -c /dev/tpmrm0 ]]; then
    tpm_status="TPM device present"
  else
    tpm_status="TPM device not detected"
  fi

  encryption_summary="$(lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null | awk '/crypt/ {found=1} {print}' | tr '\n' ';' | sed 's/;*$//')"
  [[ -z "${encryption_summary}" ]] && encryption_summary="Unknown"

  {
    echo "# Additional system snapshot"
    echo "snapshot_version=1"
    echo "snapshot_datetime=$(date '+%Y-%m-%d %H:%M:%S')"
    echo "hostname=${HOSTNAME_SHORT}"
    echo "timezone=${timezone}"
    echo "keyboard_layout=${keyboard_layout}"
    echo "keyboard_model=${keyboard_model}"
    echo "system_locale=${locale_value}"
    echo "lang=${LANG:-Unknown}"
    echo "shell=${SHELL:-Unknown}"
    echo "whoami=$(id -un 2>/dev/null || echo unknown)"
    echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
    echo "package_manager=${package_manager}"
    echo "secure_boot_status=${secure_boot_status}"
    echo "tpm_status=${tpm_status}"
    echo "encryption_summary=${encryption_summary}"
    echo "uptime_human=$(uptime -p 2>/dev/null || echo unknown)"
    echo "load_average=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo unknown)"
    echo "memory_total_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo unknown)"

    awk -F: '($3 >= 1000 || $3 == 0) {print "real_user[]="$1","$3","$4","$6","$7}' /etc/passwd 2>/dev/null
    awk -F: '{print "all_user[]="$1","$3","$4","$6","$7}' /etc/passwd 2>/dev/null

    for directory in /etc /home /root /var/log /tmp /var/tmp /etc/ssh /etc/sudoers.d; do
      if [[ -e "${directory}" ]]; then
        echo "important_path[]=$(stat -c '%a,%U,%G,%n' "${directory}" 2>/dev/null || echo "unknown,unknown,unknown,${directory}")"
      fi
    done

    python3 - <<'PY'
from pathlib import Path
import os
import pwd
import grp

FILES = [
    "/etc/motd",
    "/etc/issue",
    "/etc/issue.net",
    "/etc/ssh/sshd_config",
    "/etc/login.defs",
    "/etc/pam.d/common-password",
    "/etc/pam.d/sshd",
    "/etc/sudoers",
    "/etc/security/limits.conf",
    "/etc/audit/auditd.conf",
    "/etc/rsyslog.conf",
    "/etc/sysctl.conf",
]

MAX_PREVIEW = 1600

def one_line(value: str) -> str:
    return " ".join(value.replace("\r", "\n").splitlines())

for file_path in FILES:
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        print(f"important_file[]={file_path}|present=no")
        continue
    try:
        st = path.stat()
        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
        mode = oct(st.st_mode & 0o777).replace("0o", "")
        content = path.read_text(encoding="utf-8", errors="replace")
        preview = one_line(content[:MAX_PREVIEW])
        if len(content) > MAX_PREVIEW:
            preview += " ...[truncated]"
        print(
            "important_file[]="
            + f"{file_path}|present=yes|mode={mode}|owner={owner}|group={group}|size={st.st_size}|preview={preview}"
        )
    except Exception as exc:
        print(f"important_file[]={file_path}|present=error|error={str(exc)}")
PY

    findmnt -rn -o TARGET,FSTYPE,OPTIONS 2>/dev/null | awk '{print "mount_info[]="$0}'
    ss -tulpen 2>/dev/null | awk 'NR>1 {print "open_port[]="$0}'
    systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print "running_service_full[]="$1}'
    systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | awk '{
      unit=$1; load=$2; active=$3; sub=$4;
      $1=""; $2=""; $3=""; $4="";
      desc=$0; gsub(/^[ \t]+/, "", desc);
      print "service_status[]=" unit "|" load "|" active "|" sub "|" desc
    }'
    systemctl list-unit-files --type=service --no-pager --no-legend 2>/dev/null | awk '{
      print "service_enablement[]=" $1 "|" $2
    }'

    for key in \
      kernel.kptr_restrict kernel.modules_disabled kernel.sysrq kernel.unprivileged_bpf_disabled \
      net.core.bpf_jit_harden net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians \
      fs.protected_fifos fs.protected_regular fs.protected_symlinks fs.suid_dumpable ; do
      echo "security_sysctl[]=${key}=$(sysctl -n "${key}" 2>/dev/null || echo unavailable)"
    done

    if command -v sshd >/dev/null 2>&1; then
      sshd -T 2>/dev/null | awk '{print "sshd_effective[]="$0}'
    fi

    if command -v nft >/dev/null 2>&1; then
      nft list ruleset 2>/dev/null | awk 'NR<=500 {print "firewall_rule_nft[]="$0}'
    fi
    if command -v iptables-save >/dev/null 2>&1; then
      iptables-save 2>/dev/null | awk 'NR<=500 {print "firewall_rule_iptables[]="$0}'
    fi

    for target in /etc /usr/local /home /var/www; do
      if [[ -d "${target}" ]]; then
        find "${target}" -xdev -type f -perm -0002 2>/dev/null | awk 'NR<=300 {print "world_writable_file[]="$0}'
      fi
    done

    find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | awk 'NR<=500 {print "suid_sgid_file[]="$0}'

    if [[ -d /etc/ssl/certs ]] && command -v openssl >/dev/null 2>&1; then
      find /etc/ssl/certs -maxdepth 1 -type f \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | awk 'NR<=120 {print}' | while IFS= read -r cert_file; do
        cert_meta="$(openssl x509 -in "${cert_file}" -noout -subject -enddate 2>/dev/null | tr '\n' ';' | sed 's/;*$//')"
        [[ -n "${cert_meta}" ]] && echo "cert_expiry[]=${cert_file}|${cert_meta}"
      done
    fi

    case "${package_manager}" in
      apt)
        apt list --upgradable 2>/dev/null | awk 'NR>1 {print "upgradeable_package[]="$0}'
        ;;
      dnf)
        dnf check-update --refresh 2>/dev/null | awk 'NF>=3 && $1 !~ /Last/ && $1 !~ /^Obsoleting/ {print "upgradeable_package[]="$0}'
        ;;
      yum)
        yum check-update 2>/dev/null | awk 'NF>=3 && $1 !~ /^Loaded/ {print "upgradeable_package[]="$0}'
        ;;
      zypper)
        zypper --no-refresh list-updates 2>/dev/null | awk 'NR>2 {print "upgradeable_package[]="$0}'
        ;;
      pacman)
        pacman -Qu 2>/dev/null | awk '{print "upgradeable_package[]="$0}'
        ;;
      apk)
        apk version -l '<' 2>/dev/null | awk '{print "upgradeable_package[]="$0}'
        ;;
    esac
  } > "${SYSTEM_SNAPSHOT_FILE}"

  # Enrich with sudoers checks when possible.
  if [[ -n "${as_root}" ]]; then
    ${as_root} sh -c "awk -F: '(\$2 ~ /^!|^\\*$/) {print \"locked_user[]=\"\$1}' /etc/shadow 2>/dev/null" >> "${SYSTEM_SNAPSHOT_FILE}" || true
    ${as_root} python3 - <<'PY' >> "${SYSTEM_SNAPSHOT_FILE}" || true
import grp
import pwd
import subprocess
from pathlib import Path


def parse_sshd_effective():
    data = {}
    try:
        out = subprocess.run(["sshd", "-T"], capture_output=True, text=True, check=False).stdout
    except Exception:
        return data
    for raw in out.splitlines():
        line = raw.strip()
        if not line or " " not in line:
            continue
        key, value = line.split(" ", 1)
        data[key.lower()] = value.strip()
    return data


def split_list(value: str):
    if not value:
        return set()
    return {item.strip() for item in value.split() if item.strip()}


def user_groups(username: str):
    out = set()
    try:
        primary_gid = pwd.getpwnam(username).pw_gid
        out.add(grp.getgrgid(primary_gid).gr_name)
    except Exception:
        pass
    for g in grp.getgrall():
        if username in g.gr_mem:
            out.add(g.gr_name)
    return out


def read_shadow_lock_state():
    state = {}
    shadow = Path("/etc/shadow")
    if not shadow.exists():
        return state
    for raw in shadow.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = raw.split(":")
        if len(parts) < 2:
            continue
        user, hash_value = parts[0], parts[1]
        if hash_value in ("", "!", "*", "!!") or hash_value.startswith("!"):
            state[user] = "locked"
        else:
            state[user] = "set"
    return state


def is_shell_login_allowed(shell_path: str):
    blocked = {
        "/usr/sbin/nologin",
        "/sbin/nologin",
        "/bin/false",
        "/usr/bin/false",
        "nologin",
        "false",
    }
    return shell_path not in blocked


def read_authorized_keys(home_dir: str):
    key_files = [
        Path(home_dir) / ".ssh" / "authorized_keys",
        Path(home_dir) / ".ssh" / "authorized_keys2",
    ]
    key_summaries = []
    count = 0
    for key_file in key_files:
        if not key_file.exists() or not key_file.is_file():
            continue
        try:
            lines = key_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for line in lines:
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            count += 1
            parts = cleaned.split()
            key_type = parts[0] if len(parts) > 0 else "unknown"
            key_comment = parts[2] if len(parts) > 2 else ""
            short = f"{key_type}:{key_comment}" if key_comment else key_type
            key_summaries.append(short)
            if len(key_summaries) >= 5:
                break
        if len(key_summaries) >= 5:
            break
    return count, ", ".join(key_summaries) if key_summaries else "none"


sshd = parse_sshd_effective()
allow_users = split_list(sshd.get("allowusers", ""))
deny_users = split_list(sshd.get("denyusers", ""))
allow_groups = split_list(sshd.get("allowgroups", ""))
deny_groups = split_list(sshd.get("denygroups", ""))
permit_root_login = sshd.get("permitrootlogin", "prohibit-password").lower()
pubkey_auth = sshd.get("pubkeyauthentication", "yes").lower() == "yes"
password_auth = sshd.get("passwordauthentication", "yes").lower() == "yes"
kbd_auth = sshd.get("kbdinteractiveauthentication", "no").lower() == "yes"
shadow_state = read_shadow_lock_state()

for pw in pwd.getpwall():
    if pw.pw_uid < 1000 and pw.pw_uid != 0:
        continue
    username = pw.pw_name
    shell = pw.pw_shell or "unknown"
    groups = user_groups(username)
    shell_allowed = is_shell_login_allowed(shell)
    passwd_state = shadow_state.get(username, "unknown")

    denied_by_user = username in deny_users
    denied_by_group = bool(deny_groups.intersection(groups))
    allowed_by_user = (not allow_users) or (username in allow_users)
    allowed_by_group = (not allow_groups) or bool(allow_groups.intersection(groups))
    ssh_access = shell_allowed and allowed_by_user and allowed_by_group and not denied_by_user and not denied_by_group

    methods = []
    key_count, key_preview = read_authorized_keys(pw.pw_dir)
    if ssh_access and pubkey_auth and key_count > 0:
        methods.append("ssh-publickey")
    if ssh_access and password_auth and passwd_state == "set":
        if username != "root" or permit_root_login == "yes":
            methods.append("ssh-password")
    if ssh_access and kbd_auth and passwd_state == "set":
        if username != "root" or permit_root_login == "yes":
            methods.append("ssh-keyboard-interactive")
    if shell_allowed and passwd_state == "set":
        methods.append("local-shell")

    if username == "root" and permit_root_login == "no":
        ssh_access = False
        methods = [m for m in methods if not m.startswith("ssh-")]

    groups_text = ",".join(sorted(groups)) if groups else "none"
    methods_text = ",".join(methods) if methods else "none"
    ssh_status = "yes" if ssh_access else "no"
    print(
        "user_auth[]="
        + f"{username}|uid={pw.pw_uid}|shell={shell}|password={passwd_state}|ssh_allowed={ssh_status}"
        + f"|methods={methods_text}|groups={groups_text}|authorized_keys={key_count}|key_preview={key_preview}"
    )
PY
  fi

  echo "[INFO] Additional system snapshot collected."
}

main() {
  local mode="${1:-full}"
  if [[ "$(uname -s)" != "Linux" ]]; then
    echo "[ERROR] This script must be run on Linux."
    exit 1
  fi

  if [[ "${mode}" == "--snapshot-only" ]]; then
    collect_system_snapshot
    return
  fi

  install_lynis
  run_audit
  collect_system_snapshot
}

main "$@"
