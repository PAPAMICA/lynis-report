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
OPENSCAP_SNAPSHOT_FILE="${REPORTS_DIR}/openscap_${HOSTNAME_SHORT}_${DATE_STAMP}.dat"
OPENSCAP_RESULT_XML="${RESULTS_DIR}/openscap_${HOSTNAME_SHORT}_${DATE_STAMP}.xml"
OPENSCAP_REPORT_HTML="${RESULTS_DIR}/openscap_${HOSTNAME_SHORT}_${DATE_STAMP}.html"

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

install_openscap() {
  if command -v oscap >/dev/null 2>&1; then
    echo "[INFO] OpenSCAP is already installed."
    return
  fi

  local as_root
  as_root="$(require_sudo)"
  echo "[INFO] OpenSCAP not found. Attempting installation..."

  if command -v apt-get >/dev/null 2>&1; then
    ${as_root} apt-get update
    ${as_root} apt-get install -y openscap-scanner ssg-debderived || ${as_root} apt-get install -y openscap-scanner
  elif command -v dnf >/dev/null 2>&1; then
    ${as_root} dnf install -y openscap-scanner scap-security-guide
  elif command -v yum >/dev/null 2>&1; then
    ${as_root} yum install -y openscap-scanner scap-security-guide
  elif command -v zypper >/dev/null 2>&1; then
    ${as_root} zypper --non-interactive install openscap-utils scap-security-guide
  elif command -v pacman >/dev/null 2>&1; then
    ${as_root} pacman -Sy --noconfirm openscap
  elif command -v apk >/dev/null 2>&1; then
    ${as_root} apk add --no-cache openscap-scanner
  else
    echo "[ERROR] Unsupported Linux distribution: no known package manager found."
    echo "[ERROR] Please install OpenSCAP manually and run this script again."
    exit 1
  fi

  if ! command -v oscap >/dev/null 2>&1; then
    echo "[ERROR] OpenSCAP installation failed."
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

find_openscap_datastream() {
  local candidates=(
    "/usr/share/xml/scap/ssg/content/ssg-debian-ds.xml"
    "/usr/share/xml/scap/ssg/content/ssg-ubuntu-ds.xml"
    "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
    "/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml"
    "/usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml"
  )
  local path
  for path in "${candidates[@]}"; do
    if [[ -f "${path}" ]]; then
      echo "${path}"
      return 0
    fi
  done
  return 1
}

run_openscap_scan() {
  local as_root
  as_root="$(require_sudo)"

  mkdir -p "${REPORTS_DIR}" "${RESULTS_DIR}"
  local datastream
  datastream="$(find_openscap_datastream || true)"
  if [[ -z "${datastream}" ]]; then
    echo "[WARN] OpenSCAP datastream not found. Skipping OpenSCAP scan."
    {
      echo "# OpenSCAP snapshot"
      echo "openscap_datetime=$(date '+%Y-%m-%d %H:%M:%S')"
      echo "openscap_status=datastream_not_found"
      echo "openscap_profile=N/A"
      echo "openscap_datastream=N/A"
      echo "openscap_total_rules=0"
      echo "openscap_passed_rules=0"
      echo "openscap_failed_rules=0"
      echo "openscap_error_rules=0"
      echo "openscap_notchecked_rules=0"
    } > "${OPENSCAP_SNAPSHOT_FILE}"
    return
  fi

  local profile="xccdf_org.ssgproject.content_profile_standard"
  echo "[INFO] Running OpenSCAP scan..."
  echo "[INFO] Datastream: ${datastream}"
  echo "[INFO] OpenSCAP results XML: ${OPENSCAP_RESULT_XML}"
  echo "[INFO] OpenSCAP HTML report: ${OPENSCAP_REPORT_HTML}"

  ${as_root} oscap xccdf eval \
    --profile "${profile}" \
    --results "${OPENSCAP_RESULT_XML}" \
    --report "${OPENSCAP_REPORT_HTML}" \
    "${datastream}" || true

  local pass_count fail_count error_count notchecked_count notselected_count total_count
  pass_count="$(rg -N -c "<result>pass</result>" "${OPENSCAP_RESULT_XML}" 2>/dev/null | awk -F: '{sum+=$NF} END {print sum+0}')"
  fail_count="$(rg -N -c "<result>fail</result>" "${OPENSCAP_RESULT_XML}" 2>/dev/null | awk -F: '{sum+=$NF} END {print sum+0}')"
  error_count="$(rg -N -c "<result>error</result>" "${OPENSCAP_RESULT_XML}" 2>/dev/null | awk -F: '{sum+=$NF} END {print sum+0}')"
  notchecked_count="$(rg -N -c "<result>notchecked</result>" "${OPENSCAP_RESULT_XML}" 2>/dev/null | awk -F: '{sum+=$NF} END {print sum+0}')"
  notselected_count="$(rg -N -c "<result>notselected</result>" "${OPENSCAP_RESULT_XML}" 2>/dev/null | awk -F: '{sum+=$NF} END {print sum+0}')"
  total_count=$((pass_count + fail_count + error_count + notchecked_count + notselected_count))

  {
    echo "# OpenSCAP snapshot"
    echo "openscap_datetime=$(date '+%Y-%m-%d %H:%M:%S')"
    echo "openscap_status=completed"
    echo "openscap_profile=${profile}"
    echo "openscap_datastream=${datastream}"
    echo "openscap_total_rules=${total_count}"
    echo "openscap_passed_rules=${pass_count}"
    echo "openscap_failed_rules=${fail_count}"
    echo "openscap_error_rules=${error_count}"
    echo "openscap_notchecked_rules=$((notchecked_count + notselected_count))"

    if [[ -f "${OPENSCAP_RESULT_XML}" ]]; then
      python3 - <<'PY' "${OPENSCAP_RESULT_XML}"
import re
import sys
from pathlib import Path

content = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
rule_re = re.compile(r'<rule-result[^>]*idref="([^"]+)"[^>]*>.*?<result>([^<]+)</result>', re.DOTALL)
count = 0
for rid, status in rule_re.findall(content):
    if status.strip().lower() == "fail":
        print(f"openscap_failed_rule[]={rid}")
        count += 1
    if count >= 200:
        break
PY
    fi
  } > "${OPENSCAP_SNAPSHOT_FILE}"

  echo "[INFO] OpenSCAP scan completed."
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

    findmnt -rn -o TARGET,FSTYPE,OPTIONS 2>/dev/null | awk '{print "mount_info[]="$0}'
    ss -tulpen 2>/dev/null | awk 'NR>1 {print "open_port[]="$0}'
    systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print "running_service_full[]="$1}'

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
  install_openscap
  run_audit
  collect_system_snapshot
  run_openscap_scan
}

main "$@"
