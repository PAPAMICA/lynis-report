#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import html
import math
import os
import re
import shutil
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple


class ParsedReport:
    def __init__(self, values: Dict[str, str], arrays: Dict[str, List[str]]) -> None:
        self.values = values
        self.arrays = arrays


def parse_report_file(report_path: Path) -> ParsedReport:
    values: Dict[str, str] = {}
    arrays: Dict[str, List[str]] = {}

    for raw_line in report_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        if key.endswith("[]"):
            arrays.setdefault(key[:-2].strip(), []).append(value.strip())
        else:
            values[key.strip()] = value.strip()

    return ParsedReport(values=values, arrays=arrays)


def parse_pipe_list(value: str) -> List[str]:
    return [item.strip() for item in value.split("|") if item.strip()]


def parse_recommendation(entry: str) -> Tuple[str, str, str]:
    parts = entry.split("|")
    test_id = parts[0].strip() if len(parts) > 0 else "N/A"
    message = parts[1].strip() if len(parts) > 1 else ""
    advice = parts[2].strip() if len(parts) > 2 else ""
    return test_id, message, advice


def parse_detail_entry(entry: str) -> Tuple[str, str, str]:
    parts = entry.split("|")
    test_id = parts[0].strip() if len(parts) > 0 else "N/A"
    component = parts[1].strip() if len(parts) > 1 else ""
    kv_blob = parts[2].strip() if len(parts) > 2 else ""

    pairs: Dict[str, str] = {}
    for chunk in kv_blob.split(";"):
        chunk = chunk.strip()
        if not chunk or ":" not in chunk:
            continue
        key, value = chunk.split(":", 1)
        pairs[key.strip()] = value.strip()

    description = pairs.get("desc", "")
    field = pairs.get("field", "")
    preferred = pairs.get("prefval", "")
    current = pairs.get("value", "")

    out: List[str] = []
    if description:
        out.append(description)
    if field:
        out.append(f"Field: {field}")
    if preferred or current:
        out.append(f"Expected: {preferred or 'N/A'} | Current: {current or 'N/A'}")

    details = " | ".join(out) if out else kv_blob
    return test_id, component, details


def score_details(score: int) -> Tuple[str, str]:
    if score >= 90:
        return "Excellent", "score-excellent"
    if score >= 75:
        return "Good", "score-good"
    if score >= 60:
        return "Fair", "score-fair"
    return "Needs Improvement", "score-poor"


def escape(value: str) -> str:
    return html.escape(value, quote=True)


def build_logo_data_uri(logo_path: Path | None) -> str:
    if logo_path is None:
        return ""
    if not logo_path.exists():
        raise FileNotFoundError(f"Logo file not found: {logo_path}")
    if logo_path.suffix.lower() != ".png":
        raise ValueError("Logo must be a PNG file.")
    encoded = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def default_output_path(parsed: ParsedReport) -> Path:
    hostname = parsed.values.get("hostname", "unknown-host").strip() or "unknown-host"
    safe_hostname = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in hostname)
    date_str = datetime.now().strftime("%Y-%m-%d")
    return Path("results") / f"report_{safe_hostname}_{date_str}.html"


def default_report_path() -> Path:
    hostname = socket.gethostname().split(".", 1)[0] or "unknown-host"
    safe_hostname = "".join(ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in hostname)
    date_str = datetime.now().strftime("%Y-%m-%d")
    return Path("reports") / f"report_{safe_hostname}_{date_str}.dat"


def default_system_data_path(report_path: Path) -> Path:
    filename = report_path.name
    if filename.startswith("report_") and filename.endswith(".dat"):
        return report_path.with_name("system_" + filename[len("report_"):])
    return report_path.with_name("system_snapshot.dat")


def default_log_path(report_path: Path) -> Path:
    filename = report_path.name
    if filename.startswith("report_") and filename.endswith(".dat"):
        log_name = "lynis_" + filename[len("report_") : -4] + ".log"
        if report_path.parent.name == "reports":
            return report_path.parent.parent / "results" / log_name
        return report_path.with_name(log_name)
    return report_path.with_suffix(".log")


def detect_package_manager() -> str:
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("yum"):
        return "yum"
    if shutil.which("zypper"):
        return "zypper"
    if shutil.which("pacman"):
        return "pacman"
    if shutil.which("apk"):
        return "apk"
    return "unknown"


def run_cmd(command: List[str], use_sudo: bool = False, check: bool = True) -> subprocess.CompletedProcess[str]:
    final_cmd = command[:]
    if use_sudo and os.geteuid() != 0:
        final_cmd = ["sudo"] + final_cmd
    return subprocess.run(final_cmd, check=check, text=True, capture_output=True)


def install_package(package_name: str) -> None:
    manager = detect_package_manager()
    if manager == "apt":
        run_cmd(["apt-get", "update"], use_sudo=True)
        run_cmd(["apt-get", "install", "-y", package_name], use_sudo=True)
    elif manager == "dnf":
        run_cmd(["dnf", "install", "-y", package_name], use_sudo=True)
    elif manager == "yum":
        run_cmd(["yum", "install", "-y", package_name], use_sudo=True)
    elif manager == "zypper":
        run_cmd(["zypper", "--non-interactive", "install", package_name], use_sudo=True)
    elif manager == "pacman":
        run_cmd(["pacman", "-Sy", "--noconfirm", package_name], use_sudo=True)
    elif manager == "apk":
        run_cmd(["apk", "add", "--no-cache", package_name], use_sudo=True)
    else:
        raise RuntimeError("Unsupported Linux distribution: package manager not found.")


def ensure_lynis_installed() -> None:
    if shutil.which("lynis"):
        return
    install_package("lynis")
    if not shutil.which("lynis"):
        raise RuntimeError("Lynis installation failed.")


def run_full_collection(report_path: Path, log_path: Path, system_data_path: Path) -> None:
    ensure_lynis_installed()

    report_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    system_data_path.parent.mkdir(parents=True, exist_ok=True)

    run_cmd(
        [
            "lynis",
            "audit",
            "system",
            "--report-file",
            str(report_path),
            "--logfile",
            str(log_path),
        ],
        use_sudo=True,
    )

    # Reuse existing Bash collector for full machine context only.
    collector_script = Path(__file__).with_name("get-data.sh")
    run_cmd(["bash", str(collector_script), "--snapshot-only"], use_sudo=False, check=False)
    default_snapshot = default_system_data_path(report_path)
    if default_snapshot.exists() and default_snapshot != system_data_path:
        system_data_path.write_text(default_snapshot.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")


def parse_skip_reasons_from_log(log_path: Path | None) -> Dict[str, List[str]]:
    if not log_path or not log_path.exists():
        return {}

    pattern = re.compile(r"(?P<test>[A-Z0-9]{3,5}-\d{3,4}).*?\[\s*SKIPPED\s*\]", re.IGNORECASE)
    reasons: Dict[str, List[str]] = {}
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines:
        match = pattern.search(line)
        if not match:
            continue
        test_id = match.group("test").upper()
        cleaned = re.sub(r"\[\s*SKIPPED\s*\]", "", line, flags=re.IGNORECASE).strip(" -\t")
        if cleaned:
            reasons.setdefault(test_id, []).append(cleaned)
    return reasons


def estimate_skip_reason(test_id: str, parsed: ParsedReport) -> str:
    values = parsed.values
    prefix = test_id.split("-", 1)[0]

    if prefix == "DBS":
        return "No database engine detected on this host."
    if prefix == "PHP":
        return "PHP is not installed or not detected."
    if prefix == "HTTP":
        return "No supported web server detected (Apache/nginx not found)."
    if prefix == "SNMP":
        return "SNMP service is not installed or not running."
    if prefix in {"KRB", "KRB5"}:
        return "Kerberos components are not present on this host."
    if prefix == "CONT":
        return "Container-specific test not applicable on this system."
    if prefix == "MAIL":
        smtp = values.get("smtp_daemon", "")
        if not smtp:
            return "No SMTP daemon detected."
    if prefix == "LDAP":
        if values.get("ldap_auth_enabled", "0") == "0":
            return "LDAP is not enabled on this host."
    if prefix == "TIME":
        return "Time-sync related check not applicable to current configuration."
    if prefix == "BOOT":
        if values.get("boot_uefi_booted", "0") == "0":
            return "UEFI-related control skipped (system not booted in UEFI mode)."

    return "Skipped by Lynis profile, missing prerequisite, or non-applicable host context."


def priority_for_test(status: str, summary: str, recommendation: str) -> str:
    text = f"{summary} {recommendation}".lower()
    if status == "warning":
        if "reboot" in text or "kernel" in text:
            return "P1"
        return "P1"
    if status in {"suggestion", "manual"}:
        if "firewall" in text or "ssh" in text or "logging" in text:
            return "P1"
        return "P2"
    if status == "skipped":
        return "P3"
    return "P3"


def build_test_rows(
    parsed: ParsedReport,
    skipped_reason_map: Dict[str, List[str]] | None = None,
) -> Tuple[List[str], Dict[str, int], Dict[str, int], List[Dict[str, str]], List[str]]:
    values = parsed.values
    arrays = parsed.arrays

    tests_executed = parse_pipe_list(values.get("tests_executed", ""))
    tests_skipped = parse_pipe_list(values.get("tests_skipped", ""))

    suggestion_by_test: Dict[str, List[Tuple[str, str]]] = {}
    for entry in arrays.get("suggestion", []):
        test_id, message, advice = parse_recommendation(entry)
        suggestion_by_test.setdefault(test_id, []).append((message, advice))

    warning_by_test: Dict[str, List[str]] = {}
    for entry in arrays.get("warning", []):
        test_id, message, _ = parse_recommendation(entry)
        warning_by_test.setdefault(test_id, []).append(message)

    details_by_test: Dict[str, List[Tuple[str, str]]] = {}
    for entry in arrays.get("details", []):
        test_id, component, detail_text = parse_detail_entry(entry)
        details_by_test.setdefault(test_id, []).append((component, detail_text))

    manual_ids = {
        item.split(":", 1)[0].strip() for item in arrays.get("manual_event", []) if item.strip()
    }

    seen = set()
    executed_unique: List[str] = []
    for test_id in tests_executed:
        if test_id not in seen:
            executed_unique.append(test_id)
            seen.add(test_id)

    rows: List[str] = []
    status_counts = {"passed": 0, "suggestion": 0, "warning": 0, "manual": 0, "skipped": 0}
    priority_counts = {"P1": 0, "P2": 0, "P3": 0}
    actions: List[Dict[str, str]] = []

    for test_id in executed_unique:
        status = "passed"
        if test_id in manual_ids:
            status = "manual"
        if test_id in suggestion_by_test:
            status = "suggestion"
        if test_id in warning_by_test:
            status = "warning"
        status_counts[status] += 1

        warning_items = [item for item in warning_by_test.get(test_id, []) if item]
        sugg_entries = suggestion_by_test.get(test_id, [])
        finding_items = [item[0] for item in sugg_entries if item[0]]
        advice_items = [item[1] for item in sugg_entries if item[1]]

        detail_entries = details_by_test.get(test_id, [])
        components = ", ".join(sorted({component for component, _ in detail_entries if component})) or "N/A"
        detail_items = [detail for _, detail in detail_entries if detail] or ["N/A"]

        summary_items = warning_items or finding_items or ["No issue reported by Lynis for this test."]
        recommendation_items = advice_items or ["No specific recommendation."]
        summary = " | ".join(summary_items)
        recommendation = " | ".join(recommendation_items)
        priority = priority_for_test(status, summary, recommendation)
        priority_counts[priority] += 1

        if status in {"warning", "suggestion", "manual"}:
            actions.append(
                {
                    "priority": priority,
                    "test_id": test_id,
                    "status": status.upper(),
                    "summary_html": "<br>".join(escape(item) for item in summary_items),
                    "recommendation_html": "<br>".join(escape(item) for item in recommendation_items),
                }
            )

        status_html = f"<span class='badge status-{status}'>{status.upper()}</span>"
        priority_html = f"<span class='badge priority-{priority.lower()}'>{priority}</span>"
        row = (
            f"<tr class='row-{status}' data-status='{status}' data-priority='{priority}'>"
            f"<td>{escape(test_id)}</td>"
            f"<td>{status_html}</td>"
            f"<td>{priority_html}</td>"
            f"<td>{'<br>'.join(escape(item) for item in summary_items)}</td>"
            f"<td>{'<br>'.join(escape(item) for item in recommendation_items)}</td>"
            f"<td>{escape(components)}</td>"
            f"<td>{'<br>'.join(escape(item) for item in detail_items)}</td>"
            "</tr>"
        )
        rows.append(row)

    skipped_rows: List[str] = []
    for test_id in tests_skipped:
        status_counts["skipped"] += 1
        priority_counts["P3"] += 1
        log_reasons = (skipped_reason_map or {}).get(test_id, [])
        reason_text = " | ".join(log_reasons) if log_reasons else estimate_skip_reason(test_id, parsed)
        source_text = "Lynis log" if log_reasons else "Heuristic"
        row = (
            "<tr class='row-skipped' data-status='skipped' data-priority='P3'>"
            f"<td>{escape(test_id)}</td>"
            "<td><span class='badge status-skipped'>SKIPPED</span></td>"
            "<td><span class='badge priority-p3'>P3</span></td>"
            f"<td>{escape(reason_text)}</td>"
            "<td>N/A</td>"
            "<td>N/A</td>"
            f"<td>Source: {escape(source_text)}</td>"
            "</tr>"
        )
        rows.append(row)
        skipped_rows.append(
            "<tr>"
            f"<td>{escape(test_id)}</td>"
            f"<td>{escape(test_id.split('-', 1)[0] if '-' in test_id else 'GEN')}</td>"
            f"<td>{escape(reason_text)}</td>"
            f"<td>{escape(source_text)}</td>"
            "</tr>"
        )

    rank = {"P1": 0, "P2": 1, "P3": 2}
    actions.sort(key=lambda item: (rank[item["priority"]], item["test_id"]))
    return rows, status_counts, priority_counts, actions, skipped_rows


def _badge(text: str, css: str) -> str:
    return f"<span class='badge {css}'>{html.escape(text, quote=True)}</span>"


def _svc_badge(state: str, kind: str) -> str:
    s = state.lower()
    if kind == "active":
        m = {
            "active": "bg-ok", "inactive": "bg-muted", "failed": "bg-danger",
            "activating": "bg-info", "deactivating": "bg-warn",
        }
    elif kind == "load":
        m = {
            "loaded": "bg-info", "not-found": "bg-danger", "error": "bg-danger",
            "masked": "bg-purple", "bad-setting": "bg-danger",
        }
    else:
        m = {
            "enabled": "bg-ok", "disabled": "bg-muted", "static": "bg-info",
            "masked": "bg-purple", "indirect": "bg-warn", "generated": "bg-info",
            "alias": "bg-info",
        }
    css_map = {
        "bg-ok": "b-green", "bg-muted": "b-gray", "bg-danger": "b-red",
        "bg-info": "b-blue", "bg-warn": "b-orange", "bg-purple": "b-purple",
    }
    return f"<span class='badge {css_map.get(m.get(s, 'bg-muted'), 'b-gray')}'>{html.escape(state, quote=True)}</span>"


def render_html(
    parsed: ParsedReport,
    report_path: Path,
    logo_data_uri: str,
    system_data: ParsedReport | None = None,
    log_path: Path | None = None,
) -> str:
    values = parsed.values
    arrays = parsed.arrays

    hostname = values.get("hostname", "Unknown")
    os_name = values.get("os_fullname", values.get("os_name", "Unknown"))
    lynis_version = values.get("lynis_version", "Unknown")
    started_at = values.get("report_datetime_start", "Unknown")
    ended_at = values.get("report_datetime_end", "Unknown")
    hardening_score = int(values.get("hardening_index", "0") or 0)
    score_label, score_css = score_details(hardening_score)

    tests_done = int(values.get("lynis_tests_done", "0") or 0)
    tests_executed = parse_pipe_list(values.get("tests_executed", ""))
    tests_skipped = parse_pipe_list(values.get("tests_skipped", ""))

    warnings = arrays.get("warning", [])
    suggestions = arrays.get("suggestion", [])
    manual_actions = arrays.get("manual", [])
    running_services = arrays.get("running_service", [])
    boot_services = arrays.get("boot_service", [])
    network_listeners = arrays.get("network_listen", [])
    report_real_users = arrays.get("real_user", [])
    report_home_directories = arrays.get("home_directory", [])
    report_filesystems = arrays.get("file_systems_ext", [])

    sys_values = system_data.values if system_data else {}
    sys_arrays = system_data.arrays if system_data else {}

    timezone = sys_values.get("timezone", "—")
    keyboard_layout = sys_values.get("keyboard_layout", "—")
    keyboard_model = sys_values.get("keyboard_model", "—")
    system_locale = sys_values.get("system_locale", "—")
    lang_value = sys_values.get("lang", "—")
    shell_value = sys_values.get("shell", "—")
    package_manager_value = sys_values.get("package_manager", "—")
    secure_boot_status = sys_values.get("secure_boot_status", "—")
    tpm_status = sys_values.get("tpm_status", "—")
    encryption_summary = sys_values.get("encryption_summary", "—")
    uptime_human = sys_values.get("uptime_human", "—")
    load_average = sys_values.get("load_average", "—")
    memory_total_kb = sys_values.get("memory_total_kb", "—")
    kernel_version = sys_values.get("kernel", values.get("os_kernel_version", "—"))

    user_entries = sys_arrays.get("real_user", report_real_users)
    locked_users = sys_arrays.get("locked_user", arrays.get("locked_account", []))
    important_paths = sys_arrays.get("important_path", [])
    mount_info = sys_arrays.get("mount_info", [])
    open_ports = sys_arrays.get("open_port", [])
    running_services_full = sys_arrays.get("running_service_full", [])
    service_status_entries = sys_arrays.get("service_status", [])
    service_enablement_entries = sys_arrays.get("service_enablement", [])
    sshd_effective = sys_arrays.get("sshd_effective", [])
    security_sysctl = sys_arrays.get("security_sysctl", [])
    upgradeable_packages = sys_arrays.get("upgradeable_package", [])
    nft_rules = sys_arrays.get("firewall_rule_nft", [])
    iptables_rules = sys_arrays.get("firewall_rule_iptables", [])
    suid_sgid_files = sys_arrays.get("suid_sgid_file", [])
    world_writable_files = sys_arrays.get("world_writable_file", [])
    cert_expiry = sys_arrays.get("cert_expiry", [])
    user_auth_entries = sys_arrays.get("user_auth", [])
    important_file_entries = sys_arrays.get("important_file", [])

    # ── Lynis test analysis ──────────────────────────────────────────────────
    skipped_reason_map = parse_skip_reasons_from_log(log_path)
    test_rows, status_counts, priority_counts, actions, skipped_rows_raw = build_test_rows(
        parsed, skipped_reason_map=skipped_reason_map
    )
    skipped_total = len(skipped_rows_raw)
    if skipped_rows_raw:
        skipped_rows_raw = skipped_rows_raw[:200]
        if skipped_total > 200:
            skipped_rows_raw.append(
                f"<tr><td colspan='4' class='note-row'>Showing first 200 of {skipped_total} skipped tests.</td></tr>"
            )
    skipped_rows_raw = skipped_rows_raw or ["<tr><td colspan='4'>No skipped tests found in this report.</td></tr>"]

    top_actions = actions[:15]
    top_action_rows: List[str] = []
    for action in top_actions:
        p = action["priority"]
        p_css = {"P1": "b-red", "P2": "b-orange", "P3": "b-blue"}.get(p, "b-gray")
        s = action["status"]
        s_css = {"WARNING": "b-red", "SUGGESTION": "b-orange", "MANUAL": "b-purple"}.get(s, "b-gray")
        top_action_rows.append(
            "<tr>"
            f"<td>{_badge(p, p_css)}</td>"
            f"<td class='mono'>{escape(action['test_id'])}</td>"
            f"<td>{_badge(s, s_css)}</td>"
            f"<td class='finding'>{action['summary_html']}</td>"
            f"<td class='finding'>{action['recommendation_html']}</td>"
            "</tr>"
        )
    if not top_action_rows:
        top_action_rows.append("<tr><td colspan='5' class='note-row'>No priority actions — all tests passed.</td></tr>")

    recommendation_rows: List[str] = []
    for entry in suggestions:
        tid, msg, adv = parse_recommendation(entry)
        recommendation_rows.append(
            f"<tr><td class='mono'>{escape(tid)}</td>"
            f"<td>{escape(msg or 'No message provided')}</td>"
            f"<td>{escape(adv or 'No additional recommendation')}</td></tr>"
        )
    if not recommendation_rows:
        recommendation_rows.append("<tr><td colspan='3'>No recommendations found.</td></tr>")
    recommendation_rows = recommendation_rows[:120]

    warning_rows: List[str] = []
    for entry in warnings:
        tid, msg, _ = parse_recommendation(entry)
        warning_rows.append(
            f"<tr><td class='mono'>{escape(tid)}</td><td>{escape(msg)}</td></tr>"
        )
    if not warning_rows:
        warning_rows.append("<tr><td colspan='2' class='note-row'>No critical warnings found.</td></tr>")

    manual_items = [f"<li>{escape(item)}</li>" for item in manual_actions] or [
        "<li>No manual verification tasks listed.</li>"
    ]

    # ── User inventory ───────────────────────────────────────────────────────
    user_rows: List[str] = []
    for entry in user_entries:
        parts = [p.strip() for p in entry.split(",")]
        u, uid, gid, home, sh = (parts + ["—"] * 5)[:5]
        user_rows.append(
            f"<tr><td><strong>{escape(u)}</strong></td>"
            f"<td class='mono muted'>{escape(uid)}</td>"
            f"<td class='mono muted'>{escape(gid)}</td>"
            f"<td class='mono'>{escape(home)}</td>"
            f"<td class='mono'>{escape(sh)}</td></tr>"
        )
    if not user_rows:
        user_rows.append("<tr><td colspan='5'>No user information available.</td></tr>")

    # ── User auth matrix ─────────────────────────────────────────────────────
    user_auth_rows: List[str] = []
    for entry in user_auth_entries:
        parts = [p.strip() for p in entry.split("|")]
        uname = parts[0] if parts else "N/A"
        kv: Dict[str, str] = {}
        for item in parts[1:]:
            if "=" in item:
                k2, v2 = item.split("=", 1)
                kv[k2.strip()] = v2.strip()

        ssh_v = kv.get("ssh_allowed", "N/A")
        if ssh_v.lower() == "yes":
            ssh_h = _badge("yes", "b-green")
        elif ssh_v.lower() == "no":
            ssh_h = _badge("no", "b-gray")
        else:
            ssh_h = _badge(ssh_v, "b-gray")

        pwd_v = kv.get("password", "N/A")
        pwd_map = {"set": "b-green", "locked": "b-red", "unset": "b-orange", "none": "b-gray"}
        pwd_h = _badge(pwd_v, pwd_map.get(pwd_v.lower(), "b-gray"))

        ak_str = kv.get("authorized_keys", "0")
        try:
            ak_int = int(ak_str)
        except ValueError:
            ak_int = 0
        ak_h = _badge(ak_str, "b-green" if ak_int > 0 else "b-gray")

        key_prev = kv.get("key_preview", "")

        user_auth_rows.append(
            f"<tr><td><strong>{escape(uname)}</strong></td>"
            f"<td class='mono muted'>{escape(kv.get('uid', '—'))}</td>"
            f"<td class='mono'>{escape(kv.get('shell', '—'))}</td>"
            f"<td>{pwd_h}</td>"
            f"<td>{ssh_h}</td>"
            f"<td class='muted small'>{escape(kv.get('methods', 'none'))}</td>"
            f"<td>{ak_h}</td>"
            f"<td class='muted small'>{escape(kv.get('groups', '—'))}</td>"
            f"<td class='mono small'>{escape(key_prev[:80])}</td></tr>"
        )
    if not user_auth_rows:
        user_auth_rows.append("<tr><td colspan='9'>No per-user authentication data available.</td></tr>")

    # ── Important paths ──────────────────────────────────────────────────────
    path_rows: List[str] = []
    for entry in important_paths:
        parts = [p.strip() for p in entry.split(",", 3)]
        perm, owner, group, path = (parts + ["—"] * 4)[:4]
        path_rows.append(
            f"<tr><td class='mono'>{escape(path)}</td>"
            f"<td class='mono'>{escape(perm)}</td>"
            f"<td class='mono muted'>{escape(owner)}</td>"
            f"<td class='mono muted'>{escape(group)}</td></tr>"
        )
    if not path_rows:
        path_rows.append("<tr><td colspan='4'>No path permission information available.</td></tr>")

    # ── Sysctl table ─────────────────────────────────────────────────────────
    sysctl_rows: List[str] = []
    for item in security_sysctl:
        item = item.strip()
        if " = " in item:
            k, v = item.split(" = ", 1)
        elif "=" in item:
            k, v = item.split("=", 1)
        else:
            ps = item.split(None, 1)
            k = ps[0]
            v = ps[1] if len(ps) > 1 else ""
        k, v = k.strip(), v.strip()
        sysctl_rows.append(
            f"<tr><td class='mono'>{escape(k)}</td><td class='mono'>{escape(v)}</td></tr>"
        )
    if not sysctl_rows:
        sysctl_rows.append("<tr><td colspan='2'>No sysctl data available.</td></tr>")

    # ── SSH config table ─────────────────────────────────────────────────────
    _ssh_sec = {
        "permitrootlogin", "passwordauthentication", "pubkeyauthentication",
        "permitemptypasswords", "x11forwarding", "usepam", "maxauthtries",
        "logingracetime", "clientaliveinterval", "clientalivecountmax",
        "challengeresponseauthentication", "kerberosauthentication",
        "hostbasedauthentication", "permituserenvironment", "allowtcpforwarding",
        "allowagentforwarding", "banner", "port", "protocol", "authorizedkeysfile",
    }
    sshd_rows: List[str] = []
    for item in sshd_effective[:120]:
        item = item.strip()
        if not item:
            continue
        ps2 = item.split(None, 1)
        key_raw = ps2[0]
        val_raw = ps2[1].strip() if len(ps2) > 1 else ""
        kl = key_raw.lower()
        is_sec = kl in _ssh_sec

        val_cls = "mono"
        if kl == "permitrootlogin" and val_raw.lower() not in ("no", "prohibit-password"):
            val_cls = "mono text-danger"
        elif kl == "passwordauthentication" and val_raw.lower() == "yes":
            val_cls = "mono text-warn"
        elif kl == "permitemptypasswords" and val_raw.lower() == "yes":
            val_cls = "mono text-danger"
        elif kl == "x11forwarding" and val_raw.lower() == "yes":
            val_cls = "mono text-warn"
        elif kl == "pubkeyauthentication" and val_raw.lower() == "yes":
            val_cls = "mono text-ok"

        row_cls = " class='sshd-sec'" if is_sec else ""
        sshd_rows.append(
            f"<tr{row_cls}><td class='mono'>{escape(key_raw)}</td>"
            f"<td class='{val_cls}'>{escape(val_raw)}</td></tr>"
        )
    if not sshd_rows:
        sshd_rows.append("<tr><td colspan='2'>No SSH configuration data available.</td></tr>")

    # ── Enablement map ───────────────────────────────────────────────────────
    enablement_map: Dict[str, str] = {}
    for entry in service_enablement_entries:
        u2, sep, st = entry.partition("|")
        if sep:
            enablement_map[u2.strip()] = st.strip()

    # ── Service status rows ──────────────────────────────────────────────────
    service_status_rows: List[str] = []
    for entry in service_status_entries:
        parts = [p.strip() for p in entry.split("|", 4)]
        unit = parts[0] if len(parts) > 0 else "N/A"
        load = parts[1] if len(parts) > 1 else "N/A"
        active = parts[2] if len(parts) > 2 else "N/A"
        sub = parts[3] if len(parts) > 3 else "N/A"
        description = parts[4] if len(parts) > 4 else ""
        enabled_state = enablement_map.get(unit, "")
        enabled_h = _svc_badge(enabled_state, "enabled") if enabled_state else "<span class='muted'>—</span>"
        service_status_rows.append(
            f"<tr><td class='mono'>{escape(unit)}</td>"
            f"<td>{_svc_badge(load, 'load')}</td>"
            f"<td>{_svc_badge(active, 'active')}</td>"
            f"<td class='mono muted'>{escape(sub)}</td>"
            f"<td>{enabled_h}</td>"
            f"<td class='muted'>{escape(description)}</td></tr>"
        )
    if not service_status_rows:
        service_status_rows.append(
            "<tr><td colspan='6'>No service status information available.</td></tr>"
        )
    else:
        svc_total = len(service_status_rows)
        service_status_rows = service_status_rows[:400]
        if svc_total > 400:
            service_status_rows.append(
                f"<tr><td colspan='6' class='note-row'>Showing first 400 of {svc_total} services.</td></tr>"
            )

    # ── Critical files rows ──────────────────────────────────────────────────
    important_file_rows: List[str] = []
    for entry in important_file_entries:
        parts = [p.strip() for p in entry.split("|")]
        fpath = parts[0] if parts else "N/A"
        kv2: Dict[str, str] = {}
        for item in parts[1:]:
            if "=" in item:
                k3, v3 = item.split("=", 1)
                kv2[k3.strip()] = v3.strip()
        preview_text = kv2.get("preview", kv2.get("error", "N/A")).replace("\\n", "\n")
        pres_v = kv2.get("present", "N/A")
        if pres_v.lower() == "yes":
            pres_h = _badge("yes", "b-green")
        elif pres_v.lower() == "no":
            pres_h = _badge("no", "b-red")
        else:
            pres_h = _badge(pres_v, "b-gray")
        important_file_rows.append(
            f"<tr><td class='mono'>{escape(fpath)}</td>"
            f"<td>{pres_h}</td>"
            f"<td class='mono muted'>{escape(kv2.get('mode', '—'))}</td>"
            f"<td class='mono muted'>{escape(kv2.get('owner', '—'))}:{escape(kv2.get('group', '—'))}</td>"
            f"<td class='muted'>{escape(kv2.get('size', '—'))}</td>"
            f"<td><pre class='code-block'>{escape(preview_text)}</pre></td></tr>"
        )
    if not important_file_rows:
        important_file_rows.append("<tr><td colspan='6'>No critical file snapshot available.</td></tr>")

    # ── Misc single-column tables ────────────────────────────────────────────
    def _mono_rows(items: List[str], limit: int) -> List[str]:
        rs = [f"<tr><td class='mono'>{escape(i)}</td></tr>" for i in items[:limit]]
        return rs or ["<tr><td class='muted'>—</td></tr>"]

    mount_rows = _mono_rows(mount_info, 60)
    suid_rows = _mono_rows(suid_sgid_files, 300)
    ww_rows = _mono_rows(world_writable_files, 300)
    cert_rows = _mono_rows(cert_expiry, 200)
    upg_rows = _mono_rows(upgradeable_packages, 300)
    nft_rows_t = _mono_rows(nft_rules, 260)
    ipt_rows_t = _mono_rows(iptables_rules, 260)
    port_rows = _mono_rows(open_ports, 80)
    listener_rows = _mono_rows(network_listeners, 80)
    running_full_rows = _mono_rows(running_services_full, 100)

    locked_user_items = [f"<li>{escape(i)}</li>" for i in locked_users] or ["<li>None</li>"]
    home_dir_items = [f"<li class='mono'>{escape(i)}</li>" for i in report_home_directories[:60]] or ["<li>—</li>"]
    fs_items = [f"<li class='mono'>{escape(i)}</li>" for i in report_filesystems[:40]] or ["<li>—</li>"]

    # ── KPI metrics ──────────────────────────────────────────────────────────
    total_checks = max(1, len(tests_executed) + len(tests_skipped))
    pass_pct = int((status_counts["passed"] / total_checks) * 100)
    warn_pct = int((status_counts["warning"] / total_checks) * 100)
    sugg_pct = int((status_counts["suggestion"] / total_checks) * 100)
    risk_level = "High" if hardening_score < 60 else "Medium" if hardening_score < 80 else "Controlled"
    risk_b_css = "b-red" if hardening_score < 60 else "b-orange" if hardening_score < 80 else "b-green"
    score_color = "#16a34a" if hardening_score >= 75 else "#d97706" if hardening_score >= 60 else "#dc2626"

    # SVG ring for score
    R = 52
    cx = cy = 64
    circ = 2 * math.pi * R
    dash_ok = circ * hardening_score / 100
    dash_gap = circ - dash_ok
    score_svg = (
        f"<svg viewBox='0 0 128 128' width='120' height='120' style='display:block;margin:0 auto'>"
        f"<circle cx='{cx}' cy='{cy}' r='{R}' fill='none' stroke='#e2e8f0' stroke-width='12'/>"
        f"<circle cx='{cx}' cy='{cy}' r='{R}' fill='none' stroke='{score_color}' stroke-width='12'"
        f" stroke-dasharray='{dash_ok:.2f} {dash_gap:.2f}'"
        f" stroke-linecap='round' transform='rotate(-90 {cx} {cy})'/>"
        f"<text x='{cx}' y='{cy}' dominant-baseline='central' text-anchor='middle'"
        f" font-size='22' font-weight='800' fill='{score_color}'>{hardening_score}</text>"
        f"<text x='{cx}' y='{cy+22}' dominant-baseline='central' text-anchor='middle'"
        f" font-size='10' fill='#64748b'>/100</text>"
        f"</svg>"
    )

    logo_html = f"<img src='{logo_data_uri}' alt='Logo' class='logo' />" if logo_data_uri else ""
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Security Report — {escape(hostname)}</title>
  <style>
    /* ── Reset & tokens ─────────────────────────────────────── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --c-bg:      #f1f5f9;
      --c-surface: #ffffff;
      --c-border:  #e2e8f0;
      --c-text:    #0f172a;
      --c-muted:   #64748b;
      --c-primary: #2563eb;
      --c-ok:      #16a34a;
      --c-warn:    #d97706;
      --c-danger:  #dc2626;
      --c-purple:  #7c3aed;
      --c-blue:    #0284c7;
      --radius-sm: 8px;
      --radius-md: 12px;
      --radius-lg: 18px;
      --shadow-sm: 0 1px 3px rgba(15,23,42,.08);
      --shadow-md: 0 4px 16px rgba(15,23,42,.10);
      --shadow-lg: 0 12px 40px rgba(30,58,138,.18);
    }}

    /* ── Base ────────────────────────────────────────────────── */
    html {{ scroll-behavior: smooth; }}
    body {{
      font-family: "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
      font-size: 14px;
      line-height: 1.6;
      color: var(--c-text);
      background: var(--c-bg);
    }}
    a {{ color: var(--c-primary); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    strong {{ font-weight: 600; }}

    /* ── Layout ──────────────────────────────────────────────── */
    .page {{ max-width: 1420px; margin: 0 auto; padding: 20px 24px 60px; }}

    /* ── Hero / Header ───────────────────────────────────────── */
    .hero {{
      background: linear-gradient(135deg, #0c1a3a 0%, #1e3a8a 50%, #2563eb 100%);
      border-radius: var(--radius-lg);
      padding: 28px 32px;
      color: #fff;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      box-shadow: var(--shadow-lg);
    }}
    .hero-left h1 {{
      font-size: 1.65rem;
      font-weight: 800;
      letter-spacing: -0.03em;
      color: #fff;
      margin-bottom: 6px;
    }}
    .hero-meta {{ display: flex; flex-wrap: wrap; gap: 6px 18px; margin-top: 8px; }}
    .hero-meta span {{
      font-size: 0.82rem;
      color: #bfdbfe;
      display: flex;
      align-items: center;
      gap: 5px;
    }}
    .hero-meta span b {{ color: #e0f2fe; }}
    .logo {{ max-height: 68px; max-width: 200px; border-radius: 10px;
             background: rgba(255,255,255,.12); padding: 8px; }}

    /* ── Stats strip ─────────────────────────────────────────── */
    .stats-strip {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 10px;
      margin-top: 14px;
    }}
    .stat-card {{
      background: var(--c-surface);
      border: 1px solid var(--c-border);
      border-radius: var(--radius-md);
      padding: 14px 16px;
      box-shadow: var(--shadow-sm);
      display: flex;
      flex-direction: column;
      gap: 2px;
    }}
    .stat-label {{ font-size: 0.72rem; text-transform: uppercase; letter-spacing: .06em; color: var(--c-muted); font-weight: 600; }}
    .stat-value {{ font-size: 1.6rem; font-weight: 800; letter-spacing: -.03em; line-height: 1; color: var(--c-text); }}
    .stat-value.ok    {{ color: var(--c-ok); }}
    .stat-value.warn  {{ color: var(--c-warn); }}
    .stat-value.danger{{ color: var(--c-danger); }}
    .stat-sub  {{ font-size: 0.78rem; color: var(--c-muted); }}

    /* ── Tabs ────────────────────────────────────────────────── */
    .tabs {{
      display: flex;
      gap: 6px;
      margin-top: 18px;
      border-bottom: 2px solid var(--c-border);
      padding-bottom: 0;
    }}
    .tab-btn {{
      border: none;
      background: transparent;
      padding: 10px 20px;
      font-size: 0.9rem;
      font-weight: 600;
      color: var(--c-muted);
      cursor: pointer;
      border-bottom: 2px solid transparent;
      margin-bottom: -2px;
      border-radius: var(--radius-sm) var(--radius-sm) 0 0;
      transition: color .15s, border-color .15s;
    }}
    .tab-btn:hover {{ color: var(--c-primary); }}
    .tab-btn.active {{ color: var(--c-primary); border-bottom-color: var(--c-primary); background: rgba(37,99,235,.05); }}
    .panel {{ display: none; margin-top: 18px; }}
    .panel.active {{ display: block; }}

    /* ── Cards & sections ────────────────────────────────────── */
    .card {{
      background: var(--c-surface);
      border: 1px solid var(--c-border);
      border-radius: var(--radius-md);
      padding: 20px;
      box-shadow: var(--shadow-sm);
    }}
    .card-title {{
      font-size: 0.88rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .05em;
      color: var(--c-muted);
      margin-bottom: 14px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--c-border);
    }}
    .info-grid {{
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    }}
    .kv-list {{ display: flex; flex-direction: column; gap: 6px; }}
    .kv-row {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 8px;
      padding: 4px 0;
      border-bottom: 1px dashed var(--c-border);
      font-size: 0.86rem;
    }}
    .kv-row:last-child {{ border-bottom: none; }}
    .kv-key {{ color: var(--c-muted); font-weight: 500; min-width: 140px; flex-shrink: 0; }}
    .kv-val {{ font-weight: 600; text-align: right; word-break: break-all; }}

    /* ── Section wrappers ────────────────────────────────────── */
    .section {{
      background: var(--c-surface);
      border: 1px solid var(--c-border);
      border-radius: var(--radius-md);
      margin-top: 14px;
      overflow: hidden;
      box-shadow: var(--shadow-sm);
    }}
    .section-header {{
      padding: 14px 20px;
      border-bottom: 1px solid var(--c-border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      background: #fafbfc;
    }}
    .section-title {{
      font-size: 1rem;
      font-weight: 700;
      color: var(--c-text);
    }}
    .section-subtitle {{
      font-size: 0.8rem;
      color: var(--c-muted);
      margin-top: 2px;
    }}
    .section-body {{ padding: 16px 20px; }}

    /* ── Collapsible details ─────────────────────────────────── */
    details {{
      background: var(--c-surface);
      border: 1px solid var(--c-border);
      border-radius: var(--radius-md);
      margin-top: 14px;
      box-shadow: var(--shadow-sm);
      overflow: hidden;
    }}
    summary {{
      cursor: pointer;
      padding: 14px 20px;
      font-size: 0.95rem;
      font-weight: 700;
      color: var(--c-text);
      list-style: none;
      display: flex;
      align-items: center;
      gap: 10px;
      border-bottom: 1px solid transparent;
      transition: background .12s;
    }}
    summary::-webkit-details-marker {{ display: none; }}
    summary::before {{
      content: "▶";
      font-size: 0.6rem;
      color: var(--c-muted);
      transition: transform .2s;
      flex-shrink: 0;
    }}
    details[open] > summary {{ border-bottom-color: var(--c-border); background: #fafbfc; }}
    details[open] > summary::before {{ transform: rotate(90deg); }}
    .details-body {{ padding: 16px 20px; }}

    /* ── Tables ──────────────────────────────────────────────── */
    .tbl-wrap {{
      overflow: auto;
      border-radius: var(--radius-sm);
      border: 1px solid var(--c-border);
    }}
    .tbl-wrap table {{ border-collapse: separate; border-spacing: 0; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.84rem;
    }}
    thead th {{
      position: sticky;
      top: 0;
      z-index: 2;
      background: #f8fafc;
      padding: 9px 12px;
      text-align: left;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: .06em;
      font-weight: 700;
      color: var(--c-muted);
      border-bottom: 2px solid var(--c-border);
      white-space: nowrap;
    }}
    tbody tr {{ transition: background .08s; }}
    tbody tr:hover {{ background: #f8fafc; }}
    td {{
      padding: 9px 12px;
      vertical-align: top;
      border-bottom: 1px solid var(--c-border);
      word-break: break-word;
    }}
    tr:last-child td {{ border-bottom: none; }}
    .scrollable-tbl {{
      max-height: 520px;
      overflow-y: auto;
    }}

    /* ── Badges ──────────────────────────────────────────────── */
    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 2px 9px;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: .03em;
      white-space: nowrap;
    }}
    .b-green  {{ background: #dcfce7; color: #15803d; }}
    .b-red    {{ background: #fee2e2; color: #b91c1c; }}
    .b-orange {{ background: #ffedd5; color: #c2410c; }}
    .b-blue   {{ background: #dbeafe; color: #1d4ed8; }}
    .b-gray   {{ background: #f1f5f9; color: #475569; }}
    .b-purple {{ background: #ede9fe; color: #6d28d9; }}
    .b-sky    {{ background: #e0f2fe; color: #0369a1; }}

    /* Lynis status badges */
    .status-passed     {{ background: #dcfce7; color: #15803d; }}
    .status-suggestion {{ background: #fef9c3; color: #92400e; }}
    .status-warning    {{ background: #fee2e2; color: #b91c1c; }}
    .status-manual     {{ background: #ede9fe; color: #6d28d9; }}
    .status-skipped    {{ background: #f1f5f9; color: #475569; }}
    .priority-p1 {{ background: #fee2e2; color: #b91c1c; }}
    .priority-p2 {{ background: #ffedd5; color: #c2410c; }}
    .priority-p3 {{ background: #dbeafe; color: #1d4ed8; }}

    /* ── Typography helpers ──────────────────────────────────── */
    .mono  {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 0.83em; }}
    .muted {{ color: var(--c-muted); }}
    .small {{ font-size: 0.8em; }}
    .text-ok     {{ color: var(--c-ok); }}
    .text-warn   {{ color: var(--c-warn); }}
    .text-danger {{ color: var(--c-danger); font-weight: 700; }}
    .note-row td {{ color: var(--c-muted); font-style: italic; font-size: 0.82rem; text-align: center; }}

    /* ── Code blocks ─────────────────────────────────────────── */
    .code-block {{
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
      font-size: 0.78rem;
      background: #0f172a;
      color: #cbd5e1;
      border-radius: 6px;
      padding: 8px 10px;
      white-space: pre-wrap;
      max-height: 160px;
      overflow: auto;
      line-height: 1.45;
    }}

    /* ── Filters & search ────────────────────────────────────── */
    .filter-bar {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
      padding: 12px 20px;
      background: #fafbfc;
      border-bottom: 1px solid var(--c-border);
    }}
    .filter-btn {{
      border: 1px solid var(--c-border);
      border-radius: 999px;
      background: #fff;
      padding: 5px 13px;
      cursor: pointer;
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--c-muted);
      transition: all .12s;
    }}
    .filter-btn:hover {{ border-color: var(--c-primary); color: var(--c-primary); }}
    .filter-btn.active {{ background: var(--c-primary); border-color: var(--c-primary); color: #fff; }}
    .search-input {{
      border: 1px solid var(--c-border);
      border-radius: var(--radius-sm);
      padding: 6px 12px;
      font-size: 0.82rem;
      min-width: 220px;
      outline: none;
      color: var(--c-text);
      transition: border-color .15s;
    }}
    .search-input:focus {{ border-color: var(--c-primary); }}
    .filter-spacer {{ flex: 1; }}

    /* ── Lynis row highlight ─────────────────────────────────── */
    .row-warning  {{ background: #fffbfb; }}
    .row-warning:hover {{ background: #fff1f2; }}
    .row-suggestion {{ background: #fffdf0; }}
    .row-suggestion:hover {{ background: #fef9c3; }}
    .sshd-sec {{ background: #fffdf0; }}

    /* ── Score ring ──────────────────────────────────────────── */
    .score-ring-wrap {{
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
    }}

    /* ── Finding cell ────────────────────────────────────────── */
    .finding {{ max-width: 340px; }}

    /* ── Print ───────────────────────────────────────────────── */
    @media print {{
      .tabs, .filter-bar {{ display: none !important; }}
      .panel {{ display: block !important; }}
      details {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
<div class="page">

  <!-- ═══ HEADER ═════════════════════════════════════════════ -->
  <header class="hero">
    <div class="hero-left">
      <h1>Security Hardening Report</h1>
      <div class="hero-meta">
        <span>🖥 <b>Host:</b> {escape(hostname)}</span>
        <span>🐧 <b>OS:</b> {escape(os_name)}</span>
        <span>🔧 <b>Kernel:</b> {escape(kernel_version)}</span>
        <span>📅 <b>Generated:</b> {escape(generated_at)}</span>
        <span>🔍 <b>Lynis:</b> {escape(lynis_version)}</span>
      </div>
    </div>
    <div>{logo_html}</div>
  </header>

  <!-- ═══ STATS STRIP ════════════════════════════════════════ -->
  <div class="stats-strip">
    <div class="stat-card">
      <div class="stat-label">Hardening Score</div>
      <div class="stat-value {'ok' if hardening_score >= 75 else 'warn' if hardening_score >= 60 else 'danger'}">{hardening_score}<span style="font-size:1rem;font-weight:500">/100</span></div>
      <div class="stat-sub">{score_label}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Risk Level</div>
      <div class="stat-value {'ok' if risk_level == 'Controlled' else 'warn' if risk_level == 'Medium' else 'danger'}">{risk_level}</div>
      <div class="stat-sub">Based on Lynis score</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Warnings</div>
      <div class="stat-value {'danger' if warnings else 'ok'}">{len(warnings)}</div>
      <div class="stat-sub">Critical issues</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Suggestions</div>
      <div class="stat-value {'warn' if suggestions else 'ok'}">{len(suggestions)}</div>
      <div class="stat-sub">Improvement opportunities</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Tests Executed</div>
      <div class="stat-value">{tests_done}</div>
      <div class="stat-sub">{status_counts['passed']} passed · {status_counts['skipped']} skipped</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Uptime</div>
      <div class="stat-value" style="font-size:1rem;font-weight:700;line-height:1.3">{escape(uptime_human)}</div>
      <div class="stat-sub">Load: {escape(load_average)}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Scan Interval</div>
      <div class="stat-value" style="font-size:0.9rem;font-weight:700;line-height:1.4">{escape(started_at[:10] if started_at and started_at != "—" else "—")}</div>
      <div class="stat-sub">Started: {escape(started_at)}</div>
    </div>
  </div>

  <!-- ═══ TABS ════════════════════════════════════════════════ -->
  <div class="tabs">
    <button class="tab-btn active" data-tab="machine" type="button">🖥 Machine Information</button>
    <button class="tab-btn" data-tab="lynis" type="button">🔍 Lynis Scan Results</button>
  </div>

  <!-- ═══════════════════════════════════════════════════════════
       PANEL: MACHINE INFORMATION
  ════════════════════════════════════════════════════════════ -->
  <section id="panel-machine" class="panel active">

    <!-- System overview cards -->
    <div class="info-grid" style="margin-top:0">

      <div class="card">
        <div class="card-title">Host &amp; Runtime</div>
        <div class="kv-list">
          <div class="kv-row"><span class="kv-key">Hostname</span><span class="kv-val mono">{escape(hostname)}</span></div>
          <div class="kv-row"><span class="kv-key">OS</span><span class="kv-val">{escape(os_name)}</span></div>
          <div class="kv-row"><span class="kv-key">Kernel</span><span class="kv-val mono">{escape(kernel_version)}</span></div>
          <div class="kv-row"><span class="kv-key">Uptime</span><span class="kv-val">{escape(uptime_human)}</span></div>
          <div class="kv-row"><span class="kv-key">Load Average</span><span class="kv-val mono">{escape(load_average)}</span></div>
          <div class="kv-row"><span class="kv-key">Memory (kB)</span><span class="kv-val mono">{escape(memory_total_kb)}</span></div>
          <div class="kv-row"><span class="kv-key">Package Manager</span><span class="kv-val">{escape(package_manager_value)}</span></div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Security Controls</div>
        <div class="kv-list">
          <div class="kv-row"><span class="kv-key">Secure Boot</span><span class="kv-val">{escape(secure_boot_status)}</span></div>
          <div class="kv-row"><span class="kv-key">TPM</span><span class="kv-val">{escape(tpm_status)}</span></div>
          <div class="kv-row"><span class="kv-key">Disk Encryption</span><span class="kv-val">{escape(encryption_summary)}</span></div>
          <div class="kv-row"><span class="kv-key">Lynis Version</span><span class="kv-val mono">{escape(lynis_version)}</span></div>
          <div class="kv-row"><span class="kv-key">Scan Started</span><span class="kv-val mono">{escape(started_at)}</span></div>
          <div class="kv-row"><span class="kv-key">Scan Ended</span><span class="kv-val mono">{escape(ended_at)}</span></div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Locale &amp; Session</div>
        <div class="kv-list">
          <div class="kv-row"><span class="kv-key">Timezone</span><span class="kv-val">{escape(timezone)}</span></div>
          <div class="kv-row"><span class="kv-key">System Locale</span><span class="kv-val">{escape(system_locale)}</span></div>
          <div class="kv-row"><span class="kv-key">LANG</span><span class="kv-val mono">{escape(lang_value)}</span></div>
          <div class="kv-row"><span class="kv-key">Default Shell</span><span class="kv-val mono">{escape(shell_value)}</span></div>
          <div class="kv-row"><span class="kv-key">Keyboard Layout</span><span class="kv-val">{escape(keyboard_layout)}</span></div>
          <div class="kv-row"><span class="kv-key">Keyboard Model</span><span class="kv-val">{escape(keyboard_model)}</span></div>
        </div>
      </div>

      <div class="card" style="display:flex;flex-direction:column;align-items:center;gap:12px">
        <div class="card-title" style="width:100%">Hardening Score</div>
        <div class="score-ring-wrap">
          {score_svg}
          <span class="badge {risk_b_css}" style="font-size:0.82rem;padding:4px 14px">Risk: {risk_level}</span>
          <span class="muted small" style="text-align:center">{score_label} security posture</span>
          <div style="width:100%;background:#e2e8f0;border-radius:999px;height:8px;overflow:hidden">
            <div style="width:{hardening_score}%;height:100%;background:{score_color};border-radius:999px"></div>
          </div>
          <div style="display:flex;gap:16px;font-size:0.78rem;color:var(--c-muted);margin-top:4px">
            <span>✅ {pass_pct}% passed</span>
            <span>⚠️ {sugg_pct}% suggestions</span>
            <span>🔴 {warn_pct}% warnings</span>
          </div>
        </div>
      </div>

    </div>

    <!-- ── User Access & Auth Matrix ───────────────────────── -->
    <div class="section" style="margin-top:14px">
      <div class="section-header">
        <div>
          <div class="section-title">User Access &amp; Authentication Matrix</div>
          <div class="section-subtitle">Shell access, SSH eligibility, account state, auth methods, and authorized key footprint</div>
        </div>
      </div>
      <div class="section-body" style="padding:0">
        <div class="tbl-wrap scrollable-tbl">
          <table>
            <thead><tr>
              <th style="width:110px">User</th>
              <th style="width:60px">UID</th>
              <th style="width:120px">Shell</th>
              <th style="width:90px">Password</th>
              <th style="width:90px">SSH</th>
              <th>Auth Methods</th>
              <th style="width:80px">Keys</th>
              <th>Groups</th>
              <th>Key Preview</th>
            </tr></thead>
            <tbody>{"".join(user_auth_rows)}</tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ── Users & Accounts ─────────────────────────────────── -->
    <details open>
      <summary>👤 Users &amp; Accounts</summary>
      <div class="details-body">
        <div class="tbl-wrap" style="margin-bottom:14px">
          <table>
            <thead><tr><th>Username</th><th>UID</th><th>GID</th><th>Home Directory</th><th>Shell</th></tr></thead>
            <tbody>{"".join(user_rows)}</tbody>
          </table>
        </div>
        <div class="info-grid">
          <div class="card">
            <div class="card-title">Locked Accounts</div>
            <ul style="padding-left:18px;line-height:2">{"".join(locked_user_items)}</ul>
          </div>
          <div class="card">
            <div class="card-title">Home Directories</div>
            <ul style="padding-left:18px;line-height:1.8">{"".join(home_dir_items)}</ul>
          </div>
          <div class="card">
            <div class="card-title">Detected Filesystems</div>
            <ul style="padding-left:18px;line-height:1.8">{"".join(fs_items)}</ul>
          </div>
        </div>
      </div>
    </details>

    <!-- ── Network & Services ───────────────────────────────── -->
    <details>
      <summary>🌐 Network &amp; Services</summary>
      <div class="details-body">

        <!-- Service status table with search -->
        <div style="margin-bottom:6px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
          <span class="muted small">All systemd services with load, active, and enablement state</span>
          <input class="search-input" id="svc-search" placeholder="🔍  Filter services…" type="search" />
        </div>
        <div class="tbl-wrap scrollable-tbl" style="margin-bottom:16px">
          <table id="svc-table">
            <thead><tr>
              <th style="width:240px">Service Unit</th>
              <th style="width:80px">Load</th>
              <th style="width:90px">Active</th>
              <th style="width:90px">Sub-State</th>
              <th style="width:90px">Enabled</th>
              <th>Description</th>
            </tr></thead>
            <tbody>{"".join(service_status_rows)}</tbody>
          </table>
        </div>

        <div class="info-grid">
          <div class="card">
            <div class="card-title">Open Ports (ss)</div>
            <div class="tbl-wrap" style="max-height:280px">
              <table><thead><tr><th>Entry</th></tr></thead>
              <tbody>{"".join(port_rows)}</tbody></table>
            </div>
          </div>
          <div class="card">
            <div class="card-title">Network Listeners (Lynis)</div>
            <div class="tbl-wrap" style="max-height:280px">
              <table><thead><tr><th>Entry</th></tr></thead>
              <tbody>{"".join(listener_rows)}</tbody></table>
            </div>
          </div>
          <div class="card">
            <div class="card-title">Running Services (Lynis)</div>
            <ul style="padding-left:18px;line-height:1.9">
              {"".join(f"<li class='mono'>{escape(i)}</li>" for i in running_services[:80]) or "<li>—</li>"}
            </ul>
          </div>
          <div class="card">
            <div class="card-title">Enabled at Boot (Lynis)</div>
            <ul style="padding-left:18px;line-height:1.9">
              {"".join(f"<li class='mono'>{escape(i)}</li>" for i in boot_services[:80]) or "<li>—</li>"}
            </ul>
          </div>
        </div>

      </div>
    </details>

    <!-- ── Filesystem & Permissions ─────────────────────────── -->
    <details>
      <summary>📁 Filesystem &amp; Permissions</summary>
      <div class="details-body">
        <div class="info-grid" style="margin-bottom:14px">
          <div class="card" style="grid-column:span 2">
            <div class="card-title">Important Path Permissions</div>
            <div class="tbl-wrap" style="max-height:300px">
              <table>
                <thead><tr><th>Path</th><th>Permissions</th><th>Owner</th><th>Group</th></tr></thead>
                <tbody>{"".join(path_rows)}</tbody>
              </table>
            </div>
          </div>
        </div>
        <div class="info-grid">
          <div class="card">
            <div class="card-title">Mount Points</div>
            <div class="tbl-wrap" style="max-height:280px">
              <table><thead><tr><th>Entry</th></tr></thead>
              <tbody>{"".join(mount_rows)}</tbody></table>
            </div>
          </div>
          <div class="card">
            <div class="card-title">SUID / SGID Files (sample)</div>
            <div class="tbl-wrap" style="max-height:280px">
              <table><thead><tr><th>File</th></tr></thead>
              <tbody>{"".join(suid_rows)}</tbody></table>
            </div>
          </div>
          <div class="card">
            <div class="card-title">World-Writable Files (sample)</div>
            <div class="tbl-wrap" style="max-height:280px">
              <table><thead><tr><th>File</th></tr></thead>
              <tbody>{"".join(ww_rows)}</tbody></table>
            </div>
          </div>
        </div>
      </div>
    </details>

    <!-- ── Hardening Baseline ────────────────────────────────── -->
    <details>
      <summary>🛡 Hardening Baseline</summary>
      <div class="details-body">
        <div class="info-grid">

          <div class="card">
            <div class="card-title">Security Sysctl Parameters</div>
            <div class="tbl-wrap" style="max-height:400px">
              <table>
                <thead><tr><th>Parameter</th><th>Value</th></tr></thead>
                <tbody>{"".join(sysctl_rows)}</tbody>
              </table>
            </div>
          </div>

          <div class="card">
            <div class="card-title">SSH Effective Config (sshd -T)</div>
            <p class="muted small" style="margin-bottom:8px">Highlighted rows are security-relevant settings</p>
            <div class="tbl-wrap" style="max-height:400px">
              <table>
                <thead><tr><th>Directive</th><th>Value</th></tr></thead>
                <tbody>{"".join(sshd_rows)}</tbody>
              </table>
            </div>
          </div>

          <div class="card">
            <div class="card-title">Pending Package Updates ({len(upgradeable_packages)})</div>
            <div class="tbl-wrap" style="max-height:400px">
              <table><thead><tr><th>Package</th></tr></thead>
              <tbody>{"".join(upg_rows)}</tbody></table>
            </div>
          </div>

          <div class="card">
            <div class="card-title">Certificate Expiry (sample)</div>
            <div class="tbl-wrap" style="max-height:400px">
              <table><thead><tr><th>Certificate</th></tr></thead>
              <tbody>{"".join(cert_rows)}</tbody></table>
            </div>
          </div>

        </div>
      </div>
    </details>

    <!-- ── Firewall Rules ────────────────────────────────────── -->
    <details>
      <summary>🔥 Firewall Rules</summary>
      <div class="details-body">
        <div class="info-grid">
          <div class="card">
            <div class="card-title">NFTables Rules</div>
            <div class="tbl-wrap" style="max-height:400px">
              <table><thead><tr><th>Rule</th></tr></thead>
              <tbody>{"".join(nft_rows_t)}</tbody></table>
            </div>
          </div>
          <div class="card">
            <div class="card-title">iptables Rules</div>
            <div class="tbl-wrap" style="max-height:400px">
              <table><thead><tr><th>Rule</th></tr></thead>
              <tbody>{"".join(ipt_rows_t)}</tbody></table>
            </div>
          </div>
        </div>
      </div>
    </details>

    <!-- ── Critical Config Files ─────────────────────────────── -->
    <details>
      <summary>📄 Critical Configuration Files Snapshot</summary>
      <div class="details-body">
        <p class="muted small" style="margin-bottom:12px">
          Content preview of security-relevant files: MOTD, SSH, PAM, sudoers, audit, syslog, and kernel tuning.
        </p>
        <div class="tbl-wrap scrollable-tbl">
          <table>
            <thead><tr>
              <th style="width:200px">File Path</th>
              <th style="width:60px">Present</th>
              <th style="width:80px">Mode</th>
              <th style="width:120px">Owner:Group</th>
              <th style="width:70px">Size</th>
              <th>Content Preview</th>
            </tr></thead>
            <tbody>{"".join(important_file_rows)}</tbody>
          </table>
        </div>
      </div>
    </details>

  </section>

  <!-- ═══════════════════════════════════════════════════════════
       PANEL: LYNIS SCAN RESULTS
  ════════════════════════════════════════════════════════════ -->
  <section id="panel-lynis" class="panel">

    <!-- ── KPI Strip ────────────────────────────────────────── -->
    <div class="info-grid" style="margin-top:0">
      <div class="card" style="text-align:center">
        <div class="card-title">Score</div>
        {score_svg}
      </div>
      <div class="card">
        <div class="card-title">Test Results Breakdown</div>
        <div class="kv-list">
          <div class="kv-row"><span class="kv-key">✅ Passed</span><span class="kv-val text-ok">{status_counts['passed']}</span></div>
          <div class="kv-row"><span class="kv-key">⚠️ Suggestions</span><span class="kv-val text-warn">{status_counts['suggestion']}</span></div>
          <div class="kv-row"><span class="kv-key">🔴 Warnings</span><span class="kv-val text-danger">{status_counts['warning']}</span></div>
          <div class="kv-row"><span class="kv-key">🔵 Manual review</span><span class="kv-val">{status_counts['manual']}</span></div>
          <div class="kv-row"><span class="kv-key">⏭ Skipped</span><span class="kv-val muted">{status_counts['skipped']}</span></div>
          <div class="kv-row" style="border:none"><span class="kv-key">📊 Total checks</span><span class="kv-val">{total_checks}</span></div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">Priority Distribution</div>
        <div class="kv-list">
          <div class="kv-row"><span class="kv-key"><span class="badge priority-p1">P1</span> Critical</span><span class="kv-val text-danger">{priority_counts['P1']}</span></div>
          <div class="kv-row"><span class="kv-key"><span class="badge priority-p2">P2</span> Important</span><span class="kv-val text-warn">{priority_counts['P2']}</span></div>
          <div class="kv-row"><span class="kv-key"><span class="badge priority-p3">P3</span> Low</span><span class="kv-val">{priority_counts['P3']}</span></div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">Risk Assessment</div>
        <div style="margin:12px 0;font-size:2rem;text-align:center">
          {'🔴' if hardening_score < 60 else '🟡' if hardening_score < 80 else '🟢'}
        </div>
        <div style="text-align:center;font-size:1.2rem;font-weight:700;color:{'#b91c1c' if hardening_score < 60 else '#d97706' if hardening_score < 80 else '#15803d'}">{risk_level}</div>
        <div class="muted small" style="text-align:center;margin-top:6px">Overall risk level based on hardening index</div>
      </div>
    </div>

    <!-- ── Priority Action Plan ──────────────────────────────── -->
    <div class="section" style="margin-top:14px">
      <div class="section-header">
        <div>
          <div class="section-title">🎯 Priority Action Plan</div>
          <div class="section-subtitle">Top findings that require immediate attention — sorted by priority</div>
        </div>
      </div>
      <div class="section-body" style="padding:0">
        <div class="tbl-wrap scrollable-tbl">
          <table>
            <thead><tr>
              <th style="width:70px">Priority</th>
              <th style="width:100px">Test ID</th>
              <th style="width:90px">Type</th>
              <th>Finding</th>
              <th>Recommended Action</th>
            </tr></thead>
            <tbody>{"".join(top_action_rows)}</tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ── Key Warnings ──────────────────────────────────────── -->
    <div class="section" style="margin-top:14px">
      <div class="section-header">
        <div class="section-title">🔴 Key Warnings</div>
      </div>
      <div class="section-body" style="padding:0">
        <div class="tbl-wrap">
          <table>
            <thead><tr><th style="width:120px">Test ID</th><th>Warning Message</th></tr></thead>
            <tbody>{"".join(warning_rows)}</tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ── Full Test Results (filterable) ───────────────────── -->
    <div class="section" style="margin-top:14px">
      <div class="section-header">
        <div>
          <div class="section-title">📋 Full Test Results</div>
          <div class="section-subtitle">All {len(tests_executed)} executed tests — filter by status or priority</div>
        </div>
      </div>
      <div class="filter-bar" id="lynis-filters">
        <div id="status-filters" style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="filter-btn active" data-filter="all" type="button">All</button>
          <button class="filter-btn" data-filter="warning" type="button">🔴 Warning</button>
          <button class="filter-btn" data-filter="suggestion" type="button">⚠️ Suggestion</button>
          <button class="filter-btn" data-filter="manual" type="button">🔵 Manual</button>
          <button class="filter-btn" data-filter="passed" type="button">✅ Passed</button>
          <button class="filter-btn" data-filter="skipped" type="button">⏭ Skipped</button>
        </div>
        <div id="priority-filters" style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="filter-btn active" data-priority-filter="all" type="button">All Priorities</button>
          <button class="filter-btn" data-priority-filter="P1" type="button">P1</button>
          <button class="filter-btn" data-priority-filter="P2" type="button">P2</button>
          <button class="filter-btn" data-priority-filter="P3" type="button">P3</button>
        </div>
        <span class="filter-spacer"></span>
        <input class="search-input" id="test-search" placeholder="🔍  Search tests…" type="search" />
      </div>
      <div style="padding:0">
        <div class="tbl-wrap scrollable-tbl">
          <table id="tests-table">
            <thead><tr>
              <th style="width:100px">Test ID</th>
              <th style="width:90px">Status</th>
              <th style="width:70px">Priority</th>
              <th>Result / Finding</th>
              <th>Recommendation</th>
              <th style="width:120px">Component</th>
              <th>Technical Details</th>
            </tr></thead>
            <tbody>{"".join(test_rows)}</tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ── Detailed Recommendations ─────────────────────────── -->
    <details>
      <summary>💡 Detailed Recommendations ({len(suggestions)})</summary>
      <div class="details-body" style="padding:0">
        <div class="tbl-wrap scrollable-tbl">
          <table>
            <thead><tr><th style="width:110px">Test ID</th><th>Finding</th><th>Recommendation</th></tr></thead>
            <tbody>{"".join(recommendation_rows)}</tbody>
          </table>
        </div>
      </div>
    </details>

    <!-- ── Manual Tasks ──────────────────────────────────────── -->
    <details>
      <summary>🔵 Manual Verification Tasks</summary>
      <div class="details-body">
        <ul style="padding-left:20px;line-height:2">{"".join(manual_items)}</ul>
      </div>
    </details>

    <!-- ── Skipped Tests ─────────────────────────────────────── -->
    <details>
      <summary>⏭ Skipped Tests Analysis ({skipped_total})</summary>
      <div class="details-body" style="padding:0">
        <div class="tbl-wrap scrollable-tbl">
          <table>
            <thead><tr><th style="width:110px">Test ID</th><th style="width:80px">Family</th><th>Reason</th><th style="width:90px">Source</th></tr></thead>
            <tbody>{"".join(skipped_rows_raw)}</tbody>
          </table>
        </div>
      </div>
    </details>

  </section>

</div><!-- /page -->

<script>
(function () {{
  /* Tab switching */
  document.querySelectorAll(".tab-btn").forEach(function (btn) {{
    btn.addEventListener("click", function () {{
      var tab = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-btn").forEach(function (b) {{ b.classList.remove("active"); }});
      btn.classList.add("active");
      document.getElementById("panel-machine").classList.toggle("active", tab === "machine");
      document.getElementById("panel-lynis").classList.toggle("active", tab === "lynis");
    }});
  }});

  /* Lynis test filter */
  var rows = Array.from(document.querySelectorAll("#tests-table tbody tr"));
  var activeStatus = "all";
  var activePriority = "all";
  var testSearch = "";

  function applyTestFilters() {{
    rows.forEach(function (row) {{
      var rs = row.getAttribute("data-status") || "";
      var rp = row.getAttribute("data-priority") || "";
      var text = row.textContent.toLowerCase();
      var sm = activeStatus === "all" || rs === activeStatus;
      var pm = activePriority === "all" || rp === activePriority;
      var qm = testSearch === "" || text.indexOf(testSearch) !== -1;
      row.style.display = (sm && pm && qm) ? "" : "none";
    }});
  }}

  document.querySelectorAll("#status-filters .filter-btn").forEach(function (btn) {{
    btn.addEventListener("click", function () {{
      activeStatus = btn.getAttribute("data-filter") || "all";
      document.querySelectorAll("#status-filters .filter-btn").forEach(function (b) {{
        b.classList.toggle("active", b.getAttribute("data-filter") === activeStatus);
      }});
      applyTestFilters();
    }});
  }});

  document.querySelectorAll("#priority-filters .filter-btn").forEach(function (btn) {{
    btn.addEventListener("click", function () {{
      activePriority = btn.getAttribute("data-priority-filter") || "all";
      document.querySelectorAll("#priority-filters .filter-btn").forEach(function (b) {{
        b.classList.toggle("active", b.getAttribute("data-priority-filter") === activePriority);
      }});
      applyTestFilters();
    }});
  }});

  var testSearchInput = document.getElementById("test-search");
  if (testSearchInput) {{
    testSearchInput.addEventListener("input", function () {{
      testSearch = testSearchInput.value.toLowerCase().trim();
      applyTestFilters();
    }});
  }}

  /* Service table search */
  var svcRows = Array.from(document.querySelectorAll("#svc-table tbody tr"));
  var svcSearchInput = document.getElementById("svc-search");
  if (svcSearchInput) {{
    svcSearchInput.addEventListener("input", function () {{
      var q = svcSearchInput.value.toLowerCase().trim();
      svcRows.forEach(function (row) {{
        row.style.display = (q === "" || row.textContent.toLowerCase().indexOf(q) !== -1) ? "" : "none";
      }});
    }});
  }}
}})();
</script>
</body>
</html>
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a professional HTML report from a Lynis report.dat file."
    )
    parser.add_argument(
        "--report",
        default=None,
        help="Path to the Lynis report.dat file. Default: reports/report_<hostname>_<YYYY-MM-DD>.dat",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output HTML path. Default: results/report_<server-name>_<YYYY-MM-DD>.html",
    )
    parser.add_argument(
        "--logo",
        default=None,
        help="Path to a PNG company logo to include in the report.",
    )
    parser.add_argument(
        "--system-data",
        default=None,
        help="Optional path to extra system snapshot data (default: infer from report name).",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Optional Lynis log file to extract skipped test reasons (default: infer from report name).",
    )
    parser.add_argument(
        "--full-run",
        action="store_true",
        default=True,
        help="Install tools, run scans, collect data, and then generate the HTML report (default behavior).",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Skip scans and generate HTML from existing data files only.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    report_path = Path(args.report) if args.report else default_report_path()
    inferred_system_path = default_system_data_path(report_path)
    system_data_path = Path(args.system_data) if args.system_data else inferred_system_path
    inferred_log_path = default_log_path(report_path)
    log_path = Path(args.log_file) if args.log_file else inferred_log_path

    run_full = args.full_run and not args.report_only

    if run_full:
        run_full_collection(
            report_path=report_path,
            log_path=log_path,
            system_data_path=system_data_path,
        )
    elif not report_path.exists():
        parser.error(f"Input report file not found: {report_path}")

    if not report_path.exists():
        parser.error(f"Expected report file not found after collection: {report_path}")

    parsed = parse_report_file(report_path)
    output_path = Path(args.output) if args.output else default_output_path(parsed)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    logo_path = Path(args.logo) if args.logo else None
    logo_data_uri = build_logo_data_uri(logo_path)

    system_data: ParsedReport | None = None
    if system_data_path.exists():
        system_data = parse_report_file(system_data_path)

    output_path.write_text(
        render_html(
            parsed,
            report_path,
            logo_data_uri,
            system_data=system_data,
            log_path=log_path,
        ),
        encoding="utf-8",
    )
    print(f"HTML report successfully generated: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
