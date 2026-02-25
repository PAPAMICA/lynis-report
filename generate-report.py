#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import html
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
from xml.etree import ElementTree as ET


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


def default_openscap_data_path(report_path: Path) -> Path:
    filename = report_path.name
    if filename.startswith("report_") and filename.endswith(".dat"):
        return report_path.with_name("openscap_" + filename[len("report_"):])
    return report_path.with_name("openscap_snapshot.dat")


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


def ensure_openscap_installed() -> None:
    if shutil.which("oscap"):
        return
    manager = detect_package_manager()
    candidates = {
        "apt": ["openscap-scanner", "ssg-debderived"],
        "dnf": ["openscap-scanner", "scap-security-guide"],
        "yum": ["openscap-scanner", "scap-security-guide"],
        "zypper": ["openscap-utils", "scap-security-guide"],
        "pacman": ["openscap"],
        "apk": ["openscap-scanner"],
    }
    for pkg in candidates.get(manager, ["openscap-scanner"]):
        try:
            install_package(pkg)
        except Exception:
            continue
        if shutil.which("oscap"):
            return
    if not shutil.which("oscap"):
        raise RuntimeError("OpenSCAP installation failed.")


def find_openscap_datastream() -> Path | None:
    candidates = [
        "/usr/share/xml/scap/ssg/content/ssg-debian-ds.xml",
        "/usr/share/xml/scap/ssg/content/ssg-ubuntu-ds.xml",
        "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml",
        "/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml",
        "/usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml",
    ]
    for candidate in candidates:
        path = Path(candidate)
        if path.exists():
            return path
    return None


def parse_openscap_results(results_xml: Path) -> Dict[str, str]:
    summary = {
        "openscap_total_rules": "0",
        "openscap_passed_rules": "0",
        "openscap_failed_rules": "0",
        "openscap_error_rules": "0",
        "openscap_notchecked_rules": "0",
    }
    if not results_xml.exists():
        return summary

    try:
        tree = ET.parse(results_xml)
    except ET.ParseError:
        return summary
    root = tree.getroot()
    counts = {"pass": 0, "fail": 0, "error": 0, "notchecked": 0, "notselected": 0, "informational": 0}
    for elem in root.iter():
        tag = elem.tag.split("}", 1)[-1]
        if tag != "rule-result":
            continue
        result_node = None
        for child in elem:
            child_tag = child.tag.split("}", 1)[-1]
            if child_tag == "result":
                result_node = child
                break
        if result_node is None or not result_node.text:
            continue
        key = result_node.text.strip().lower()
        if key in counts:
            counts[key] += 1

    total = sum(counts.values())
    summary["openscap_total_rules"] = str(total)
    summary["openscap_passed_rules"] = str(counts["pass"])
    summary["openscap_failed_rules"] = str(counts["fail"])
    summary["openscap_error_rules"] = str(counts["error"])
    summary["openscap_notchecked_rules"] = str(counts["notchecked"] + counts["notselected"])
    return summary


def run_full_collection(report_path: Path, log_path: Path, system_data_path: Path, openscap_data_path: Path) -> None:
    ensure_lynis_installed()
    ensure_openscap_installed()

    report_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    system_data_path.parent.mkdir(parents=True, exist_ok=True)
    openscap_data_path.parent.mkdir(parents=True, exist_ok=True)

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

    datastream = find_openscap_datastream()
    openscap_html = openscap_data_path.with_suffix(".html")
    openscap_xml = openscap_data_path.with_suffix(".xml")

    openscap_meta = {
        "openscap_status": "not_run",
        "openscap_profile": "N/A",
        "openscap_datastream": "N/A",
    }

    if datastream is not None:
        profile = "xccdf_org.ssgproject.content_profile_standard"
        try:
            run_cmd(
                [
                    "oscap",
                    "xccdf",
                    "eval",
                    "--profile",
                    profile,
                    "--results",
                    str(openscap_xml),
                    "--report",
                    str(openscap_html),
                    str(datastream),
                ],
                use_sudo=True,
                check=False,
            )
            openscap_meta["openscap_status"] = "completed"
            openscap_meta["openscap_profile"] = profile
            openscap_meta["openscap_datastream"] = str(datastream)
            openscap_meta.update(parse_openscap_results(openscap_xml))
        except Exception:
            openscap_meta["openscap_status"] = "failed"
    else:
        openscap_meta["openscap_status"] = "datastream_not_found"

    failed_rule_lines: List[str] = []
    if openscap_xml.exists():
        try:
            tree = ET.parse(openscap_xml)
        except ET.ParseError:
            tree = None
        if tree is not None:
            root = tree.getroot()
        else:
            root = None
    else:
        root = None
    if root is not None:
        for elem in root.iter():
            tag = elem.tag.split("}", 1)[-1]
            if tag != "rule-result":
                continue
            rule_id = elem.attrib.get("idref", "N/A")
            result_value = ""
            for child in elem:
                if child.tag.split("}", 1)[-1] == "result" and child.text:
                    result_value = child.text.strip().lower()
                    break
            if result_value == "fail":
                failed_rule_lines.append(f"openscap_failed_rule[]={rule_id}")

    with openscap_data_path.open("w", encoding="utf-8") as handle:
        handle.write("# OpenSCAP snapshot\n")
        handle.write(f"openscap_datetime={datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        for key, value in openscap_meta.items():
            handle.write(f"{key}={value}\n")
        for line in failed_rule_lines[:200]:
            handle.write(line + "\n")


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


def render_html(
    parsed: ParsedReport,
    report_path: Path,
    logo_data_uri: str,
    system_data: ParsedReport | None = None,
    openscap_data: ParsedReport | None = None,
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
    oscap_values = openscap_data.values if openscap_data else {}
    oscap_arrays = openscap_data.arrays if openscap_data else {}

    timezone = sys_values.get("timezone", "Unknown")
    keyboard_layout = sys_values.get("keyboard_layout", "Unknown")
    keyboard_model = sys_values.get("keyboard_model", "Unknown")
    system_locale = sys_values.get("system_locale", "Unknown")
    lang_value = sys_values.get("lang", "Unknown")
    shell_value = sys_values.get("shell", "Unknown")
    package_manager_value = sys_values.get("package_manager", "Unknown")
    secure_boot_status = sys_values.get("secure_boot_status", "Unknown")
    tpm_status = sys_values.get("tpm_status", "Unknown")
    encryption_summary = sys_values.get("encryption_summary", "Unknown")
    uptime_human = sys_values.get("uptime_human", "Unknown")
    load_average = sys_values.get("load_average", "Unknown")
    memory_total_kb = sys_values.get("memory_total_kb", "Unknown")

    user_entries = sys_arrays.get("real_user", report_real_users)
    locked_users = sys_arrays.get("locked_user", arrays.get("locked_account", []))
    important_paths = sys_arrays.get("important_path", [])
    mount_info = sys_arrays.get("mount_info", [])
    open_ports = sys_arrays.get("open_port", [])
    running_services_full = sys_arrays.get("running_service_full", [])
    sshd_effective = sys_arrays.get("sshd_effective", [])
    security_sysctl = sys_arrays.get("security_sysctl", [])
    upgradeable_packages = sys_arrays.get("upgradeable_package", [])
    nft_rules = sys_arrays.get("firewall_rule_nft", [])
    iptables_rules = sys_arrays.get("firewall_rule_iptables", [])
    suid_sgid_files = sys_arrays.get("suid_sgid_file", [])
    world_writable_files = sys_arrays.get("world_writable_file", [])
    cert_expiry = sys_arrays.get("cert_expiry", [])
    openscap_failed_rules = oscap_arrays.get("openscap_failed_rule", [])

    recommendation_rows: List[str] = []
    for entry in suggestions:
        test_id, message, advice = parse_recommendation(entry)
        recommendation_rows.append(
            "<tr>"
            f"<td>{escape(test_id)}</td>"
            f"<td>{escape(message or 'No message provided')}</td>"
            f"<td>{escape(advice or 'No additional recommendation')}</td>"
            "</tr>"
        )
    if not recommendation_rows:
        recommendation_rows.append("<tr><td colspan='3'>Aucune recommandation detectee.</td></tr>")

    warning_items: List[str] = []
    for entry in warnings:
        test_id, message, _ = parse_recommendation(entry)
        warning_items.append(f"<li><strong>{escape(test_id)}</strong> - {escape(message)}</li>")
    if not warning_items:
        warning_items.append("<li>Aucune alerte critique.</li>")

    manual_items = [f"<li>{escape(item)}</li>" for item in manual_actions] or [
        "<li>Aucune verification manuelle listee.</li>"
    ]

    user_rows: List[str] = []
    for entry in user_entries:
        parts = [item.strip() for item in entry.split(",")]
        username = parts[0] if len(parts) > 0 else "N/A"
        uid = parts[1] if len(parts) > 1 else "N/A"
        gid = parts[2] if len(parts) > 2 else "N/A"
        home = parts[3] if len(parts) > 3 else "N/A"
        shell = parts[4] if len(parts) > 4 else "N/A"
        user_rows.append(
            "<tr>"
            f"<td>{escape(username)}</td><td>{escape(uid)}</td><td>{escape(gid)}</td>"
            f"<td>{escape(home)}</td><td>{escape(shell)}</td>"
            "</tr>"
        )
    if not user_rows:
        user_rows.append("<tr><td colspan='5'>Aucune information utilisateur disponible.</td></tr>")

    path_rows: List[str] = []
    for entry in important_paths:
        parts = [item.strip() for item in entry.split(",", 3)]
        perm = parts[0] if len(parts) > 0 else "N/A"
        owner = parts[1] if len(parts) > 1 else "N/A"
        group = parts[2] if len(parts) > 2 else "N/A"
        path = parts[3] if len(parts) > 3 else "N/A"
        path_rows.append(
            "<tr>"
            f"<td>{escape(path)}</td><td>{escape(perm)}</td><td>{escape(owner)}</td><td>{escape(group)}</td>"
            "</tr>"
        )
    if not path_rows:
        path_rows.append("<tr><td colspan='4'>Aucun chemin sensible disponible.</td></tr>")

    service_items = [f"<li>{escape(item)}</li>" for item in running_services] or ["<li>N/A</li>"]
    boot_service_items = [f"<li>{escape(item)}</li>" for item in boot_services] or ["<li>N/A</li>"]
    locked_user_items = [f"<li>{escape(item)}</li>" for item in locked_users] or ["<li>Aucun</li>"]
    home_dir_items = [f"<li>{escape(item)}</li>" for item in report_home_directories[:60]] or ["<li>N/A</li>"]
    fs_items = [f"<li>{escape(item)}</li>" for item in report_filesystems[:40]] or ["<li>N/A</li>"]
    mount_items = [f"<li>{escape(item)}</li>" for item in mount_info[:40]] or ["<li>N/A</li>"]
    network_listener_items = [f"<li>{escape(item)}</li>" for item in network_listeners] or ["<li>N/A</li>"]
    open_port_items = [f"<li>{escape(item)}</li>" for item in open_ports[:60]] or ["<li>N/A</li>"]
    running_service_full_items = [f"<li>{escape(item)}</li>" for item in running_services_full[:80]] or ["<li>N/A</li>"]
    sshd_effective_items = [f"<li>{escape(item)}</li>" for item in sshd_effective[:120]] or ["<li>N/A</li>"]
    security_sysctl_items = [f"<li>{escape(item)}</li>" for item in security_sysctl] or ["<li>N/A</li>"]
    upgradeable_package_items = [f"<li>{escape(item)}</li>" for item in upgradeable_packages[:300]] or [
        "<li>Aucune mise a jour en attente signalee.</li>"
    ]
    nft_rule_items = [f"<li>{escape(item)}</li>" for item in nft_rules[:260]] or ["<li>N/A</li>"]
    iptables_rule_items = [f"<li>{escape(item)}</li>" for item in iptables_rules[:260]] or ["<li>N/A</li>"]
    suid_sgid_items = [f"<li>{escape(item)}</li>" for item in suid_sgid_files[:300]] or ["<li>N/A</li>"]
    world_writable_items = [f"<li>{escape(item)}</li>" for item in world_writable_files[:300]] or [
        "<li>Aucun fichier world-writable detecte dans l'echantillon.</li>"
    ]
    cert_expiry_items = [f"<li>{escape(item)}</li>" for item in cert_expiry[:200]] or ["<li>N/A</li>"]
    openscap_failed_rule_items = [f"<li>{escape(item)}</li>" for item in openscap_failed_rules[:200]] or [
        "<li>Aucune regle en echec ou scan indisponible.</li>"
    ]

    skipped_reason_map = parse_skip_reasons_from_log(log_path)
    test_rows, status_counts, priority_counts, actions, skipped_rows = build_test_rows(
        parsed, skipped_reason_map=skipped_reason_map
    )
    skipped_rows = skipped_rows or [
        "<tr><td colspan='4'>Aucun test ignore detecte.</td></tr>"
    ]
    top_actions = actions[:12]
    top_action_rows: List[str] = []
    for action in top_actions:
        top_action_rows.append(
            "<tr>"
            f"<td><span class='badge priority-{action['priority'].lower()}'>{escape(action['priority'])}</span></td>"
            f"<td>{escape(action['test_id'])}</td>"
            f"<td><span class='badge status-{action['status'].lower()}'>{escape(action['status'])}</span></td>"
            f"<td>{action['summary_html']}</td>"
            f"<td>{action['recommendation_html']}</td>"
            "</tr>"
        )
    if not top_action_rows:
        top_action_rows.append("<tr><td colspan='5'>Aucune action prioritaire. Tous les tests passent.</td></tr>")

    total_checks = max(1, len(tests_executed) + len(tests_skipped))
    pass_pct = int((status_counts["passed"] / total_checks) * 100)
    warn_pct = int((status_counts["warning"] / total_checks) * 100)
    sugg_pct = int((status_counts["suggestion"] / total_checks) * 100)
    risk_level = "Eleve" if hardening_score < 60 else "Modere" if hardening_score < 80 else "Maitrise"
    risk_css = "risk-high" if hardening_score < 60 else "risk-medium" if hardening_score < 80 else "risk-low"
    openscap_status = oscap_values.get("openscap_status", "not_available")
    openscap_profile = oscap_values.get("openscap_profile", "N/A")
    openscap_total_rules = oscap_values.get("openscap_total_rules", "0")
    openscap_passed_rules = oscap_values.get("openscap_passed_rules", "0")
    openscap_failed_rules_count = oscap_values.get("openscap_failed_rules", "0")
    openscap_error_rules = oscap_values.get("openscap_error_rules", "0")
    openscap_datastream = oscap_values.get("openscap_datastream", "N/A")

    logo_html = f"<img src='{logo_data_uri}' alt='Logo' class='logo' />" if logo_data_uri else ""
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Rapport de durcissement Lynis - {escape(hostname)}</title>
  <style>
    :root {{
      --bg: #f4f7fb;
      --surface: #ffffff;
      --line: #e2e8f0;
      --text: #0f172a;
      --muted: #64748b;
      --primary: #2563eb;
      --ok: #16a34a;
      --warn: #d97706;
      --danger: #dc2626;
      --violet: #7c3aed;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      background: linear-gradient(180deg, #eef4ff 0%, var(--bg) 240px, var(--bg) 100%);
      color: var(--text);
      line-height: 1.5;
    }}
    .container {{
      max-width: 1380px;
      margin: 0 auto;
      padding: 24px;
    }}
    .hero {{
      background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 55%, #1d4ed8 100%);
      color: #eff6ff;
      border-radius: 20px;
      padding: 22px;
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: flex-start;
      box-shadow: 0 18px 40px rgba(30, 58, 138, 0.28);
    }}
    .hero h1 {{
      margin: 0 0 8px;
      letter-spacing: -0.02em;
      font-size: 1.7rem;
    }}
    .hero p {{
      margin: 0;
      color: #dbeafe;
    }}
    .logo {{
      max-height: 72px;
      max-width: 220px;
      border-radius: 10px;
      background: rgba(255,255,255,0.16);
      padding: 8px;
    }}
    .tabs {{
      margin-top: 14px;
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }}
    .tab-btn {{
      border: 1px solid #bfdbfe;
      background: #ffffff;
      color: #1d4ed8;
      font-weight: 600;
      border-radius: 999px;
      padding: 8px 14px;
      cursor: pointer;
    }}
    .tab-btn.active {{
      color: #ffffff;
      background: var(--primary);
      border-color: var(--primary);
    }}
    .panel {{
      display: none;
      margin-top: 14px;
    }}
    .panel.active {{
      display: block;
    }}
    .grid {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
      box-shadow: 0 8px 18px rgba(15, 23, 42, 0.06);
    }}
    .card h2 {{
      margin: 0 0 8px;
      font-size: 1rem;
      letter-spacing: -0.01em;
    }}
    .kpi {{
      font-size: 1.9rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      margin: 2px 0 4px;
    }}
    .muted {{ color: var(--muted); font-size: 0.92rem; }}
    .score-excellent, .score-good {{ color: var(--ok); }}
    .score-fair {{ color: var(--warn); }}
    .score-poor {{ color: var(--danger); }}
    .risk-pill {{
      display: inline-block;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 0.8rem;
      font-weight: 700;
    }}
    .risk-high {{ background: #fee2e2; color: #991b1b; }}
    .risk-medium {{ background: #fef3c7; color: #92400e; }}
    .risk-low {{ background: #dcfce7; color: #166534; }}
    .progress {{
      height: 10px;
      border-radius: 999px;
      background: #e2e8f0;
      overflow: hidden;
      margin-top: 8px;
    }}
    .progress > span {{
      display: block;
      height: 100%;
      background: linear-gradient(90deg, #2563eb 0%, #3b82f6 100%);
    }}
    .donut {{
      width: 140px;
      height: 140px;
      margin: 0 auto;
      border-radius: 50%;
      background: conic-gradient(var(--ok) 0% {pass_pct}%, var(--warn) {pass_pct}% {pass_pct + sugg_pct}%, var(--danger) {pass_pct + sugg_pct}% {pass_pct + sugg_pct + warn_pct}%, #cbd5e1 {pass_pct + sugg_pct + warn_pct}% 100%);
      position: relative;
    }}
    .donut::after {{
      content: "{hardening_score}/100";
      position: absolute;
      inset: 18px;
      border-radius: 50%;
      background: #fff;
      display: grid;
      place-items: center;
      font-weight: 800;
      color: #1e293b;
      font-size: 1.2rem;
    }}
    .section {{
      margin-top: 14px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
    }}
    .section h3 {{
      margin: 0 0 6px;
      font-size: 1.05rem;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 9px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: #f8fafc;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: #334155;
    }}
    tr:last-child td {{ border-bottom: none; }}
    ul {{ margin: 0; padding-left: 18px; }}
    code {{
      background: #0f172a;
      color: #e2e8f0;
      border-radius: 6px;
      padding: 1px 6px;
      font-size: 0.85em;
    }}
    .badge {{
      display: inline-block;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 0.74rem;
      font-weight: 700;
      letter-spacing: 0.02em;
    }}
    .status-passed {{ background: #dcfce7; color: #166534; }}
    .status-suggestion {{ background: #fef3c7; color: #92400e; }}
    .status-warning {{ background: #fee2e2; color: #991b1b; }}
    .status-manual {{ background: #ede9fe; color: #5b21b6; }}
    .status-skipped {{ background: #e2e8f0; color: #334155; }}
    .priority-p1 {{ background: #fee2e2; color: #b91c1c; }}
    .priority-p2 {{ background: #ffedd5; color: #b45309; }}
    .priority-p3 {{ background: #e0f2fe; color: #0369a1; }}
    .controls {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin: 10px 0;
    }}
    .filter-button {{
      border: 1px solid #cbd5e1;
      border-radius: 999px;
      background: #fff;
      padding: 7px 12px;
      cursor: pointer;
      font-size: 0.82rem;
    }}
    .filter-button.active {{
      background: var(--primary);
      border-color: var(--primary);
      color: #fff;
    }}
    details {{
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 10px;
      background: #fcfdff;
    }}
    details + details {{
      margin-top: 10px;
    }}
    summary {{
      cursor: pointer;
      font-weight: 600;
      color: #1e3a8a;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header class="hero">
      <div>
        <h1>Rapport de durcissement Lynis</h1>
        <p><strong>Hote:</strong> {escape(hostname)} | <strong>OS:</strong> {escape(os_name)}</p>
        <p><strong>Genere le:</strong> {escape(generated_at)} | <strong>Source:</strong> <code>{escape(str(report_path))}</code></p>
      </div>
      <div>{logo_html}</div>
    </header>

    <div class="tabs">
      <button class="tab-btn active" data-tab="machine" type="button">Information sur la machine</button>
      <button class="tab-btn" data-tab="lynis" type="button">Scan Lynis</button>
      <button class="tab-btn" data-tab="openscap" type="button">Scan OpenSCAP</button>
    </div>

    <section id="panel-machine" class="panel active">
      <div class="grid">
        <article class="card">
          <h2>Niveau de securite global</h2>
          <div class="kpi {escape(score_css)}">{hardening_score}/100</div>
          <div class="risk-pill {risk_css}">Risque {risk_level}</div>
          <div class="progress"><span style="width:{hardening_score}%"></span></div>
          <div class="muted" style="margin-top: 6px;">Lecture rapide: {escape(score_label)}</div>
        </article>
        <article class="card">
          <h2>Repartition des resultats</h2>
          <div class="donut"></div>
          <div class="muted" style="margin-top:8px;">PASS: {status_counts["passed"]} | SUGGESTION: {status_counts["suggestion"]} | WARNING: {status_counts["warning"]}</div>
        </article>
        <article class="card">
          <h2>Couverture du scan</h2>
          <div class="kpi">{tests_done}</div>
          <div class="muted">Tests executes: {len(tests_executed)} | Tests ignores: {len(tests_skipped)}</div>
          <div class="muted">Lynis: {escape(lynis_version)}</div>
        </article>
        <article class="card">
          <h2>Priorites d'action</h2>
          <div><span class="badge priority-p1">P1: {priority_counts["P1"]}</span> <span class="badge priority-p2">P2: {priority_counts["P2"]}</span> <span class="badge priority-p3">P3: {priority_counts["P3"]}</span></div>
          <div class="muted" style="margin-top: 8px;">Debut: {escape(started_at)}</div>
          <div class="muted">Fin: {escape(ended_at)}</div>
        </article>
      </div>

      <div class="section">
        <h3>Contexte plateforme (synthese)</h3>
        <div class="grid">
          <article class="card">
            <h2>Environnement</h2>
            <div><strong>Fuseau:</strong> {escape(timezone)}</div>
            <div><strong>Locale:</strong> {escape(system_locale)}</div>
            <div><strong>Shell:</strong> {escape(shell_value)}</div>
            <div><strong>Uptime:</strong> {escape(uptime_human)}</div>
          </article>
          <article class="card">
            <h2>Signaux securite</h2>
            <div><strong>Package manager:</strong> {escape(package_manager_value)}</div>
            <div><strong>Secure Boot:</strong> {escape(secure_boot_status)}</div>
            <div><strong>TPM:</strong> {escape(tpm_status)}</div>
          </article>
          <article class="card">
            <h2>Ressources</h2>
            <div><strong>Load avg:</strong> {escape(load_average)}</div>
            <div><strong>RAM totale (kB):</strong> {escape(memory_total_kb)}</div>
            <div><strong>Clavier:</strong> {escape(keyboard_layout)} / {escape(keyboard_model)}</div>
            <div><strong>LANG:</strong> {escape(lang_value)}</div>
          </article>
        </div>
      </div>
    </section>

    <section id="panel-lynis" class="panel">
      <div class="section">
        <h3>Plan d'action prioritaire (Lynis)</h3>
        <p class="muted">Actions les plus importantes pour reduire rapidement le risque.</p>
        <table>
          <thead>
            <tr>
              <th>Priorite</th>
              <th>Test</th>
              <th>Type</th>
              <th>Constat</th>
              <th>Action conseillee</th>
            </tr>
          </thead>
          <tbody>
            {"".join(top_action_rows)}
          </tbody>
        </table>
      </div>

      <div class="section">
        <h3>Alertes clefs</h3>
        <ul>{"".join(warning_items)}</ul>
      </div>

      <div class="section">
        <h3>Filtrage des tests</h3>
        <p class="muted">Vue complete pour investigation technique et suivi des remediations.</p>
        <div class="controls" id="status-filters">
          <button class="filter-button active" data-filter="all" type="button">Tous statuts</button>
          <button class="filter-button" data-filter="warning" type="button">Warning</button>
          <button class="filter-button" data-filter="suggestion" type="button">Suggestion</button>
          <button class="filter-button" data-filter="manual" type="button">Manual</button>
          <button class="filter-button" data-filter="passed" type="button">Passed</button>
          <button class="filter-button" data-filter="skipped" type="button">Skipped</button>
        </div>
        <div class="controls" id="priority-filters">
          <button class="filter-button active" data-priority-filter="all" type="button">Toutes priorites</button>
          <button class="filter-button" data-priority-filter="P1" type="button">P1</button>
          <button class="filter-button" data-priority-filter="P2" type="button">P2</button>
          <button class="filter-button" data-priority-filter="P3" type="button">P3</button>
        </div>
        <table id="tests-table">
          <thead>
            <tr>
              <th>Test ID</th>
              <th>Status</th>
              <th>Priorite</th>
              <th>Resultat</th>
              <th>Recommendation</th>
              <th>Component</th>
              <th>Details techniques</th>
            </tr>
          </thead>
          <tbody>
            {"".join(test_rows)}
          </tbody>
        </table>
      </div>

      <details open>
        <summary>Recommandations detaillees</summary>
        <table style="margin-top:10px;">
          <thead><tr><th>Test ID</th><th>Finding</th><th>Recommendation</th></tr></thead>
          <tbody>{"".join(recommendation_rows)}</tbody>
        </table>
      </details>

      <details>
        <summary>Taches de verification manuelle</summary>
        <ul style="margin-top:10px;">{"".join(manual_items)}</ul>
      </details>

      <details>
        <summary>Analyse des tests ignores</summary>
        <table style="margin-top:10px;">
          <thead><tr><th>Test ID</th><th>Famille</th><th>Raison</th><th>Source</th></tr></thead>
          <tbody>{"".join(skipped_rows)}</tbody>
        </table>
      </details>

      <details>
        <summary>Utilisateurs et comptes</summary>
        <table style="margin-top:10px;">
          <thead><tr><th>User</th><th>UID</th><th>GID</th><th>Home</th><th>Shell</th></tr></thead>
          <tbody>{"".join(user_rows)}</tbody>
        </table>
        <div class="grid" style="margin-top:10px;">
          <article class="card"><h2>Comptes verrouilles</h2><ul>{"".join(locked_user_items)}</ul></article>
          <article class="card"><h2>Home directories (sample)</h2><ul>{"".join(home_dir_items)}</ul></article>
        </div>
      </details>

      <details>
        <summary>Filesystem et permissions</summary>
        <table style="margin-top:10px;">
          <thead><tr><th>Path</th><th>Perm</th><th>Owner</th><th>Group</th></tr></thead>
          <tbody>{"".join(path_rows)}</tbody>
        </table>
        <div class="grid" style="margin-top:10px;">
          <article class="card"><h2>Filesystems (sample)</h2><ul>{"".join(fs_items)}</ul></article>
          <article class="card"><h2>Mounts (sample)</h2><ul>{"".join(mount_items)}</ul></article>
        </div>
      </details>

      <details>
        <summary>Services et exposition reseau</summary>
        <div class="grid" style="margin-top:10px;">
          <article class="card"><h2>Running services</h2><ul>{"".join(service_items)}</ul></article>
          <article class="card"><h2>Enabled at boot</h2><ul>{"".join(boot_service_items)}</ul></article>
        </div>
        <div class="grid" style="margin-top:10px;">
          <article class="card"><h2>Listeners (Lynis)</h2><ul>{"".join(network_listener_items)}</ul></article>
          <article class="card"><h2>Open ports (ss)</h2><ul>{"".join(open_port_items)}</ul></article>
        </div>
        <article class="card" style="margin-top:10px;"><h2>systemd services</h2><ul>{"".join(running_service_full_items)}</ul></article>
      </details>

      <details>
        <summary>SSH, firewall et hygiene systeme</summary>
        <div class="grid" style="margin-top:10px;">
          <article class="card"><h2>SSHD effectif</h2><ul>{"".join(sshd_effective_items)}</ul></article>
          <article class="card"><h2>Sysctl securite</h2><ul>{"".join(security_sysctl_items)}</ul></article>
        </div>
        <div class="grid" style="margin-top:10px;">
          <article class="card"><h2>Packages upgradables</h2><ul>{"".join(upgradeable_package_items)}</ul></article>
          <article class="card"><h2>NFT rules (sample)</h2><ul>{"".join(nft_rule_items)}</ul></article>
        </div>
        <article class="card" style="margin-top:10px;"><h2>iptables rules (sample)</h2><ul>{"".join(iptables_rule_items)}</ul></article>
      </details>

      <details>
        <summary>Indicateurs d'exposition fichiers</summary>
        <div class="grid" style="margin-top:10px;">
          <article class="card"><h2>SUID/SGID (sample)</h2><ul>{"".join(suid_sgid_items)}</ul></article>
          <article class="card"><h2>World-writable (sample)</h2><ul>{"".join(world_writable_items)}</ul></article>
        </div>
        <article class="card" style="margin-top:10px;"><h2>Certificats (sample)</h2><ul>{"".join(cert_expiry_items)}</ul></article>
      </details>
    </section>

    <section id="panel-openscap" class="panel">
      <div class="section">
        <h3>Resume OpenSCAP</h3>
        <div class="grid">
          <article class="card">
            <h2>Statut du scan</h2>
            <div class="kpi">{escape(openscap_status)}</div>
            <div class="muted">Profil: {escape(openscap_profile)}</div>
            <div class="muted">Datastream: <code>{escape(openscap_datastream)}</code></div>
          </article>
          <article class="card">
            <h2>Regles evaluees</h2>
            <div class="kpi">{escape(openscap_total_rules)}</div>
            <div class="muted">Passees: {escape(openscap_passed_rules)}</div>
            <div class="muted">En echec: {escape(openscap_failed_rules_count)}</div>
            <div class="muted">Erreurs: {escape(openscap_error_rules)}</div>
          </article>
        </div>
      </div>

      <div class="section">
        <h3>Regles OpenSCAP en echec (echantillon)</h3>
        <ul>{"".join(openscap_failed_rule_items)}</ul>
      </div>
    </section>
  </div>

  <script>
    (function () {{
      const rows = Array.from(document.querySelectorAll("#tests-table tbody tr"));
      let activeStatus = "all";
      let activePriority = "all";

      function applyFilters() {{
        rows.forEach((row) => {{
          const rowStatus = row.getAttribute("data-status");
          const rowPriority = row.getAttribute("data-priority");
          const statusMatch = activeStatus === "all" || rowStatus === activeStatus;
          const priorityMatch = activePriority === "all" || rowPriority === activePriority;
          row.style.display = statusMatch && priorityMatch ? "" : "none";
        }});
      }}

      function activateButton(groupSelector, attributeName, activeValue) {{
        const buttons = document.querySelectorAll(groupSelector + " .filter-button");
        buttons.forEach((btn) => {{
          btn.classList.toggle("active", btn.getAttribute(attributeName) === activeValue);
        }});
      }}

      document.querySelectorAll("#status-filters .filter-button").forEach((btn) => {{
        btn.addEventListener("click", () => {{
          activeStatus = btn.getAttribute("data-filter") || "all";
          activateButton("#status-filters", "data-filter", activeStatus);
          applyFilters();
        }});
      }});

      document.querySelectorAll("#priority-filters .filter-button").forEach((btn) => {{
        btn.addEventListener("click", () => {{
          activePriority = btn.getAttribute("data-priority-filter") || "all";
          activateButton("#priority-filters", "data-priority-filter", activePriority);
          applyFilters();
        }});
      }});

      document.querySelectorAll(".tab-btn").forEach((btn) => {{
        btn.addEventListener("click", () => {{
          const tab = btn.getAttribute("data-tab");
          document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
          btn.classList.add("active");
          document.getElementById("panel-machine").classList.toggle("active", tab === "machine");
          document.getElementById("panel-lynis").classList.toggle("active", tab === "lynis");
          document.getElementById("panel-openscap").classList.toggle("active", tab === "openscap");
        }});
      }});
    }})();
  </script>
</body>
</html>
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a professional HTML report from a Lynis report.dat file."
    )
    parser.add_argument("--report", required=True, help="Path to the input Lynis report.dat file.")
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
        "--openscap-data",
        default=None,
        help="Optional path to OpenSCAP snapshot data (default: infer from report name).",
    )
    parser.add_argument(
        "--full-run",
        action="store_true",
        help="Install tools, run scans, collect data, and then generate the HTML report.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    report_path = Path(args.report)
    inferred_system_path = default_system_data_path(report_path)
    system_data_path = Path(args.system_data) if args.system_data else inferred_system_path
    inferred_log_path = default_log_path(report_path)
    log_path = Path(args.log_file) if args.log_file else inferred_log_path
    inferred_openscap_path = default_openscap_data_path(report_path)
    openscap_data_path = Path(args.openscap_data) if args.openscap_data else inferred_openscap_path

    if args.full_run:
        run_full_collection(
            report_path=report_path,
            log_path=log_path,
            system_data_path=system_data_path,
            openscap_data_path=openscap_data_path,
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

    openscap_data: ParsedReport | None = None
    if openscap_data_path.exists():
        openscap_data = parse_report_file(openscap_data_path)

    output_path.write_text(
        render_html(
            parsed,
            report_path,
            logo_data_uri,
            system_data=system_data,
            openscap_data=openscap_data,
            log_path=log_path,
        ),
        encoding="utf-8",
    )
    print(f"HTML report successfully generated: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
