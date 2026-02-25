#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import html
import re
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
        recommendation_rows.append("<tr><td colspan='3'>No recommendations found.</td></tr>")

    warning_items: List[str] = []
    for entry in warnings:
        test_id, message, _ = parse_recommendation(entry)
        warning_items.append(f"<li><strong>{escape(test_id)}</strong> - {escape(message)}</li>")
    if not warning_items:
        warning_items.append("<li>No warnings in this report.</li>")

    manual_items = [f"<li>{escape(item)}</li>" for item in manual_actions] or [
        "<li>No manual verification tasks listed.</li>"
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
        user_rows.append("<tr><td colspan='5'>No user information available.</td></tr>")

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
        path_rows.append("<tr><td colspan='4'>No path permission information available.</td></tr>")

    service_items = [f"<li>{escape(item)}</li>" for item in running_services] or ["<li>N/A</li>"]
    boot_service_items = [f"<li>{escape(item)}</li>" for item in boot_services] or ["<li>N/A</li>"]
    locked_user_items = [f"<li>{escape(item)}</li>" for item in locked_users] or ["<li>None</li>"]
    home_dir_items = [f"<li>{escape(item)}</li>" for item in report_home_directories[:60]] or ["<li>N/A</li>"]
    fs_items = [f"<li>{escape(item)}</li>" for item in report_filesystems[:40]] or ["<li>N/A</li>"]
    mount_items = [f"<li>{escape(item)}</li>" for item in mount_info[:40]] or ["<li>N/A</li>"]
    network_listener_items = [f"<li>{escape(item)}</li>" for item in network_listeners] or ["<li>N/A</li>"]
    open_port_items = [f"<li>{escape(item)}</li>" for item in open_ports[:60]] or ["<li>N/A</li>"]
    running_service_full_items = [f"<li>{escape(item)}</li>" for item in running_services_full[:80]] or ["<li>N/A</li>"]
    sshd_effective_items = [f"<li>{escape(item)}</li>" for item in sshd_effective[:120]] or ["<li>N/A</li>"]
    security_sysctl_items = [f"<li>{escape(item)}</li>" for item in security_sysctl] or ["<li>N/A</li>"]
    upgradeable_package_items = [f"<li>{escape(item)}</li>" for item in upgradeable_packages[:300]] or [
        "<li>No pending package update reported.</li>"
    ]
    nft_rule_items = [f"<li>{escape(item)}</li>" for item in nft_rules[:260]] or ["<li>N/A</li>"]
    iptables_rule_items = [f"<li>{escape(item)}</li>" for item in iptables_rules[:260]] or ["<li>N/A</li>"]
    suid_sgid_items = [f"<li>{escape(item)}</li>" for item in suid_sgid_files[:300]] or ["<li>N/A</li>"]
    world_writable_items = [f"<li>{escape(item)}</li>" for item in world_writable_files[:300]] or ["<li>None found in scanned paths.</li>"]
    cert_expiry_items = [f"<li>{escape(item)}</li>" for item in cert_expiry[:200]] or ["<li>N/A</li>"]

    skipped_reason_map = parse_skip_reasons_from_log(log_path)
    test_rows, status_counts, priority_counts, actions, skipped_rows = build_test_rows(
        parsed, skipped_reason_map=skipped_reason_map
    )
    skipped_rows = skipped_rows or [
        "<tr><td colspan='4'>No skipped tests found in this report.</td></tr>"
    ]
    top_actions = actions[:15]
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
        top_action_rows.append("<tr><td colspan='5'>No action needed. All tests are passed.</td></tr>")

    logo_html = (
        f"<img src='{logo_data_uri}' alt='Company logo' class='logo' />" if logo_data_uri else ""
    )
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Lynis Hardening Report - {escape(hostname)}</title>
  <style>
    :root {{
      --bg1: #0f172a;
      --bg2: #1e293b;
      --surface: #ffffff;
      --surface-soft: #f8fafc;
      --text: #0b1220;
      --muted: #64748b;
      --line: #e2e8f0;
      --accent: #2563eb;
      --danger: #dc2626;
      --warn: #d97706;
      --good: #15803d;
      --manual: #4338ca;
      --p1: #b91c1c;
      --p2: #b45309;
      --p3: #0369a1;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      color: var(--text);
      line-height: 1.55;
      background: radial-gradient(circle at top right, #1d4ed8 0%, transparent 30%),
                  linear-gradient(145deg, var(--bg1) 0%, var(--bg2) 40%, #0b1220 100%);
      min-height: 100vh;
    }}
    .container {{
      max-width: 1440px;
      margin: 0 auto;
      padding: 26px;
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 18px;
      border-radius: 20px;
      padding: 22px;
      background: linear-gradient(130deg, #111827 0%, #1f2937 60%, #0f172a 100%);
      border: 1px solid rgba(148, 163, 184, 0.22);
      color: #f8fafc;
      box-shadow: 0 20px 45px rgba(2, 6, 23, 0.45);
    }}
    .header h1 {{
      margin: 0 0 8px;
      font-size: 1.9rem;
      letter-spacing: -0.03em;
    }}
    .header .muted {{
      color: #cbd5e1;
    }}
    .logo {{
      max-height: 76px;
      max-width: 280px;
      object-fit: contain;
      background: rgba(255, 255, 255, 0.08);
      padding: 8px;
      border-radius: 10px;
    }}
    .grid {{
      margin-top: 16px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 14px;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid rgba(226, 232, 240, 0.95);
      border-radius: 16px;
      padding: 18px;
      box-shadow: 0 10px 24px rgba(2, 6, 23, 0.10);
    }}
    .score {{
      font-size: 2.2rem;
      font-weight: 800;
      margin: 6px 0;
      letter-spacing: -0.02em;
    }}
    .score-excellent {{ color: var(--good); }}
    .score-good {{ color: #16a34a; }}
    .score-fair {{ color: var(--warn); }}
    .score-poor {{ color: var(--danger); }}
    .muted {{ color: var(--muted); font-size: 0.95rem; }}
    section {{ margin-top: 16px; }}
    .card h2 {{
      margin: 0 0 10px;
      font-size: 1.1rem;
      letter-spacing: -0.02em;
    }}
    table {{
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      font-size: 0.9rem;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 12px;
      overflow: hidden;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: linear-gradient(180deg, #eff6ff 0%, #f8fafc 100%);
      font-weight: 700;
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: #334155;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tbody tr:hover td {{ background: #f8fbff; }}
    ul {{ margin: 0; padding-left: 18px; }}
    code {{
      background: #0f172a;
      color: #e2e8f0;
      border-radius: 6px;
      padding: 2px 6px;
      font-size: 0.88em;
    }}
    .kpi {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 8px;
    }}
    .badge {{
      display: inline-block;
      font-size: 0.74rem;
      font-weight: 700;
      border-radius: 999px;
      padding: 4px 10px;
      letter-spacing: 0.03em;
    }}
    .status-passed {{ background: #dcfce7; color: #166534; }}
    .status-suggestion {{ background: #fef3c7; color: #92400e; }}
    .status-warning {{ background: #fee2e2; color: #991b1b; }}
    .status-manual {{ background: #e0e7ff; color: var(--manual); }}
    .status-skipped {{ background: #e2e8f0; color: #334155; }}
    .priority-p1 {{ background: #fee2e2; color: var(--p1); }}
    .priority-p2 {{ background: #ffedd5; color: var(--p2); }}
    .priority-p3 {{ background: #e0f2fe; color: var(--p3); }}
    .row-passed td {{ background: #f0fdf4; }}
    .row-suggestion td {{ background: #fffbeb; }}
    .row-warning td {{ background: #fff1f2; }}
    .row-manual td {{ background: #eef2ff; }}
    .row-skipped td {{ background: #f8fafc; }}
    .controls {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 10px 0;
    }}
    .filter-button {{
      border: 1px solid #cbd5e1;
      border-radius: 999px;
      background: #fff;
      padding: 7px 13px;
      cursor: pointer;
      font-size: 0.82rem;
      transition: all 0.12s ease-in-out;
      color: #334155;
    }}
    .filter-button.active {{
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
      box-shadow: 0 8px 18px rgba(37, 99, 235, 0.25);
    }}
    .filter-button:hover {{
      transform: translateY(-1px);
      border-color: #94a3b8;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <div>
        <h1>Lynis Security Hardening Report</h1>
        <p class="muted">Generated at {escape(generated_at)} from <code>{escape(str(report_path))}</code></p>
      </div>
      <div>{logo_html}</div>
    </header>

    <div class="grid">
      <article class="card">
        <h2>Target Host</h2>
        <div><strong>{escape(hostname)}</strong></div>
        <div class="muted">{escape(os_name)}</div>
      </article>
      <article class="card">
        <h2>Hardening Score</h2>
        <div class="score {escape(score_css)}">{hardening_score}/100</div>
        <div class="muted">{escape(score_label)}</div>
      </article>
      <article class="card">
        <h2>Scan Coverage</h2>
        <div><strong>{tests_done}</strong> tests done</div>
        <div class="muted">Executed IDs: {len(tests_executed)} | Skipped IDs: {len(tests_skipped)}</div>
      </article>
      <article class="card">
        <h2>Scan Metadata</h2>
        <div><strong>Lynis:</strong> {escape(lynis_version)}</div>
        <div class="muted">{escape(started_at)} -> {escape(ended_at)}</div>
      </article>
    </div>

    <section class="card">
      <h2>System Context (Extended Data)</h2>
      <div class="grid">
        <article class="card">
          <h2>Timezone and Locale</h2>
          <div><strong>Timezone:</strong> {escape(timezone)}</div>
          <div><strong>Locale:</strong> {escape(system_locale)}</div>
          <div><strong>LANG:</strong> {escape(lang_value)}</div>
        </article>
        <article class="card">
          <h2>Keyboard and Shell</h2>
          <div><strong>Keyboard layout:</strong> {escape(keyboard_layout)}</div>
          <div><strong>Keyboard model:</strong> {escape(keyboard_model)}</div>
          <div><strong>Default shell:</strong> {escape(shell_value)}</div>
        </article>
        <article class="card">
          <h2>Runtime State</h2>
          <div><strong>Uptime:</strong> {escape(uptime_human)}</div>
          <div><strong>Load average:</strong> {escape(load_average)}</div>
          <div><strong>Total memory (kB):</strong> {escape(memory_total_kb)}</div>
        </article>
        <article class="card">
          <h2>Platform Security Signals</h2>
          <div><strong>Package manager:</strong> {escape(package_manager_value)}</div>
          <div><strong>Secure Boot:</strong> {escape(secure_boot_status)}</div>
          <div><strong>TPM:</strong> {escape(tpm_status)}</div>
          <div><strong>Encryption summary:</strong> {escape(encryption_summary)}</div>
        </article>
      </div>
    </section>

    <section class="card">
      <h2>Patch and Hardening Hygiene</h2>
      <div class="grid">
        <article class="card">
          <h2>Upgradeable Packages (sample)</h2>
          <ul>{"".join(upgradeable_package_items)}</ul>
        </article>
        <article class="card">
          <h2>Security Sysctl Snapshot</h2>
          <ul>{"".join(security_sysctl_items)}</ul>
        </article>
      </div>
    </section>

    <section class="card">
      <h2>Executive Summary</h2>
      <p class="muted">This section highlights the most important hardening actions to communicate quickly with clients.</p>
      <div class="kpi">
        <span class="badge priority-p1">P1: {priority_counts["P1"]}</span>
        <span class="badge priority-p2">P2: {priority_counts["P2"]}</span>
        <span class="badge priority-p3">P3: {priority_counts["P3"]}</span>
        <span class="badge status-warning">WARNING: {status_counts["warning"]}</span>
        <span class="badge status-suggestion">SUGGESTION: {status_counts["suggestion"]}</span>
        <span class="badge status-manual">MANUAL: {status_counts["manual"]}</span>
        <span class="badge status-passed">PASSED: {status_counts["passed"]}</span>
        <span class="badge status-skipped">SKIPPED: {status_counts["skipped"]}</span>
      </div>
      <table style="margin-top: 12px;">
        <thead>
          <tr>
            <th>Priority</th>
            <th>Test ID</th>
            <th>Status</th>
            <th>Finding</th>
            <th>Recommendation</th>
          </tr>
        </thead>
        <tbody>
          {"".join(top_action_rows)}
        </tbody>
      </table>
    </section>

    <section class="card">
      <h2>Key Warnings</h2>
      <ul>
        {"".join(warning_items)}
      </ul>
    </section>

    <section class="card">
      <h2>Recommendations</h2>
      <table>
        <thead>
          <tr><th>Test ID</th><th>Finding</th><th>Recommendation</th></tr>
        </thead>
        <tbody>
          {"".join(recommendation_rows)}
        </tbody>
      </table>
    </section>

    <section class="card">
      <h2>Manual Verification Tasks</h2>
      <ul>
        {"".join(manual_items)}
      </ul>
    </section>

    <section class="card">
      <h2>Skipped Tests Analysis</h2>
      <p class="muted">Reason source is <strong>log-based</strong> when available, otherwise heuristic from host context.</p>
      <table>
        <thead>
          <tr><th>Test ID</th><th>Family</th><th>Reason</th><th>Source</th></tr>
        </thead>
        <tbody>
          {"".join(skipped_rows)}
        </tbody>
      </table>
    </section>

    <section class="card">
      <h2>Users and Accounts</h2>
      <table>
        <thead>
          <tr><th>User</th><th>UID</th><th>GID</th><th>Home</th><th>Shell</th></tr>
        </thead>
        <tbody>
          {"".join(user_rows)}
        </tbody>
      </table>
      <div class="grid" style="margin-top: 12px;">
        <article class="card">
          <h2>Locked Accounts</h2>
          <ul>{"".join(locked_user_items)}</ul>
        </article>
        <article class="card">
          <h2>Home Directories (sample)</h2>
          <ul>{"".join(home_dir_items)}</ul>
        </article>
      </div>
    </section>

    <section class="card">
      <h2>File System and Important Paths</h2>
      <table>
        <thead>
          <tr><th>Path</th><th>Perm</th><th>Owner</th><th>Group</th></tr>
        </thead>
        <tbody>
          {"".join(path_rows)}
        </tbody>
      </table>
      <div class="grid" style="margin-top: 12px;">
        <article class="card">
          <h2>Filesystem Entries (sample)</h2>
          <ul>{"".join(fs_items)}</ul>
        </article>
        <article class="card">
          <h2>Mount Information (sample)</h2>
          <ul>{"".join(mount_items)}</ul>
        </article>
      </div>
    </section>

    <section class="card">
      <h2>Services and Network Exposure</h2>
      <div class="grid">
        <article class="card">
          <h2>Running Services</h2>
          <ul>{"".join(service_items)}</ul>
        </article>
        <article class="card">
          <h2>Enabled at Boot</h2>
          <ul>{"".join(boot_service_items)}</ul>
        </article>
      </div>
      <div class="grid" style="margin-top: 12px;">
        <article class="card">
          <h2>Listening Endpoints (Lynis)</h2>
          <ul>{"".join(network_listener_items)}</ul>
        </article>
        <article class="card">
          <h2>Open Ports Snapshot (ss)</h2>
          <ul>{"".join(open_port_items)}</ul>
        </article>
      </div>
      <article class="card" style="margin-top: 12px;">
        <h2>Running Services Snapshot (systemd)</h2>
        <ul>{"".join(running_service_full_items)}</ul>
      </article>
    </section>

    <section class="card">
      <h2>SSH and Firewall Deep Dive</h2>
      <div class="grid">
        <article class="card">
          <h2>Effective SSH Configuration (sshd -T)</h2>
          <ul>{"".join(sshd_effective_items)}</ul>
        </article>
        <article class="card">
          <h2>NFT Ruleset (sample)</h2>
          <ul>{"".join(nft_rule_items)}</ul>
        </article>
      </div>
      <article class="card" style="margin-top: 12px;">
        <h2>iptables Ruleset (sample)</h2>
        <ul>{"".join(iptables_rule_items)}</ul>
      </article>
    </section>

    <section class="card">
      <h2>File Exposure Indicators</h2>
      <div class="grid">
        <article class="card">
          <h2>SUID/SGID Files (sample)</h2>
          <ul>{"".join(suid_sgid_items)}</ul>
        </article>
        <article class="card">
          <h2>World-Writable Files (sample)</h2>
          <ul>{"".join(world_writable_items)}</ul>
        </article>
      </div>
      <article class="card" style="margin-top: 12px;">
        <h2>Certificate Expiry Snapshot</h2>
        <ul>{"".join(cert_expiry_items)}</ul>
      </article>
    </section>

    <section class="card">
      <h2>Detailed Test Results</h2>
      <p class="muted">Use filters to focus on specific statuses or priorities.</p>

      <div class="controls" id="status-filters">
        <button class="filter-button active" data-filter="all" type="button">All Statuses</button>
        <button class="filter-button" data-filter="warning" type="button">Warning</button>
        <button class="filter-button" data-filter="suggestion" type="button">Suggestion</button>
        <button class="filter-button" data-filter="manual" type="button">Manual</button>
        <button class="filter-button" data-filter="passed" type="button">Passed</button>
        <button class="filter-button" data-filter="skipped" type="button">Skipped</button>
      </div>

      <div class="controls" id="priority-filters">
        <button class="filter-button active" data-priority-filter="all" type="button">All Priorities</button>
        <button class="filter-button" data-priority-filter="P1" type="button">P1</button>
        <button class="filter-button" data-priority-filter="P2" type="button">P2</button>
        <button class="filter-button" data-priority-filter="P3" type="button">P3</button>
      </div>

      <table id="tests-table">
        <thead>
          <tr>
            <th>Test ID</th>
            <th>Status</th>
            <th>Priority</th>
            <th>Result Summary</th>
            <th>Recommendation</th>
            <th>Component</th>
            <th>Technical Details</th>
          </tr>
        </thead>
        <tbody>
          {"".join(test_rows)}
        </tbody>
      </table>
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
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        parser.error(f"Input report file not found: {report_path}")

    parsed = parse_report_file(report_path)
    output_path = Path(args.output) if args.output else default_output_path(parsed)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    logo_path = Path(args.logo) if args.logo else None
    logo_data_uri = build_logo_data_uri(logo_path)

    system_data: ParsedReport | None = None
    inferred_system_path = default_system_data_path(report_path)
    system_data_path = Path(args.system_data) if args.system_data else inferred_system_path
    if system_data_path.exists():
        system_data = parse_report_file(system_data_path)

    inferred_log_path = default_log_path(report_path)
    log_path = Path(args.log_file) if args.log_file else inferred_log_path

    output_path.write_text(
        render_html(parsed, report_path, logo_data_uri, system_data=system_data, log_path=log_path),
        encoding="utf-8",
    )
    print(f"HTML report successfully generated: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
