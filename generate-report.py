#!/usr/bin/env python3
"""Security Hardening Report Generator
Single script: installs Lynis, collects system data, runs audit, generates HTML.
Usage: sudo python3 generate-report.py
"""
from __future__ import annotations

import argparse
import base64
import configparser
import grp
import html as _html
import math
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── SVG icon set (Lucide-inspired, MIT) ──────────────────────────────────────
_I: Dict[str, str] = {
    "shield":    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>',
    "server":    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="currentColor"/><circle cx="6" cy="18" r="1" fill="currentColor"/></svg>',
    "cpu":       '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>',
    "users":     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    "lock":      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    "activity":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    "globe":     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
    "drive":     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><circle cx="12" cy="16" r="1" fill="currentColor"/></svg>',
    "settings":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    "calendar":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>',
    "login":     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>',
    "file":      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
    "alert":     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    "check":     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    "package":   '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="16.5" y1="9.4" x2="7.5" y2="4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>',
    "key":       '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
    "database":  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
    "flame":     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/></svg>',
    "search":    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    "info":      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
}

def icon(name: str, size: int = 16, cls: str = "") -> str:
    svg = _I.get(name, _I["info"])
    attrs = f' width="{size}" height="{size}"'
    if cls:
        attrs += f' class="{cls}"'
    return svg.replace("<svg ", f"<svg{attrs} ", 1)


# ── Generic helpers ───────────────────────────────────────────────────────────
def esc(v: Any) -> str:
    return _html.escape(str(v), quote=True)

def _run(cmd: List[str], *, sudo: bool = False, timeout: int = 30) -> str:
    try:
        if sudo and os.geteuid() != 0:
            cmd = ["sudo", "-n"] + cmd
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return r.stdout or ""
    except Exception:
        return ""

def _read(path: str, max_chars: int = 8192) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:max_chars]
    except Exception:
        return ""

def _pkg_mgr() -> str:
    for m in ("apt-get", "dnf", "yum", "zypper", "pacman", "apk"):
        if shutil.which(m):
            return m.replace("-get", "apt")
    return "unknown"

def badge(text: str, color: str) -> str:
    """color: green | red | orange | blue | gray | purple | sky"""
    return f"<span class='badge badge-{color}'>{esc(text)}</span>"

def _svc_badge(val: str, kind: str) -> str:
    s = val.lower()
    if kind == "active":
        c = {"active": "green", "failed": "red", "inactive": "gray",
             "activating": "blue", "deactivating": "orange"}.get(s, "gray")
    elif kind == "load":
        c = {"loaded": "blue", "not-found": "red", "masked": "purple"}.get(s, "gray")
    else:
        c = {"enabled": "green", "disabled": "gray", "static": "blue",
             "masked": "purple", "indirect": "orange"}.get(s, "gray")
    return badge(val, c)

# ── System data collection ────────────────────────────────────────────────────
def collect_system() -> Dict[str, str]:
    d: Dict[str, str] = {}
    d["hostname"] = socket.gethostname()
    try:
        d["fqdn"] = socket.getfqdn()
    except Exception:
        d["fqdn"] = d["hostname"]

    osr: Dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                osr[k.strip()] = v.strip('"\'')
    except Exception:
        pass
    d["os_name"] = osr.get("PRETTY_NAME", osr.get("NAME", "Unknown"))
    d["os_id"]   = osr.get("ID", "unknown")
    d["kernel"]  = _run(["uname", "-r"]).strip()
    d["arch"]    = _run(["uname", "-m"]).strip()

    try:
        sec = float(Path("/proc/uptime").read_text().split()[0])
        days, rem = divmod(int(sec), 86400)
        hrs, rem  = divmod(rem, 3600)
        mins      = rem // 60
        d["uptime"] = (f"{days}d " if days else "") + (f"{hrs}h " if hrs else "") + f"{mins}m"
    except Exception:
        d["uptime"] = "—"

    try:
        d["load_avg"] = " ".join(Path("/proc/loadavg").read_text().split()[:3])
    except Exception:
        d["load_avg"] = "—"

    try:
        mem: Dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            if ":" in line:
                k2, v2 = line.split(":", 1)
                mem[k2.strip()] = int(v2.strip().split()[0])
        total = mem.get("MemTotal", 0)
        avail = mem.get("MemAvailable", 0)
        used  = total - avail
        d["mem_total"]   = f"{total // 1024} MB"
        d["mem_avail"]   = f"{avail // 1024} MB"
        d["mem_used_pct"]= f"{int(used/total*100)}%" if total else "—"
    except Exception:
        d["mem_total"] = d["mem_avail"] = d["mem_used_pct"] = "—"

    try:
        ci = Path("/proc/cpuinfo").read_text()
        m2 = re.search(r"model name\s*:\s*(.+)", ci)
        d["cpu_model"] = m2.group(1).strip() if m2 else "—"
        d["cpu_count"] = str(ci.count("processor\t:"))
    except Exception:
        d["cpu_model"] = d["cpu_count"] = "—"

    try:
        tz = _run(["timedatectl", "show", "-p", "Timezone", "--value"]).strip()
        if not tz:
            lnk = str(Path("/etc/localtime").resolve())
            tz = lnk.split("zoneinfo/")[-1] if "zoneinfo/" in lnk else "—"
        d["timezone"] = tz or "—"
    except Exception:
        d["timezone"] = "—"

    d["locale"]  = os.environ.get("LANG", "—")
    d["shell"]   = os.environ.get("SHELL", "—")
    d["pkg_mgr"] = _pkg_mgr()

    if shutil.which("mokutil"):
        d["secure_boot"] = _run(["mokutil", "--sb-state"]).strip() or "—"
    elif Path("/sys/firmware/efi").is_dir():
        d["secure_boot"] = "UEFI (mokutil not available)"
    else:
        d["secure_boot"] = "Legacy BIOS mode"

    if Path("/dev/tpm0").exists() or Path("/dev/tpmrm0").exists():
        d["tpm"] = "TPM device present"
    else:
        d["tpm"] = "Not detected"

    lsblk = _run(["lsblk", "-o", "NAME,TYPE,FSTYPE"])
    d["encryption"] = "LUKS encryption detected" if "crypt" in lsblk else "No LUKS device detected"

    return d


def collect_disk() -> List[Dict[str, str]]:
    out = _run(["df", "-h", "--output=source,size,used,avail,pcent,target",
                "-x", "tmpfs", "-x", "devtmpfs", "-x", "udev"])
    rows = []
    for line in out.splitlines()[1:]:
        p = line.split()
        if len(p) >= 6:
            pct_int = int(p[4].replace("%", "")) if p[4].replace("%", "").isdigit() else 0
            rows.append({"src": p[0], "size": p[1], "used": p[2],
                         "avail": p[3], "pct": p[4], "pct_int": pct_int, "mp": p[5]})
    return rows


def collect_users() -> List[Dict[str, str]]:
    shadow: Dict[str, str] = {}
    sh_text = _read("/etc/shadow", 200000) or _run(["cat", "/etc/shadow"], sudo=True)
    for line in sh_text.splitlines():
        p = line.split(":")
        if len(p) >= 2:
            h = p[1]
            shadow[p[0]] = "locked" if (not h or h in ("!", "*", "!!") or h.startswith("!")) else "set"

    def _groups(name: str) -> str:
        gs = []
        try:
            gs.append(grp.getgrgid(pwd.getpwnam(name).pw_gid).gr_name)
        except Exception:
            pass
        for g in grp.getgrall():
            if name in g.gr_mem and g.gr_name not in gs:
                gs.append(g.gr_name)
        return ", ".join(sorted(gs))

    def _keys(home: str) -> Tuple[int, str]:
        cnt, prev = 0, []
        for kf in [Path(home)/".ssh"/"authorized_keys", Path(home)/".ssh"/"authorized_keys2"]:
            if not kf.is_file():
                continue
            try:
                for ln in kf.read_text(encoding="utf-8", errors="replace").splitlines():
                    ln = ln.strip()
                    if ln and not ln.startswith("#"):
                        cnt += 1
                        p = ln.split()
                        ktype = p[0] if p else "?"
                        cmt   = p[2] if len(p) > 2 else ""
                        prev.append(f"{ktype}:{cmt}" if cmt else ktype)
                        if len(prev) >= 3:
                            break
            except Exception:
                pass
        return cnt, ", ".join(prev) or "—"

    nologin = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"}
    result = []
    try:
        for pw in pwd.getpwall():
            if pw.pw_uid < 1000 and pw.pw_uid != 0:
                continue
            kc, kp = _keys(pw.pw_dir)
            result.append({
                "name":     pw.pw_name,
                "uid":      str(pw.pw_uid),
                "gid":      str(pw.pw_gid),
                "home":     pw.pw_dir,
                "shell":    pw.pw_shell,
                "login":    "yes" if pw.pw_shell not in nologin else "no",
                "password": shadow.get(pw.pw_name, "unknown"),
                "groups":   _groups(pw.pw_name),
                "keys":     str(kc),
                "key_prev": kp,
                "uid0":     "yes" if pw.pw_uid == 0 else "no",
            })
    except Exception:
        pass
    return result


def collect_password_aging() -> List[Dict[str, str]]:
    if not shutil.which("chage"):
        return []
    result = []
    try:
        for pw in pwd.getpwall():
            if pw.pw_uid < 1000 and pw.pw_uid != 0:
                continue
            out = _run(["chage", "-l", pw.pw_name], sudo=True)
            if not out.strip():
                continue
            ag: Dict[str, str] = {}
            for ln in out.splitlines():
                if ":" in ln:
                    k2, v2 = ln.split(":", 1)
                    ag[k2.strip().lower()] = v2.strip()
            result.append({
                "name":        pw.pw_name,
                "last_change": ag.get("last password change", "—"),
                "expires":     ag.get("password expires", "—"),
                "max_days":    ag.get("maximum number of days between password change", "—"),
                "min_days":    ag.get("minimum number of days between password change", "—"),
                "warn_days":   ag.get("number of days of warning before password expires", "—"),
                "acct_exp":    ag.get("account expires", "—"),
            })
    except Exception:
        pass
    return result


def collect_services() -> List[Dict[str, str]]:
    enab: Dict[str, str] = {}
    for ln in _run(["systemctl", "list-unit-files", "--type=service",
                    "--no-pager", "--no-legend"]).splitlines():
        p = ln.split()
        if len(p) >= 2:
            enab[p[0]] = p[1]
    svcs = []
    out = _run(["systemctl", "list-units", "--type=service", "--all",
                "--no-pager", "--no-legend"])
    for ln in out.splitlines():
        # strip ANSI, bullet "●" prefix, and whitespace
        clean = re.sub(r'\x1b\[[0-9;]*m', '', ln).strip()
        clean = clean.lstrip("\u25cf\u25cb\u2022").strip()
        p = clean.split(None, 4)
        if len(p) < 4:
            continue
        unit = p[0]
        # only accept valid service unit names
        if not unit.endswith(".service"):
            continue
        svcs.append({"unit": unit, "load": p[1], "active": p[2], "sub": p[3],
                     "enabled": enab.get(unit, "—"), "desc": p[4].strip() if len(p) > 4 else ""})
    return svcs


def collect_ports() -> List[Dict[str, str]]:
    out = _run(["ss", "-tulpen"], sudo=True)
    ports = []
    for ln in out.splitlines()[1:]:
        p = ln.split()
        if len(p) < 5:
            continue
        proto = p[0]
        state = p[1]
        local = p[4] if len(p) > 4 else "—"
        raw_proc = " ".join(p[6:]) if len(p) > 6 else ""
        lci = local.rfind(":")
        addr, port = (local[:lci], local[lci+1:]) if lci >= 0 else (local, "—")
        proc = ""
        pid  = ""
        m = re.search(r'users:\(\("([^"]+)"', raw_proc)
        if m:
            proc = m.group(1)
        m2 = re.search(r'pid=(\d+)', raw_proc)
        if m2:
            pid = m2.group(1)
        ports.append({"proto": proto, "state": state, "addr": addr,
                      "port": port, "proc": proc, "pid": pid})
    return ports


def _parse_iptables(lines: List[str]) -> List[Dict[str, str]]:
    """Parse iptables-save output into structured rows."""
    rows = []
    table = ""
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("*"):
            table = ln[1:]
            continue
        if ln.startswith(":"):
            parts = ln[1:].split()
            chain = parts[0] if parts else ln[1:]
            policy = parts[1] if len(parts) > 1 else "—"
            rows.append({"table": table, "chain": chain, "target": policy,
                         "proto": "—", "src": "—", "dst": "—", "opts": "(default policy)"})
            continue
        if ln.startswith("-A") or ln.startswith("-I"):
            parts = ln.split()
            chain = parts[1] if len(parts) > 1 else "—"
            target = proto = src = dst = ""
            i = 2
            while i < len(parts):
                if parts[i] == "-j" and i+1 < len(parts):
                    target = parts[i+1]; i += 2
                elif parts[i] == "-p" and i+1 < len(parts):
                    proto = parts[i+1]; i += 2
                elif parts[i] == "-s" and i+1 < len(parts):
                    src = parts[i+1]; i += 2
                elif parts[i] == "-d" and i+1 < len(parts):
                    dst = parts[i+1]; i += 2
                else:
                    i += 1
            opts_parts = [p for p in parts[2:] if p not in
                          ("-j", target, "-p", proto, "-s", src, "-d", dst)]
            rows.append({"table": table, "chain": chain,
                         "target": target or "—", "proto": proto or "any",
                         "src": src or "any", "dst": dst or "any",
                         "opts": " ".join(opts_parts)[:80]})
    return rows


def _parse_nft(lines: List[str]) -> List[Dict[str, str]]:
    """Parse nft list ruleset into structured rows."""
    rows = []
    table = chain = ""
    for ln in lines:
        stripped = ln.strip()
        if not stripped:
            continue
        m = re.match(r'^table\s+(\w+)\s+(\w+)', stripped)
        if m:
            table = f"{m.group(1)} {m.group(2)}"; chain = ""; continue
        m2 = re.match(r'^chain\s+(\S+)', stripped)
        if m2:
            chain = m2.group(1); continue
        if stripped in ("{", "}"):
            if stripped == "}":
                chain = "" if chain else table
            continue
        if table and chain:
            rows.append({"table": table, "chain": chain, "rule": stripped})
        elif table and not chain:
            rows.append({"table": table, "chain": "—", "rule": stripped})
    return rows


def _parse_ufw(lines: List[str]) -> List[Dict[str, str]]:
    """Parse ufw status verbose into structured rows."""
    rows = []
    in_rules = False
    for ln in lines:
        stripped = ln.strip()
        if stripped.startswith("--"):
            in_rules = True; continue
        if not in_rules:
            continue
        if not stripped:
            continue
        parts = re.split(r'\s{2,}', stripped)
        if len(parts) >= 3:
            rows.append({"to": parts[0].strip(), "action": parts[1].strip(), "from": parts[2].strip()})
        elif len(parts) == 2:
            rows.append({"to": parts[0].strip(), "action": parts[1].strip(), "from": "Anywhere"})
    return rows


def collect_firewall() -> Dict[str, Any]:
    fw: Dict[str, Any] = {
        "type": "none",
        "nft": [], "nft_parsed": [],
        "ipt": [], "ipt_parsed": [],
        "ufw": [], "ufw_parsed": [], "ufw_active": False,
    }
    nft = _run(["nft", "list", "ruleset"], sudo=True)
    if nft.strip():
        fw["nft"]        = [l for l in nft.splitlines() if l.strip()]
        fw["nft_parsed"] = _parse_nft(fw["nft"])
        fw["type"]       = "nftables"
    ipt = _run(["iptables-save"], sudo=True)
    if ipt.strip():
        fw["ipt"]        = [l for l in ipt.splitlines() if l.strip()]
        fw["ipt_parsed"] = _parse_iptables(fw["ipt"])
        if fw["type"] == "none":
            fw["type"]   = "iptables"
    if shutil.which("ufw"):
        ufw = _run(["ufw", "status", "verbose"], sudo=True)
        fw["ufw"]        = [l for l in ufw.splitlines() if l.strip()]
        fw["ufw_parsed"] = _parse_ufw(fw["ufw"])
        fw["ufw_active"] = "Status: active" in ufw
    return fw


def collect_mounts() -> List[Dict[str, str]]:
    out = _run(["findmnt", "-rn", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"])
    rows = []
    for ln in out.splitlines():
        p = ln.split(None, 3)
        if len(p) >= 3:
            rows.append({"mp": p[0], "src": p[1], "fs": p[2], "opts": p[3] if len(p) > 3 else ""})
    return rows


def collect_important_paths() -> List[Dict[str, str]]:
    PATHS = ["/etc", "/etc/passwd", "/etc/shadow", "/etc/sudoers",
             "/home", "/root", "/var/log", "/tmp", "/var/tmp",
             "/etc/ssh", "/etc/sudoers.d", "/usr/bin/sudo",
             "/etc/crontab", "/etc/cron.d"]
    rows = []
    for p in PATHS:
        path = Path(p)
        if not path.exists():
            continue
        try:
            st    = path.stat()
            owner = pwd.getpwuid(st.st_uid).pw_name
            grpn  = grp.getgrgid(st.st_gid).gr_name
            mode  = oct(st.st_mode & 0o777).replace("0o", "")
            rows.append({"path": p, "mode": mode, "owner": owner, "group": grpn})
        except Exception:
            rows.append({"path": p, "mode": "—", "owner": "—", "group": "—"})
    return rows


SYSCTL_EXPECTED: Dict[str, Tuple[str, str]] = {
    "kernel.randomize_va_space":               ("2",  "ASLR — Address Space Layout Randomization"),
    "kernel.kptr_restrict":                    ("2",  "Restrict kernel pointer exposure in /proc"),
    "kernel.dmesg_restrict":                   ("1",  "Restrict dmesg access to privileged users"),
    "kernel.sysrq":                            ("0",  "Disable the SysRq magic key"),
    "kernel.unprivileged_bpf_disabled":        ("1",  "Restrict eBPF programs to root only"),
    "kernel.perf_event_paranoid":              ("3",  "Restrict perf event access"),
    "kernel.yama.ptrace_scope":                ("1",  "Restrict ptrace to child processes only"),
    "kernel.core_uses_pid":                    ("1",  "Append PID to core dump filename"),
    "net.core.bpf_jit_harden":                 ("2",  "Harden BPF JIT compiler against attacks"),
    "net.ipv4.ip_forward":                     ("0",  "Disable IP packet forwarding (non-router)"),
    "net.ipv4.conf.all.send_redirects":        ("0",  "Disable sending ICMP redirect messages"),
    "net.ipv4.conf.default.send_redirects":    ("0",  "Disable sending ICMP redirects (default iface)"),
    "net.ipv4.conf.all.accept_redirects":      ("0",  "Reject incoming ICMP redirect messages"),
    "net.ipv4.conf.default.accept_redirects":  ("0",  "Reject ICMP redirects on default interface"),
    "net.ipv4.conf.all.accept_source_route":   ("0",  "Disable source routing"),
    "net.ipv4.conf.all.log_martians":          ("1",  "Log packets with impossible source addresses"),
    "net.ipv4.conf.default.log_martians":      ("1",  "Log martian packets on default interface"),
    "net.ipv4.conf.all.rp_filter":             ("1",  "Enable reverse path filtering"),
    "net.ipv4.conf.default.rp_filter":         ("1",  "Reverse path filtering on default interface"),
    "net.ipv4.tcp_syncookies":                 ("1",  "SYN cookie protection against SYN flood attacks"),
    "net.ipv4.icmp_echo_ignore_broadcasts":    ("1",  "Ignore ICMP echo requests to broadcast addresses"),
    "net.ipv4.icmp_ignore_bogus_error_responses": ("1", "Ignore malformed ICMP error responses"),
    "net.ipv6.conf.all.accept_redirects":      ("0",  "Reject IPv6 ICMP redirect messages"),
    "net.ipv6.conf.all.accept_ra":             ("0",  "Ignore IPv6 router advertisements"),
    "fs.protected_symlinks":                   ("1",  "Symlink-in-sticky-directory restriction"),
    "fs.protected_hardlinks":                  ("1",  "Restrict hardlink creation to file owner"),
    "fs.protected_fifos":                      ("2",  "Restrict FIFO creation in world-writable dirs"),
    "fs.protected_regular":                    ("2",  "Restrict regular file creation in sticky dirs"),
    "fs.suid_dumpable":                        ("0",  "Disable core dumps for SUID executables"),
}

def collect_sysctl() -> List[Dict[str, str]]:
    rows = []
    for key, (expected, desc) in SYSCTL_EXPECTED.items():
        val = _run(["sysctl", "-n", key]).strip()
        if not val:
            val = "unavailable"
        status = "ok" if val == expected else ("fail" if val != "unavailable" else "na")
        rows.append({"key": key, "val": val, "expected": expected,
                     "desc": desc, "status": status})
    return rows


def collect_sshd() -> List[Dict[str, str]]:
    SEC = {"permitrootlogin", "passwordauthentication", "pubkeyauthentication",
           "permitemptypasswords", "x11forwarding", "usepam", "maxauthtries",
           "logingracetime", "clientaliveinterval", "clientalivecountmax",
           "challengeresponseauthentication", "hostbasedauthentication",
           "permituserenvironment", "allowtcpforwarding", "allowagentforwarding",
           "banner", "port", "authorizedkeysfile", "loglevel", "printlastlog"}
    rows = []
    if not shutil.which("sshd"):
        return rows
    for ln in _run(["sshd", "-T"], sudo=True).splitlines():
        ln = ln.strip()
        if not ln:
            continue
        p = ln.split(None, 1)
        k = p[0].lower() if p else ""
        v = p[1].strip() if len(p) > 1 else ""
        concern = ""
        if k == "permitrootlogin" and v.lower() not in ("no", "prohibit-password"):
            concern = "danger"
        elif k in ("passwordauthentication", "x11forwarding", "allowtcpforwarding") and v.lower() == "yes":
            concern = "warn"
        elif k == "permitemptypasswords" and v.lower() == "yes":
            concern = "danger"
        elif k == "pubkeyauthentication" and v.lower() == "yes":
            concern = "ok"
        rows.append({"key": p[0] if p else "", "val": v,
                     "sec": k in SEC, "concern": concern})
    return rows


def collect_mac() -> Dict[str, str]:
    d = {"type": "none", "status": "Not detected", "detail": ""}
    if shutil.which("aa-status"):
        out = _run(["aa-status"], sudo=True)
        if out.strip():
            d["type"]   = "AppArmor"
            d["status"] = out.splitlines()[0] if out.splitlines() else "Active"
            d["detail"] = out[:3000]
            return d
    if Path("/sys/module/apparmor").exists():
        d["type"]   = "AppArmor"
        d["status"] = "Active (aa-status unavailable)"
        return d
    if shutil.which("getenforce"):
        s = _run(["getenforce"]).strip()
        if s:
            d["type"]   = "SELinux"
            d["status"] = s
            d["detail"] = _run(["sestatus"])[:3000]
            return d
    return d


def collect_ntp() -> Dict[str, str]:
    if shutil.which("timedatectl"):
        out = _run(["timedatectl", "status"])
        sync = "unknown"
        for ln in out.splitlines():
            if "synchronized" in ln.lower():
                sync = "yes" if "yes" in ln.lower() else "no"
                break
        return {"tool": "timedatectl", "sync": sync, "detail": out.strip()}
    if shutil.which("chronyc"):
        out = _run(["chronyc", "tracking"])
        return {"tool": "chronyc", "sync": "yes" if "Reference" in out else "unknown", "detail": out.strip()}
    if shutil.which("ntpq"):
        out = _run(["ntpq", "-p"])
        return {"tool": "ntpq", "sync": "unknown", "detail": out.strip()}
    return {"tool": "none", "sync": "unknown", "detail": ""}


def collect_logins() -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    def parse_last(raw: str, skip_prefix: str = "wtmp") -> List[Dict[str, str]]:
        rows = []
        for ln in raw.splitlines():
            if not ln.strip() or ln.startswith(skip_prefix):
                continue
            p = ln.split()
            if len(p) < 3:
                continue
            rows.append({"user": p[0], "tty": p[1], "host": p[2],
                         "date": " ".join(p[3:])})
        return rows
    success = parse_last(_run(["last", "-n", "50", "-F"]))
    failed  = parse_last(_run(["lastb", "-n", "50", "-F"], sudo=True), skip_prefix="btmp")
    return success, failed


def collect_cron() -> List[Dict[str, str]]:
    jobs = []
    for f in [Path("/etc/crontab")] + list(Path("/etc/cron.d").glob("*") if Path("/etc/cron.d").is_dir() else []):
        if not f.is_file():
            continue
        try:
            for ln in f.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    jobs.append({"src": str(f), "type": "system", "entry": ln})
        except Exception:
            pass
    for d in ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"):
        dp = Path(d)
        if dp.is_dir():
            for f in dp.iterdir():
                if f.is_file():
                    jobs.append({"src": d, "type": "system", "entry": f"[script] {f.name}"})
    try:
        for pw in pwd.getpwall():
            if pw.pw_uid < 1000 and pw.pw_uid != 0:
                continue
            out = _run(["crontab", "-l", "-u", pw.pw_name], sudo=True)
            for ln in out.splitlines():
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    jobs.append({"src": pw.pw_name, "type": "user", "entry": ln})
    except Exception:
        pass
    for ln in _run(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"]).splitlines():
        if ln.strip():
            jobs.append({"src": "systemd", "type": "timer", "entry": ln.strip()})
    return jobs


def collect_important_files() -> List[Dict[str, str]]:
    FILES = ["/etc/motd", "/etc/issue", "/etc/issue.net", "/etc/ssh/sshd_config",
             "/etc/login.defs", "/etc/pam.d/common-password", "/etc/pam.d/sshd",
             "/etc/sudoers", "/etc/security/limits.conf", "/etc/audit/auditd.conf",
             "/etc/rsyslog.conf", "/etc/sysctl.conf", "/etc/hosts", "/etc/resolv.conf"]
    rows = []
    for fp in FILES:
        p = Path(fp)
        if not p.exists() or not p.is_file():
            rows.append({"path": fp, "present": "no", "mode": "—",
                         "owner": "—", "group": "—", "size": "—", "preview": ""})
            continue
        try:
            st    = p.stat()
            owner = pwd.getpwuid(st.st_uid).pw_name
            grpn  = grp.getgrgid(st.st_gid).gr_name
            mode  = oct(st.st_mode & 0o777).replace("0o", "")
            content = p.read_text(encoding="utf-8", errors="replace")
            lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")][:50]
            rows.append({"path": fp, "present": "yes", "mode": mode,
                         "owner": owner, "group": grpn,
                         "size": f"{st.st_size} B",
                         "preview": "\n".join(lines)[:3000]})
        except Exception as e:
            rows.append({"path": fp, "present": "error", "mode": "—",
                         "owner": "—", "group": "—", "size": "—", "preview": str(e)})
    return rows


def collect_suid_sgid(limit: int = 300) -> List[str]:
    out = _run(["find", "/", "-xdev", "-type", "f",
                "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print"], sudo=True)
    return [l for l in out.splitlines() if l.strip()][:limit]


def collect_world_writable(limit: int = 300) -> List[str]:
    result: List[str] = []
    for target in ("/etc", "/usr/local", "/home", "/var/www", "/tmp"):
        if Path(target).is_dir():
            out = _run(["find", target, "-xdev", "-type", "f", "-perm", "-0002", "-print"])
            result.extend(l for l in out.splitlines() if l.strip())
    return result[:limit]


def collect_cert_expiry(limit: int = 80) -> List[Dict[str, str]]:
    if not shutil.which("openssl"):
        return []
    certs = []
    cert_dir = Path("/etc/ssl/certs")
    if not cert_dir.is_dir():
        return []
    files = list(cert_dir.glob("*.pem"))[:limit] + list(cert_dir.glob("*.crt"))[:limit]
    for cf in files[:limit]:
        if not cf.is_file():
            continue
        meta = _run(["openssl", "x509", "-in", str(cf), "-noout", "-subject", "-enddate"])
        if not meta:
            continue
        subj = enddate = ""
        for ln in meta.splitlines():
            if ln.startswith("subject"):
                subj = ln.replace("subject=", "").strip()
            elif ln.startswith("notAfter"):
                enddate = ln.replace("notAfter=", "").strip()
        status = "ok"
        try:
            exp = datetime.strptime(enddate, "%b %d %H:%M:%S %Y %Z")
            days = (exp - datetime.utcnow()).days
            status = "expired" if days < 0 else ("warn" if days <= 30 else "ok")
        except Exception:
            days = None
        certs.append({"file": cf.name, "subject": subj[:80], "expires": enddate,
                      "days": str(days) if days is not None else "—", "status": status})
    return certs


def collect_upgradeable() -> List[str]:
    """Return a list of packages with available updates, one per entry."""
    mgr = _pkg_mgr()
    pkgs: List[str] = []

    if mgr == "apt":
        # apt-get --dry-run upgrade emits "Inst pkg [old] (new repo)" for every upgradable pkg
        # More reliable than `apt list --upgradable` which may emit ANSI/WARNING noise
        out = _run(["apt-get", "--dry-run", "upgrade"])
        for ln in out.splitlines():
            ln = re.sub(r"\x1b\[[0-9;]*m", "", ln).strip()
            if ln.startswith("Inst "):
                # "Inst bash [5.1-2] (5.2-1 Debian:stable [amd64])"
                parts = ln.split()
                pkg = parts[1] if len(parts) > 1 else ln
                # grab new version if present inside parentheses
                m = re.search(r"\(([^\s)]+)", ln)
                ver = f"  →  {m.group(1)}" if m else ""
                pkgs.append(f"{pkg}{ver}")
        # Fallback: if apt-get dry-run returned nothing (e.g. partial installs state),
        # try apt list --upgradable
        if not pkgs:
            out2 = _run(["apt", "list", "--upgradable"])
            for ln in out2.splitlines():
                ln = re.sub(r"\x1b\[[0-9;]*m", "", ln).strip()
                if ln and not ln.lower().startswith(("listing", "warning", "note")):
                    pkgs.append(ln)

    elif mgr == "dnf":
        # `dnf list --upgrades` is more parseable than `check-update` (which exits 100)
        out = _run(["dnf", "list", "--upgrades", "--quiet"])
        for ln in out.splitlines():
            ln = re.sub(r"\x1b\[[0-9;]*m", "", ln).strip()
            if not ln or ln.lower().startswith(("last metadata", "available upgrade",
                                                 "updated package", "obsolet")):
                continue
            # "pkg.arch  version  repo" — at least two fields
            if re.match(r"^\S+\.\S+\s+\S+", ln):
                parts = ln.split()
                pkgs.append(f"{parts[0]}  →  {parts[1]}" if len(parts) >= 2 else parts[0])

    elif mgr == "yum":
        out = _run(["yum", "list", "updates", "--quiet"])
        for ln in out.splitlines():
            ln = re.sub(r"\x1b\[[0-9;]*m", "", ln).strip()
            if not ln or ln.lower().startswith(("loaded plugin", "repo id",
                                                 "updated package")):
                continue
            if re.match(r"^\S+\.\S+\s+\S+", ln):
                parts = ln.split()
                pkgs.append(f"{parts[0]}  →  {parts[1]}" if len(parts) >= 2 else parts[0])

    elif mgr == "zypper":
        out = _run(["zypper", "--no-refresh", "list-updates"])
        for ln in out.splitlines():
            ln = ln.strip()
            # Skip header rows: "Loading...", "S | Repository | ...", separator lines
            if not ln or re.match(r"^[-+|=]+$", ln) or ln.startswith(("S |", "Loading",
                                                                         "Repository data")):
                continue
            if "|" in ln:
                # "v | repo | pkg | old_ver | new_ver | arch"
                cols = [c.strip() for c in ln.split("|")]
                if len(cols) >= 5 and cols[0].lower() != "s":
                    pkgs.append(f"{cols[2]}  →  {cols[4]}" if cols[2] else ln)

    elif mgr == "pacman":
        out = _run(["pacman", "-Qu"])
        pkgs = [re.sub(r"\x1b\[[0-9;]*m", "", ln).strip()
                for ln in out.splitlines() if ln.strip()]

    elif mgr == "apk":
        out = _run(["apk", "version", "-l", "<"])
        for ln in out.splitlines():
            ln = ln.strip()
            if ln and not ln.lower().startswith(("installed", "fetch")):
                pkgs.append(ln)

    return pkgs


def collect_audit_rules() -> List[str]:
    if not shutil.which("auditctl"):
        return []
    return [l for l in _run(["auditctl", "-l"], sudo=True).splitlines() if l.strip()]


def collect_all() -> Dict[str, Any]:
    """Collect ALL system data and return as a dict."""
    print("[INFO] Collecting system information...")
    data: Dict[str, Any] = {}
    data["system"]     = collect_system()
    data["disk"]       = collect_disk()
    data["users"]      = collect_users()
    data["aging"]      = collect_password_aging()
    data["services"]   = collect_services()
    data["ports"]      = collect_ports()
    data["firewall"]   = collect_firewall()
    data["mounts"]     = collect_mounts()
    data["imp_paths"]  = collect_important_paths()
    data["sysctl"]     = collect_sysctl()
    data["sshd"]       = collect_sshd()
    data["mac"]        = collect_mac()
    data["ntp"]        = collect_ntp()
    logins, failed = collect_logins()
    data["logins"]     = logins
    data["failed_logins"] = failed
    data["cron"]       = collect_cron()
    data["imp_files"]  = collect_important_files()
    data["suid_sgid"]  = collect_suid_sgid()
    data["world_wr"]   = collect_world_writable()
    data["certs"]      = collect_cert_expiry()
    data["upgrades"]   = collect_upgradeable()
    data["audit"]      = collect_audit_rules()
    print("[INFO] System data collection complete.")
    return data


# ── Lynis installation & execution ────────────────────────────────────────────
class ParsedReport:
    def __init__(self, values: Dict[str, str], arrays: Dict[str, List[str]]) -> None:
        self.values = values
        self.arrays = arrays


def parse_lynis_report(path: Path) -> ParsedReport:
    values: Dict[str, str] = {}
    arrays: Dict[str, List[str]] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        k, v = ln.split("=", 1)
        if k.endswith("[]"):
            arrays.setdefault(k[:-2].strip(), []).append(v.strip())
        else:
            values[k.strip()] = v.strip()
    return ParsedReport(values=values, arrays=arrays)


def _parse_rec(entry: str) -> Tuple[str, str, str]:
    p = entry.split("|")
    return (p[0].strip() if p else "N/A",
            p[1].strip() if len(p) > 1 else "",
            p[2].strip() if len(p) > 2 else "")


def _parse_detail(entry: str) -> Tuple[str, str, str]:
    p = entry.split("|")
    tid = p[0].strip() if p else "N/A"
    cmp = p[1].strip() if len(p) > 1 else ""
    kv_blob = p[2].strip() if len(p) > 2 else ""
    pairs: Dict[str, str] = {}
    for chunk in kv_blob.split(";"):
        chunk = chunk.strip()
        if chunk and ":" in chunk:
            k2, v2 = chunk.split(":", 1)
            pairs[k2.strip()] = v2.strip()
    desc = pairs.get("desc", "")
    fld  = pairs.get("field", "")
    pref = pairs.get("prefval", "")
    cur  = pairs.get("value", "")
    out  = []
    if desc:
        out.append(desc)
    if fld:
        out.append(f"Field: {fld}")
    if pref or cur:
        out.append(f"Expected: {pref or 'N/A'} — Current: {cur or 'N/A'}")
    return tid, cmp, " | ".join(out) if out else kv_blob


def load_config(path: Optional[Path] = None) -> Dict[str, str]:
    """Load report.conf and return a flat dict of values."""
    defaults = {
        "logo":        "",
        "client_name": "",
        "created_by":  "",
        "disclaimer":  (
            "This report is strictly confidential and intended solely for the named "
            "client organisation. It contains sensitive security information about the "
            "assessed system. Unauthorised disclosure or distribution to any third party "
            "is prohibited without prior written consent."
        ),
    }
    candidates = [
        path,
        Path("report.conf"),
        Path(__file__).parent / "report.conf",
    ]
    cfg = configparser.ConfigParser(interpolation=None)
    for p in candidates:
        if p and p.exists():
            cfg.read(str(p))
            break
    if cfg.has_option("branding", "logo"):         defaults["logo"]        = cfg.get("branding", "logo").strip()
    if cfg.has_option("branding", "client_name"):  defaults["client_name"] = cfg.get("branding", "client_name").strip()
    if cfg.has_option("branding", "created_by"):   defaults["created_by"]  = cfg.get("branding", "created_by").strip()
    if cfg.has_option("footer",   "disclaimer"):   defaults["disclaimer"]  = cfg.get("footer",   "disclaimer").strip()
    return defaults


def _score_label(score: int) -> Tuple[str, str, str]:
    """Return (label, css_class, grade_letter)."""
    if score >= 90: return "Excellent",        "score-ok",   "A"
    if score >= 80: return "Good",             "score-ok",   "B"
    if score >= 65: return "Fair",             "score-warn", "C"
    if score >= 50: return "Needs Improvement","score-warn", "D"
    return "Critical",                         "score-bad",  "F"


def _priority(status: str, summary: str, rec: str) -> str:
    text = f"{summary} {rec}".lower()
    if status == "warning":
        return "P1"
    if status in {"suggestion", "manual"}:
        return "P1" if any(k in text for k in ("ssh", "firewall", "logging", "sudo")) else "P2"
    return "P3"


def build_test_rows(rep: ParsedReport, skip_reasons: Dict[str, List[str]]) -> Tuple[
        List[str], Dict[str, int], Dict[str, int], List[Dict[str, str]], List[str]]:

    vals   = rep.values
    arrays = rep.arrays

    def _pipe_list(v: str) -> List[str]:
        return [x.strip() for x in v.split("|") if x.strip()]

    executed  = _pipe_list(vals.get("tests_executed", ""))
    skipped   = _pipe_list(vals.get("tests_skipped", ""))
    manual_ids = {e.split(":", 1)[0].strip() for e in arrays.get("manual_event", []) if e.strip()}

    sugg_by: Dict[str, List[Tuple[str, str]]] = {}
    for e in arrays.get("suggestion", []):
        tid, msg, adv = _parse_rec(e)
        sugg_by.setdefault(tid, []).append((msg, adv))

    warn_by: Dict[str, List[str]] = {}
    for e in arrays.get("warning", []):
        tid, msg, _ = _parse_rec(e)
        warn_by.setdefault(tid, []).append(msg)

    detail_by: Dict[str, List[Tuple[str, str]]] = {}
    for e in arrays.get("details", []):
        tid, cmp, dtxt = _parse_detail(e)
        detail_by.setdefault(tid, []).append((cmp, dtxt))

    seen: set = set()
    unique_exec: List[str] = []
    for tid in executed:
        if tid not in seen:
            unique_exec.append(tid)
            seen.add(tid)

    rows: List[str] = []
    status_counts = {"passed": 0, "suggestion": 0, "warning": 0, "manual": 0, "skipped": 0}
    prio_counts   = {"P1": 0, "P2": 0, "P3": 0}
    actions: List[Dict[str, str]] = []

    for tid in unique_exec:
        status = "passed"
        if tid in manual_ids:   status = "manual"
        if tid in sugg_by:      status = "suggestion"
        if tid in warn_by:      status = "warning"
        status_counts[status] += 1

        warns   = [x for x in warn_by.get(tid, []) if x]
        suggs   = sugg_by.get(tid, [])
        findings = [x[0] for x in suggs if x[0]]
        advices  = [x[1] for x in suggs if x[1]]
        details_e = detail_by.get(tid, [])
        comps    = ", ".join(sorted({c for c, _ in details_e if c})) or "—"
        dets     = [d for _, d in details_e if d] or ["—"]

        summary_items  = warns or findings or ["No issue reported."]
        rec_items      = advices or ["No specific recommendation."]
        summary = " | ".join(summary_items)
        rec     = " | ".join(rec_items)
        prio    = _priority(status, summary, rec)
        prio_counts[prio] += 1

        if status in {"warning", "suggestion", "manual"}:
            actions.append({"priority": prio, "test_id": tid, "status": status.upper(),
                             "summary_html": "<br>".join(esc(x) for x in summary_items),
                             "rec_html":     "<br>".join(esc(x) for x in rec_items)})

        s_badge = f"<span class='badge badge-{('red' if status=='warning' else 'orange' if status=='suggestion' else 'purple' if status=='manual' else 'gray' if status=='skipped' else 'green')}'>{status.upper()}</span>"
        p_badge = f"<span class='badge badge-{('red' if prio=='P1' else 'orange' if prio=='P2' else 'blue')}'>{prio}</span>"
        rows.append(
            f"<tr class='row-{status}' data-status='{status}' data-prio='{prio}'>"
            f"<td class='mono'>{esc(tid)}</td><td>{s_badge}</td><td>{p_badge}</td>"
            f"<td>{'<br>'.join(esc(x) for x in summary_items)}</td>"
            f"<td>{'<br>'.join(esc(x) for x in rec_items)}</td>"
            f"<td class='mono'>{esc(comps)}</td>"
            f"<td>{'<br>'.join(esc(x) for x in dets)}</td></tr>"
        )

    def _skip_reason(tid: str) -> str:
        lg = skip_reasons.get(tid, [])
        if lg:
            return " | ".join(lg)
        pfx = tid.split("-", 1)[0]
        hints = {"DBS": "No database engine detected.", "PHP": "PHP not installed.",
                 "HTTP": "No web server detected.", "SNMP": "SNMP not running.",
                 "MAIL": "No SMTP daemon detected.", "CONT": "Container test N/A.",
                 "LDAP": "LDAP not enabled.", "KRB": "Kerberos not present."}
        return hints.get(pfx, "Prerequisite not met or profile skipped.")

    skipped_rows: List[str] = []
    for tid in skipped:
        status_counts["skipped"] += 1
        prio_counts["P3"] += 1
        reason = _skip_reason(tid)
        rows.append(
            f"<tr class='row-skipped' data-status='skipped' data-prio='P3'>"
            f"<td class='mono'>{esc(tid)}</td>"
            f"<td><span class='badge badge-gray'>SKIPPED</span></td>"
            f"<td><span class='badge badge-blue'>P3</span></td>"
            f"<td>{esc(reason)}</td><td>—</td><td>—</td><td>—</td></tr>"
        )
        skipped_rows.append(
            f"<tr><td class='mono'>{esc(tid)}</td>"
            f"<td class='mono'>{esc(tid.split('-',1)[0] if '-' in tid else 'GEN')}</td>"
            f"<td>{esc(reason)}</td></tr>"
        )

    actions.sort(key=lambda a: ({"P1": 0, "P2": 1, "P3": 2}[a["priority"]], a["test_id"]))
    return rows, status_counts, prio_counts, actions, skipped_rows


def parse_skip_reasons_from_log(log_path: Optional[Path]) -> Dict[str, List[str]]:
    if not log_path or not log_path.exists():
        return {}
    pat = re.compile(r"(?P<t>[A-Z0-9]{3,5}-\d{3,4}).*?\[\s*SKIPPED\s*\]", re.IGNORECASE)
    reasons: Dict[str, List[str]] = {}
    for ln in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = pat.search(ln)
        if not m:
            continue
        tid     = m.group("t").upper()
        cleaned = re.sub(r"\[\s*SKIPPED\s*\]", "", ln, flags=re.IGNORECASE).strip(" -\t")
        if cleaned:
            reasons.setdefault(tid, []).append(cleaned)
    return reasons


_CUSTOM_PRF_SRC = Path(__file__).parent / "custom.prf"


def _deploy_custom_prf() -> None:
    """Copy custom.prf into the Lynis profile directory if not already present."""
    if not _CUSTOM_PRF_SRC.exists():
        return
    # Detect Lynis profile directory
    for candidate in [
        Path("/etc/lynis"),
        Path("/usr/local/etc/lynis"),
        Path("/usr/share/lynis"),
    ]:
        if candidate.exists():
            dest = candidate / "custom.prf"
            try:
                if not dest.exists() or dest.read_bytes() != _CUSTOM_PRF_SRC.read_bytes():
                    sudo_prefix = ["sudo"] if os.geteuid() != 0 else []
                    subprocess.run(sudo_prefix + ["cp", str(_CUSTOM_PRF_SRC), str(dest)], check=True)
                    print(f"[INFO] custom.prf deployed to {dest}")
                else:
                    print(f"[INFO] custom.prf already up-to-date at {dest}")
            except Exception as e:
                print(f"[WARN] Could not deploy custom.prf to {dest}: {e}", file=sys.stderr)
            return
    print("[WARN] Could not find Lynis profile directory — custom.prf not deployed.", file=sys.stderr)


def install_lynis() -> None:
    if shutil.which("lynis"):
        _deploy_custom_prf()
        return
    print("[INFO] Lynis not found, installing...")
    mgr = _pkg_mgr()
    cmds: Dict[str, List[List[str]]] = {
        "apt":    [["apt-get", "update"], ["apt-get", "install", "-y", "lynis"]],
        "dnf":    [["dnf", "install", "-y", "lynis"]],
        "yum":    [["yum", "install", "-y", "lynis"]],
        "zypper": [["zypper", "--non-interactive", "install", "lynis"]],
        "pacman": [["pacman", "-Sy", "--noconfirm", "lynis"]],
        "apk":    [["apk", "add", "--no-cache", "lynis"]],
    }
    for cmd in cmds.get(mgr, []):
        subprocess.run((["sudo"] if os.geteuid() != 0 else []) + cmd, check=True)
    if not shutil.which("lynis"):
        raise RuntimeError("Lynis installation failed.")
    print("[INFO] Lynis installed.")
    _deploy_custom_prf()


def run_lynis(report_path: Path, log_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = (["sudo"] if os.geteuid() != 0 else []) + [
        "lynis", "audit", "system",
        "--report-file", str(report_path),
        "--logfile",     str(log_path),
    ]
    print(f"[INFO] Running Lynis audit → {report_path}")
    subprocess.run(cmd, check=True)
    print("[INFO] Lynis audit complete.")


def build_logo_uri(logo_src) -> str:
    """Accept an http(s) URL (returned as-is) or a local PNG path (base64-encoded)."""
    if not logo_src:
        return ""
    s = str(logo_src).strip()
    if s.lower().startswith(("http://", "https://")):
        return s
    p = Path(s)
    if not p.exists():
        raise FileNotFoundError(f"Logo file not found: {p}")
    if p.suffix.lower() not in (".png", ".jpg", ".jpeg", ".svg", ".gif", ".webp"):
        raise ValueError(f"Unsupported logo format: {p.suffix}")
    mime = {".jpg": "jpeg", ".jpeg": "jpeg", ".svg": "svg+xml",
            ".gif": "gif", ".webp": "webp"}.get(p.suffix.lower(), "png")
    return f"data:image/{mime};base64," + base64.b64encode(p.read_bytes()).decode()


def default_paths() -> Tuple[Path, Path, Path]:
    hn   = socket.gethostname().split(".", 1)[0]
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in hn)
    ds   = datetime.now().strftime("%Y-%m-%d")
    report = Path("reports") / f"report_{safe}_{ds}.dat"
    log    = Path("results") / f"lynis_{safe}_{ds}.log"
    html   = Path("results") / f"report_{safe}_{ds}.html"
    return report, log, html


# ── HTML rendering ────────────────────────────────────────────────────────────
_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f1f5f9;--surface:#fff;--border:#e2e8f0;--text:#0f172a;
  --muted:#64748b;--primary:#1e40af;--primary-light:#3b82f6;
  --ok:#059669;--warn:#d97706;--danger:#dc2626;--purple:#7c3aed;--info:#0284c7;
  --r-sm:6px;--r-md:10px;--r-lg:16px;
  --shadow-sm:0 1px 3px rgba(15,23,42,.08);
  --shadow-md:0 4px 16px rgba(15,23,42,.10);
  --shadow-lg:0 12px 40px rgba(30,58,138,.18);
}
html{scroll-behavior:smooth}
body{font-family:"Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
  font-size:14px;line-height:1.6;color:var(--text);background:var(--bg)}
a{color:var(--primary);text-decoration:none}
strong{font-weight:600}

/* Layout */
.page{max-width:1460px;margin:0 auto;padding:20px 24px 60px}

/* Header */
.header{background:linear-gradient(135deg,#0c1a3a 0%,#1e3a8a 50%,#2563eb 100%);
  border-radius:var(--r-lg);padding:26px 32px;color:#fff;
  display:flex;justify-content:space-between;align-items:center;gap:24px;
  box-shadow:var(--shadow-lg);margin-bottom:16px}
.header-brand{display:flex;align-items:center;gap:16px}
.header-brand h1{font-size:1.55rem;font-weight:800;letter-spacing:-.03em;color:#fff}
.header-meta{display:flex;flex-wrap:wrap;gap:6px 20px;margin-top:8px}
.header-meta span{font-size:.82rem;color:#bfdbfe;display:flex;align-items:center;gap:5px}
.header-meta span b{color:#e0f2fe}
.logo{max-height:64px;max-width:180px;border-radius:8px;background:rgba(255,255,255,.12);padding:8px}

/* KPI strip */
.kpi-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);
  padding:14px 16px;box-shadow:var(--shadow-sm)}
.kpi-label{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600}
.kpi-value{font-size:1.6rem;font-weight:800;letter-spacing:-.03em;line-height:1;margin-top:3px}
.kpi-sub{font-size:.76rem;color:var(--muted);margin-top:2px}
.kpi-value.ok{color:var(--ok)}.kpi-value.warn{color:var(--warn)}.kpi-value.danger{color:var(--danger)}

/* Tabs */
.tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:18px}
.tab-btn{border:none;background:transparent;padding:11px 24px;font-size:.9rem;font-weight:600;
  color:var(--muted);cursor:pointer;border-bottom:3px solid transparent;margin-bottom:-2px;
  transition:color .15s,border-color .15s;display:flex;align-items:center;gap:7px}
.tab-btn svg{opacity:.7;transition:opacity .15s}
.tab-btn:hover{color:var(--primary)}
.tab-btn.active{color:var(--primary);border-bottom-color:var(--primary);background:rgba(30,64,175,.04)}
.tab-btn.active svg{opacity:1}
.panel{display:none}.panel.active{display:block}

/* Info cards */
.card-grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));margin-bottom:0}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);
  padding:18px 20px;box-shadow:var(--shadow-sm)}
.card-title{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted);margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:6px}
.card-title svg{color:var(--primary)}
.kv-list{display:flex;flex-direction:column;gap:0}
.kv-row{display:flex;justify-content:space-between;align-items:baseline;gap:8px;
  padding:6px 0;border-bottom:1px dashed #f1f5f9;font-size:.86rem}
.kv-row:last-child{border-bottom:none}
.kv-key{color:var(--muted);font-weight:500;min-width:130px;flex-shrink:0}
.kv-val{font-weight:600;text-align:right;word-break:break-all}

/* Section wrapper */
.section{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);
  margin-bottom:14px;box-shadow:var(--shadow-sm);overflow:hidden}
.section-hdr{padding:13px 20px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;background:#fafbfc}
.section-title{font-size:.97rem;font-weight:700;display:flex;align-items:center;gap:8px}
.section-title svg{color:var(--primary)}
.section-sub{font-size:.78rem;color:var(--muted);margin-top:2px}
.section-body{padding:0}

/* Collapsible */
details{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-md);
  margin-bottom:12px;box-shadow:var(--shadow-sm);overflow:hidden}
summary{cursor:pointer;padding:13px 20px;font-size:.95rem;font-weight:700;
  display:flex;align-items:center;gap:8px;list-style:none;
  border-bottom:1px solid transparent;transition:background .12s}
summary::-webkit-details-marker{display:none}
summary .caret{margin-left:auto;font-size:.65rem;color:var(--muted);transition:transform .2s}
details[open] summary{border-bottom-color:var(--border);background:#fafbfc}
details[open] summary .caret{transform:rotate(90deg)}
summary svg{color:var(--primary)}
.det-body{padding:16px 20px}

/* Tables */
.tbl-wrap{overflow:auto;border-radius:var(--r-sm)}
.scrollable{max-height:480px;overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:.84rem}
thead th{position:sticky;top:0;z-index:2;background:#f8fafc;padding:9px 12px;
  text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;
  font-weight:700;color:var(--muted);border-bottom:2px solid var(--border);white-space:nowrap}
tbody tr{transition:background .07s}
tbody tr:hover{background:#f8fafc}
td{padding:8px 12px;vertical-align:top;border-bottom:1px solid var(--border);word-break:break-word}
tr:last-child td{border-bottom:none}
.row-warning{background:#fffbfb}.row-warning:hover{background:#fff1f2}
.row-suggestion{background:#fffdf0}.row-suggestion:hover{background:#fef9c3}

/* Badges */
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;
  font-size:.7rem;font-weight:700;letter-spacing:.02em;white-space:nowrap}
.badge-green{background:#dcfce7;color:#15803d}
.badge-red{background:#fee2e2;color:#b91c1c}
.badge-orange{background:#ffedd5;color:#c2410c}
.badge-blue{background:#dbeafe;color:#1d4ed8}
.badge-gray{background:#f1f5f9;color:#475569}
.badge-purple{background:#ede9fe;color:#6d28d9}
.badge-sky{background:#e0f2fe;color:#0369a1}

/* Monospace & helpers */
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.82em}
.muted{color:var(--muted)}.small{font-size:.8em}
.text-ok{color:var(--ok)}.text-warn{color:var(--warn)}.text-danger{color:var(--danger);font-weight:700}
.bold{font-weight:700}
.center{text-align:center}

/* Alert banners */
.alert{border-radius:var(--r-sm);padding:10px 14px;font-size:.86rem;margin-bottom:12px;
  display:flex;align-items:flex-start;gap:8px}
.alert svg{flex-shrink:0;margin-top:1px}
.alert-danger{background:#fee2e2;border:1px solid #fca5a5;color:#991b1b}
.alert-warn{background:#fef9c3;border:1px solid #fde047;color:#92400e}
.alert-ok{background:#dcfce7;border:1px solid #86efac;color:#166534}

/* Code blocks */
.code-block{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.78rem;
  background:#0f172a;color:#cbd5e1;border-radius:var(--r-sm);padding:10px 12px;
  white-space:pre-wrap;max-height:200px;overflow:auto;line-height:1.5}

/* Disk bar */
.disk-bar{width:100%;height:6px;background:#e2e8f0;border-radius:999px;overflow:hidden}
.disk-bar span{display:block;height:100%;border-radius:999px;transition:width .3s}
.disk-bar .ok{background:var(--ok)}.disk-bar .warn{background:var(--warn)}.disk-bar .danger{background:var(--danger)}

/* Filter toolbar */
.filter-bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;
  padding:10px 16px;background:#fafbfc;border-bottom:1px solid var(--border)}
.filter-btn{border:1px solid var(--border);border-radius:999px;background:#fff;
  padding:4px 12px;cursor:pointer;font-size:.76rem;font-weight:600;color:var(--muted);transition:all .12s}
.filter-btn:hover{border-color:var(--primary);color:var(--primary)}
.filter-btn.active{background:var(--primary);border-color:var(--primary);color:#fff}
.search-input{border:1px solid var(--border);border-radius:var(--r-sm);
  padding:5px 10px 5px 30px;font-size:.82rem;min-width:200px;outline:none;color:var(--text);
  background:#fff url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cline x1='21' y1='21' x2='16.65' y2='16.65'/%3E%3C/svg%3E") no-repeat 8px 50%}
.search-input:focus{border-color:var(--primary)}
.spacer{flex:1}

/* Score ring / card */
.score-wrap{display:flex;flex-direction:column;align-items:center;gap:10px}

.score-hero{display:flex;align-items:center;gap:24px;padding:4px 0}
.score-hero svg{flex-shrink:0}
.score-hero-info{display:flex;flex-direction:column;gap:6px}
.score-grade{font-size:3.2rem;font-weight:900;line-height:1;letter-spacing:-.04em}
.score-label-txt{font-size:1rem;font-weight:700;color:var(--text)}
.score-meta{font-size:.8rem;color:var(--muted);margin-top:2px}

.score-full-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-lg);
  padding:28px 32px;display:flex;align-items:center;gap:40px;margin-bottom:16px;
  box-shadow:var(--shadow-md)}
.score-full-left{display:flex;flex-direction:column;gap:14px}
.score-full-stats{display:grid;grid-template-columns:1fr 1fr;gap:8px 24px}
.score-stat{display:flex;flex-direction:column;gap:2px}
.score-stat-lbl{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600}
.score-stat-val{font-size:1.05rem;font-weight:700;color:var(--text)}

/* Footer */
.report-footer{margin-top:40px;padding:16px 24px;border-top:1px solid var(--border);
  font-size:.78rem;color:var(--muted);display:flex;flex-wrap:wrap;gap:6px 20px;
  align-items:flex-start}
.report-footer .footer-brand{font-weight:600;color:var(--text)}
.report-footer .footer-disclaimer{flex:1;min-width:300px;line-height:1.6}

/* sshd security row highlight */
tr.sshd-sec{background:#fffdf5}

/* Subsection (within collapsible) */
.subsection{background:var(--bg);border:1px solid var(--border);border-radius:var(--r-sm);padding:14px 18px}
.subsec-hdr{font-size:.88rem;font-weight:700;display:flex;align-items:center;gap:7px;
  margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border);color:var(--text)}
.subsec-hdr svg{color:var(--primary)}

/* Section description */
.sec-desc{font-size:.83rem;color:var(--muted);line-height:1.65;margin-bottom:12px;
  background:#f8fafc;border-left:3px solid var(--primary-light);padding:8px 12px;border-radius:0 var(--r-sm) var(--r-sm) 0}
.sec-desc code,.sec-desc em{color:var(--text);font-style:normal;font-weight:500}

/* Print */
@media print{
  .tabs,.filter-bar,.search-input{display:none!important}
  .panel{display:block!important}
  details{break-inside:avoid}
  body{background:#fff}
}
"""

_JS = """
(function(){
  /* Tab switching */
  document.querySelectorAll('.tab-btn').forEach(function(btn){
    btn.addEventListener('click',function(){
      var tab=btn.dataset.tab;
      document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active')});
      btn.classList.add('active');
      document.querySelectorAll('.panel').forEach(function(p){p.classList.remove('active')});
      var el=document.getElementById('panel-'+tab);
      if(el) el.classList.add('active');
    });
  });

  /* Lynis test filter */
  var testRows=Array.from(document.querySelectorAll('#tests-tbl tbody tr'));
  var aStatus='all', aPrio='all', aSearch='';
  function filterTests(){
    testRows.forEach(function(r){
      var rs=r.dataset.status||'', rp=r.dataset.prio||'';
      var txt=r.textContent.toLowerCase();
      var ok=(aStatus==='all'||rs===aStatus)&&(aPrio==='all'||rp===aPrio)&&(aSearch===''||txt.includes(aSearch));
      r.style.display=ok?'':'none';
    });
  }
  document.querySelectorAll('#sf .filter-btn').forEach(function(b){
    b.addEventListener('click',function(){
      aStatus=b.dataset.filter||'all';
      document.querySelectorAll('#sf .filter-btn').forEach(function(x){x.classList.toggle('active',x.dataset.filter===aStatus)});
      filterTests();
    });
  });
  document.querySelectorAll('#pf .filter-btn').forEach(function(b){
    b.addEventListener('click',function(){
      aPrio=b.dataset.prio||'all';
      document.querySelectorAll('#pf .filter-btn').forEach(function(x){x.classList.toggle('active',x.dataset.prio===aPrio)});
      filterTests();
    });
  });
  var tSearch=document.getElementById('test-search');
  if(tSearch) tSearch.addEventListener('input',function(){aSearch=tSearch.value.toLowerCase().trim();filterTests();});

  /* Service search */
  var svcRows=Array.from(document.querySelectorAll('#svc-tbl tbody tr'));
  var svcSearch=document.getElementById('svc-search');
  if(svcSearch) svcSearch.addEventListener('input',function(){
    var q=svcSearch.value.toLowerCase().trim();
    svcRows.forEach(function(r){r.style.display=(q===''||r.textContent.toLowerCase().includes(q))?'':'none';});
  });

  /* Port search */
  var portRows=Array.from(document.querySelectorAll('#port-tbl tbody tr'));
  var portSearch=document.getElementById('port-search');
  if(portSearch) portSearch.addEventListener('input',function(){
    var q=portSearch.value.toLowerCase().trim();
    portRows.forEach(function(r){r.style.display=(q===''||r.textContent.toLowerCase().includes(q))?'':'none';});
  });
})();
"""


def _make_score_ring(score: int, color: str, size: int = 140, sw: int = 13) -> str:
    R    = size // 2 - sw
    cx   = cy = size // 2
    circ = 2 * math.pi * R
    dok  = circ * score / 100
    dg   = circ - dok
    fs   = int(size * 0.22)
    fs2  = int(size * 0.085)
    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">'
        f'<circle cx="{cx}" cy="{cy}" r="{R}" fill="none" stroke="#e2e8f0" stroke-width="{sw}"/>'
        f'<circle cx="{cx}" cy="{cy}" r="{R}" fill="none" stroke="{color}" stroke-width="{sw}"'
        f' stroke-dasharray="{dok:.2f} {dg:.2f}" stroke-linecap="round"'
        f' transform="rotate(-90 {cx} {cy})"/>'
        f'<text x="{cx}" y="{cy - fs2//2}" dominant-baseline="central" text-anchor="middle"'
        f' font-size="{fs}" font-weight="900" fill="{color}">{score}</text>'
        f'<text x="{cx}" y="{cy + fs2 + 5}" dominant-baseline="central" text-anchor="middle"'
        f' font-size="{fs2}" fill="#94a3b8">/100</text>'
        f'</svg>'
    )


def _make_score_hero(score: int, label: str, grade: str, risk_lbl: str,
                     risk_css: str, color: str, scan_date: str,
                     sc: Dict[str, int], warnings_n: int, suggestions_n: int) -> str:
    ring = _make_score_ring(score, color, size=150, sw=14)
    return f"""<div class="score-hero">
      {ring}
      <div class="score-hero-info">
        <div style="display:flex;align-items:baseline;gap:10px">
          <span class="score-grade" style="color:{color}">{grade}</span>
          <span class="score-label-txt">{esc(label)}</span>
        </div>
        {badge(f'Risk: {risk_lbl}', risk_css)}
        <div class="score-meta">Scan: {esc(scan_date)}</div>
      </div>
    </div>"""


def _make_score_full(score: int, label: str, grade: str, risk_lbl: str,
                     risk_css: str, color: str, scan_date: str, lynis_ver: str,
                     sc: Dict[str, int], warnings_n: int, suggestions_n: int) -> str:
    ring = _make_score_ring(score, color, size=180, sw=15)
    return f"""<div class="score-full-card">
  {ring}
  <div class="score-full-left">
    <div style="display:flex;align-items:baseline;gap:12px">
      <span class="score-grade" style="color:{color}">{grade}</span>
      <div>
        <div class="score-label-txt" style="font-size:1.3rem">{esc(label)}</div>
        <div class="score-meta">Hardening score: {score}/100 &mdash; {badge(f'Risk: {risk_lbl}', risk_css)}</div>
      </div>
    </div>
    <div class="score-full-stats">
      <div class="score-stat"><span class="score-stat-lbl">Tests passed</span><span class="score-stat-val text-ok">{sc.get('passed',0)}</span></div>
      <div class="score-stat"><span class="score-stat-lbl">Warnings</span><span class="score-stat-val {'text-danger' if warnings_n else 'text-ok'}">{warnings_n}</span></div>
      <div class="score-stat"><span class="score-stat-lbl">Suggestions</span><span class="score-stat-val {'text-warn' if suggestions_n else 'text-ok'}">{suggestions_n}</span></div>
      <div class="score-stat"><span class="score-stat-lbl">Skipped</span><span class="score-stat-val muted">{sc.get('skipped',0)}</span></div>
      <div class="score-stat"><span class="score-stat-lbl">Lynis version</span><span class="score-stat-val mono">{esc(lynis_ver)}</span></div>
      <div class="score-stat"><span class="score-stat-lbl">Scan date</span><span class="score-stat-val">{esc(scan_date)}</span></div>
    </div>
  </div>
</div>"""


def render_html(sys_data, lynis, lynis_path, log_path, logo_uri, cfg: Optional[Dict[str, str]] = None):
    cfg = cfg or {}
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Branding from config
    client_name = cfg.get("client_name", "")
    created_by  = cfg.get("created_by", "")
    disclaimer  = cfg.get("disclaimer", "")
    logo_html   = f"<img src='{logo_uri}' alt='Logo' class='logo'/>" if logo_uri else ""

    lv = lynis.values; la = lynis.arrays
    score     = int(lv.get("hardening_index", "0") or 0)
    score_lbl, _, grade = _score_label(score)
    risk_lbl  = "High" if score < 60 else "Medium" if score < 80 else "Controlled"
    risk_css  = "danger" if score < 60 else "warn" if score < 80 else "ok"
    score_col = "#dc2626" if score < 60 else "#d97706" if score < 80 else "#059669"
    lynis_ver = lv.get("lynis_version", "—")
    scan_start= lv.get("report_datetime_start", "—")
    scan_end  = lv.get("report_datetime_end", "—")
    scan_date = scan_start[:10] if len(scan_start) >= 10 else scan_start
    tests_done= int(lv.get("lynis_tests_done", "0") or 0)
    warnings  = la.get("warning", [])
    suggestions=la.get("suggestion", [])
    manual_lst= la.get("manual", [])
    skip_map  = parse_skip_reasons_from_log(log_path)
    test_rows, sc, pc, actions, skipped_rows = build_test_rows(lynis, skip_map)
    total_chk = max(1, sum(sc.values()))

    # Compact score ring (Machine tab overview card)
    score_ring_sm = _make_score_ring(score, score_col, size=120, sw=12)
    # Hero score for Machine tab card
    score_hero_html = _make_score_hero(score, score_lbl, grade, risk_lbl,
                                        risk_css, score_col, scan_date, sc,
                                        len(warnings), len(suggestions))
    # Full score card for Lynis tab
    score_full_html = _make_score_full(score, score_lbl, grade, risk_lbl,
                                        risk_css, score_col, scan_date, lynis_ver,
                                        sc, len(warnings), len(suggestions))
    sys  = sys_data.get("system", {})
    hostname = sys.get("hostname", lv.get("hostname", "Unknown"))
    os_name  = sys.get("os_name",  lv.get("os_fullname", lv.get("os_name", "Unknown")))
    kernel   = sys.get("kernel",   lv.get("os_kernel_version", "—"))
    arch     = sys.get("arch", "—")
    top_rows = []
    for a in actions[:15]:
        p = a["priority"]; s = a["status"]
        pc_css = {"P1":"red","P2":"orange","P3":"blue"}.get(p,"gray")
        sc_css = {"WARNING":"red","SUGGESTION":"orange","MANUAL":"purple"}.get(s,"gray")
        top_rows.append(f"<tr><td>{badge(p,pc_css)}</td><td class='mono bold'>{esc(a['test_id'])}</td><td>{badge(s,sc_css)}</td><td>{a['summary_html']}</td><td>{a['rec_html']}</td></tr>")
    if not top_rows:
        top_rows.append("<tr><td colspan='5' class='center muted'>No priority actions.</td></tr>")
    rec_rows = []
    for e in suggestions[:120]:
        tid, msg, adv = _parse_rec(e)
        rec_rows.append(f"<tr><td class='mono'>{esc(tid)}</td><td>{esc(msg or chr(8212))}</td><td>{esc(adv or chr(8212))}</td></tr>")
    if not rec_rows:
        rec_rows.append("<tr><td colspan='3' class='center muted'>No recommendations.</td></tr>")
    warn_rows = []
    for e in warnings:
        tid, msg, _ = _parse_rec(e)
        warn_rows.append(f"<tr><td class='mono'>{esc(tid)}</td><td>{esc(msg)}</td></tr>")
    if not warn_rows:
        warn_rows.append("<tr><td colspan='2' class='center muted'>No critical warnings.</td></tr>")
    manual_rows = [f"<li>{esc(x)}</li>" for x in manual_lst] or ["<li>No manual tasks.</li>"]
    if skipped_rows:
        n = len(skipped_rows); skipped_rows = skipped_rows[:200]
        if n > 200: skipped_rows.append(f"<tr><td colspan='3' class='center muted'>Showing 200 of {n}.</td></tr>")
    else:
        skipped_rows = ["<tr><td colspan='3' class='center muted'>No skipped tests.</td></tr>"]
    users = sys_data.get("users", [])
    uid0_others = [u for u in users if u.get("uid0") == "yes" and u.get("name") != "root"]
    if uid0_others:
        names = ", ".join(f"<code>{esc(u['name'])}</code>" for u in uid0_others)
        uid0_alert = f'<div class="alert alert-danger">{icon("alert")} <strong>Critical:</strong> Non-root UID 0: {names}</div>'
    else:
        uid0_alert = f'<div class="alert alert-ok">{icon("check")} Only <strong>root</strong> holds UID 0.</div>'
    user_rows_html = []
    for u in users:
        pwd_c = {"set":"green","locked":"red","no-password":"orange"}.get(u.get("password",""),"gray")
        lc = "green" if u.get("login") == "yes" else "gray"
        ak = int(u.get("keys","0")) if str(u.get("keys","0")).isdigit() else 0
        user_rows_html.append(
            f"<tr><td><strong>{esc(u.get('name',''))}</strong></td>"
            f"<td class='mono muted'>{esc(u.get('uid',''))}</td>"
            f"<td class='mono'>{esc(u.get('home',''))}</td>"
            f"<td class='mono'>{esc(u.get('shell',''))}</td>"
            f"<td>{badge(u.get('login','?'), lc)}</td>"
            f"<td>{badge(u.get('password','?'), pwd_c)}</td>"
            f"<td>{badge(u.get('keys','0'), 'green' if ak>0 else 'gray')}</td>"
            f"<td class='mono small muted'>{esc(u.get('key_prev',''))}</td>"
            f"<td class='muted small'>{esc(u.get('groups','')[:60])}</td></tr>"
        )
    if not user_rows_html:
        user_rows_html.append("<tr><td colspan='9' class='center muted'>No user data.</td></tr>")
    aging = sys_data.get("aging", [])
    aging_rows_html = []
    for a in aging:
        max_d = a.get("max_days","—")
        try: mi = int(max_d); mc = " class='text-danger'" if mi == 99999 else (" class='text-warn'" if mi > 90 else "")
        except Exception: mc = ""
        aging_rows_html.append(
            f"<tr><td><strong>{esc(a.get('name',''))}</strong></td><td{mc}>{esc(max_d)}</td>"
            f"<td>{esc(a.get('min_days','—'))}</td><td>{esc(a.get('warn_days','—'))}</td>"
            f"<td class='muted small'>{esc(a.get('last_change','—'))}</td>"
            f"<td class='muted small'>{esc(a.get('expires','—'))}</td>"
            f"<td class='muted small'>{esc(a.get('acct_exp','—'))}</td></tr>"
        )
    if not aging_rows_html:
        aging_rows_html.append("<tr><td colspan='7' class='center muted'>Requires root.</td></tr>")
    services = sys_data.get("services", [])
    svc_rows_html = []
    for s in services[:500]:
        svc_rows_html.append(
            f"<tr><td class='mono'>{esc(s.get('unit',''))}</td>"
            f"<td>{_svc_badge(s.get('load','—'),'load')}</td>"
            f"<td>{_svc_badge(s.get('active','—'),'active')}</td>"
            f"<td class='mono muted'>{esc(s.get('sub',''))}</td>"
            f"<td>{_svc_badge(s.get('enabled','—'),'enabled')}</td>"
            f"<td class='muted small'>{esc(s.get('desc','')[:80])}</td></tr>"
        )
    if not svc_rows_html:
        svc_rows_html.append("<tr><td colspan='6' class='center muted'>No service data.</td></tr>")
    ports = sys_data.get("ports", [])
    port_rows_html = []
    for p in ports:
        pc2 = "blue" if p.get("proto","").lower() == "tcp" else "sky"
        port_rows_html.append(
            f"<tr><td>{badge(p.get('proto','—'),pc2)}</td>"
            f"<td>{badge(p.get('state','—'),'green')}</td>"
            f"<td class='mono'>{esc(p.get('addr',''))}</td>"
            f"<td class='mono bold'>{esc(p.get('port',''))}</td>"
            f"<td class='mono'>{esc(p.get('proc',''))}</td>"
            f"<td class='mono muted'>{esc(p.get('pid',''))}</td></tr>"
        )
    if not port_rows_html:
        port_rows_html.append("<tr><td colspan='6' class='center muted'>No port data (requires root).</td></tr>")
    fw  = sys_data.get("firewall", {})
    fw_type   = fw.get("type","none")
    ufw_active= fw.get("ufw_active", False)

    nft_parsed = fw.get("nft_parsed", [])
    if nft_parsed:
        nft_rows_h = "".join(
            f"<tr><td class='mono muted small'>{esc(r.get('table',''))}</td>"
            f"<td class='mono'>{esc(r.get('chain',''))}</td>"
            f"<td class='mono small'>{esc(r.get('rule','')[:100])}</td></tr>"
            for r in nft_parsed[:500]
        )
        nft_lines = f"<thead><tr><th>Table</th><th>Chain</th><th>Rule</th></tr></thead><tbody>{nft_rows_h}</tbody>"
    else:
        nft_lines = "<thead><tr><th>Rule</th></tr></thead><tbody><tr><td class='muted'>No NFT rules detected.</td></tr></tbody>"

    ipt_parsed = fw.get("ipt_parsed", [])
    if ipt_parsed:
        ipt_rows_h = "".join(
            f"<tr><td class='mono muted small'>{esc(r.get('table',''))}</td>"
            f"<td class='mono'>{esc(r.get('chain',''))}</td>"
            f"<td>{badge(r.get('target','—'), 'green' if r.get('target') in ('ACCEPT','RETURN') else 'red' if r.get('target') in ('DROP','REJECT') else 'blue')}</td>"
            f"<td class='mono muted'>{esc(r.get('proto',''))}</td>"
            f"<td class='mono muted'>{esc(r.get('src',''))}</td>"
            f"<td class='mono muted'>{esc(r.get('dst',''))}</td>"
            f"<td class='mono small muted'>{esc(r.get('opts','')[:60])}</td></tr>"
            for r in ipt_parsed[:500]
        )
        ipt_lines = f"<thead><tr><th>Table</th><th>Chain</th><th>Target</th><th>Proto</th><th>Source</th><th>Destination</th><th>Options</th></tr></thead><tbody>{ipt_rows_h}</tbody>"
    else:
        ipt_lines = "<thead><tr><th>Rule</th></tr></thead><tbody><tr><td class='muted'>No iptables rules detected.</td></tr></tbody>"

    ufw_parsed = fw.get("ufw_parsed", [])
    if ufw_parsed:
        ufw_rows_h = "".join(
            f"<tr><td class='mono bold'>{esc(r.get('to',''))}</td>"
            f"<td>{badge(r.get('action',''), 'green' if 'ALLOW' in r.get('action','').upper() else 'red' if 'DENY' in r.get('action','').upper() else 'blue')}</td>"
            f"<td class='mono'>{esc(r.get('from',''))}</td></tr>"
            for r in ufw_parsed[:200]
        )
        ufw_lines = f"<thead><tr><th>To (port/service)</th><th>Action</th><th>From</th></tr></thead><tbody>{ufw_rows_h}</tbody>"
    else:
        ufw_lines = "<thead><tr><th>Rule</th></tr></thead><tbody><tr><td class='muted'>UFW not active or no rules configured.</td></tr></tbody>"
    mounts = sys_data.get("mounts", [])
    mount_rows_html = []
    for m in mounts:
        mount_rows_html.append(f"<tr><td class='mono'>{esc(m.get('mp',''))}</td><td class='mono muted'>{esc(m.get('src',''))}</td><td>{badge(m.get('fs','—'),'sky')}</td><td class='mono muted small'>{esc(m.get('opts','')[:80])}</td></tr>")
    if not mount_rows_html:
        mount_rows_html.append("<tr><td colspan='4' class='center muted'>No mount data.</td></tr>")
    disk = sys_data.get("disk", [])
    disk_rows_html = []
    for d in disk:
        pi = d.get("pct_int", 0)
        bc    = "danger" if pi >= 90 else "warn" if pi >= 75 else "ok"
        color = "var(--danger)" if pi >= 90 else ("var(--warn)" if pi >= 75 else "var(--ok)")
        pct_label = esc(d.get('pct','0%'))
        disk_rows_html.append(
            f"<tr><td class='mono'>{esc(d.get('mp',''))}</td><td class='mono muted small'>{esc(d.get('src',''))}</td>"
            f"<td class='mono'>{esc(d.get('size',''))}</td><td class='mono'>{esc(d.get('used',''))}</td><td class='mono'>{esc(d.get('avail',''))}</td>"
            f"<td style='min-width:160px'>"
            f"<div style='display:flex;align-items:center;gap:8px'>"
            f"<div style='flex:1;height:8px;background:#e2e8f0;border-radius:999px;overflow:hidden'>"
            f"<div style='width:{pi}%;height:100%;background:{color};border-radius:999px;transition:width .3s'></div>"
            f"</div>"
            f"<span style='font-size:.82rem;font-weight:700;color:{color};min-width:38px;text-align:right'>{pct_label}</span>"
            f"</div></td></tr>"
        )
    if not disk_rows_html:
        disk_rows_html.append("<tr><td colspan='6' class='center muted'>No disk data.</td></tr>")
    imp_paths = sys_data.get("imp_paths", [])
    imp_path_rows = []
    for p in imp_paths:
        mode = p.get("mode","—"); mc2 = ""
        try:
            mi2 = int(mode, 8)
            if mi2 & 0o002: mc2 = " class='text-danger bold'"
            elif mi2 & 0o020: mc2 = " class='text-warn'"
        except Exception: pass
        imp_path_rows.append(f"<tr><td class='mono'>{esc(p.get('path',''))}</td><td class='mono'{mc2}>{esc(mode)}</td><td class='mono muted'>{esc(p.get('owner',''))}</td><td class='mono muted'>{esc(p.get('group',''))}</td></tr>")
    if not imp_path_rows:
        imp_path_rows.append("<tr><td colspan='4' class='center muted'>No data.</td></tr>")
    suid_h = "".join(f"<tr><td class='mono'>{esc(x)}</td></tr>" for x in sys_data.get("suid_sgid",[])) or "<tr><td class='muted'>None found.</td></tr>"
    ww_h   = "".join(f"<tr><td class='mono'>{esc(x)}</td></tr>" for x in sys_data.get("world_wr",[])) or "<tr><td class='muted'>None found.</td></tr>"
    sysctl_data = sys_data.get("sysctl", [])
    sysctl_ok   = sum(1 for s in sysctl_data if s.get("status") == "ok")
    sysctl_fail = sum(1 for s in sysctl_data if s.get("status") == "fail")
    sysctl_rows_h = []
    for s in sysctl_data:
        st = s.get("status","na")
        if st == "ok":    st_h = badge("Hardened","green")
        elif st == "fail":st_h = f"{badge('Non-compliant','red')} <span class='muted small'>expected: {esc(s.get('expected','?'))}</span>"
        else:             st_h = badge("N/A","gray")
        sysctl_rows_h.append(f"<tr><td class='mono'>{esc(s.get('key',''))}</td><td class='mono bold'>{esc(s.get('val',''))}</td><td>{st_h}</td><td class='muted small'>{esc(s.get('desc',''))}</td></tr>")
    if not sysctl_rows_h:
        sysctl_rows_h.append("<tr><td colspan='4' class='center muted'>No sysctl data.</td></tr>")
    sshd_data = sys_data.get("sshd", [])
    sshd_rows_h = []
    for s in sshd_data:
        c = s.get("concern","")
        vc = {"danger":"text-danger bold","warn":"text-warn","ok":"text-ok"}.get(c,"mono")
        rc = " class='sshd-sec'" if s.get("sec") else ""
        sshd_rows_h.append(f"<tr{rc}><td class='mono'>{esc(s.get('key',''))}</td><td class='{vc} mono'>{esc(s.get('val',''))}</td></tr>")
    if not sshd_rows_h:
        sshd_rows_h.append("<tr><td colspan='2' class='center muted'>sshd not available.</td></tr>")
    mac = sys_data.get("mac", {})
    mac_type=mac.get("type","none"); mac_status=mac.get("status","—"); mac_detail=mac.get("detail","")
    mac_b = badge(mac_type if mac_type != "none" else "None", "green" if mac_type != "none" else "red")
    ntp = sys_data.get("ntp", {})
    ntp_tool=ntp.get("tool","none"); ntp_sync=ntp.get("sync","unknown"); ntp_detail=ntp.get("detail","")
    ntp_b = badge(ntp_sync, "green" if ntp_sync == "yes" else ("orange" if ntp_sync == "unknown" else "red"))
    logins = sys_data.get("logins", [])
    failed = sys_data.get("failed_logins", [])
    login_rows_h = []
    for l in logins[:50]:
        login_rows_h.append(f"<tr><td class='mono bold'>{esc(l.get('user',''))}</td><td class='mono muted'>{esc(l.get('tty',''))}</td><td class='mono'>{esc(l.get('host',''))}</td><td class='muted small'>{esc(l.get('date',''))}</td></tr>")
    if not login_rows_h:
        login_rows_h.append("<tr><td colspan='4' class='center muted'>No login history.</td></tr>")
    failed_rows_h = []
    for l in failed[:50]:
        failed_rows_h.append(f"<tr><td class='mono bold text-danger'>{esc(l.get('user',''))}</td><td class='mono muted'>{esc(l.get('tty',''))}</td><td class='mono'>{esc(l.get('host',''))}</td><td class='muted small'>{esc(l.get('date',''))}</td></tr>")
    if not failed_rows_h:
        failed_rows_h.append("<tr><td colspan='4' class='center muted'>No failed logins (or requires root).</td></tr>")
    cron = sys_data.get("cron", [])
    cron_rows_h = []
    for c in cron[:300]:
        t = c.get("type","system")
        tb = badge(t, "blue" if t=="system" else "sky" if t=="timer" else "orange")
        cron_rows_h.append(f"<tr><td class='mono muted small'>{esc(c.get('src',''))}</td><td>{tb}</td><td class='mono'>{esc(c.get('entry','')[:120])}</td></tr>")
    if not cron_rows_h:
        cron_rows_h.append("<tr><td colspan='3' class='center muted'>No cron jobs found.</td></tr>")
    imp_files = sys_data.get("imp_files", [])
    imp_file_rows_h = []
    for f in imp_files:
        pres = f.get("present","—")
        pres_h = badge("yes","green") if pres=="yes" else (badge("no","red") if pres=="no" else badge("error","orange"))
        imp_file_rows_h.append(
            f"<tr><td class='mono'>{esc(f.get('path',''))}</td><td>{pres_h}</td>"
            f"<td class='mono muted'>{esc(f.get('mode','—'))}</td>"
            f"<td class='mono muted'>{esc(f.get('owner','—'))}:{esc(f.get('group','—'))}</td>"
            f"<td class='muted'>{esc(f.get('size','—'))}</td>"
            f"<td><pre class='code-block'>{esc(f.get('preview','')[:2000])}</pre></td></tr>"
        )
    if not imp_file_rows_h:
        imp_file_rows_h.append("<tr><td colspan='6' class='center muted'>No config file data.</td></tr>")
    certs = sys_data.get("certs", [])
    cert_h = []
    for c in certs:
        st = c.get("status","ok")
        sh = badge("EXPIRED","red") if st=="expired" else (badge("Expiring","orange") if st=="warn" else badge("Valid","green"))
        cert_h.append(f"<tr><td class='mono small'>{esc(c.get('file',''))}</td><td class='small muted'>{esc(c.get('subject','')[:60])}</td><td class='muted small'>{esc(c.get('expires',''))}</td><td class='mono'>{esc(c.get('days','—'))}</td><td>{sh}</td></tr>")
    if not cert_h:
        cert_h.append("<tr><td colspan='5' class='center muted'>No certificate data.</td></tr>")
    upgrades = sys_data.get("upgrades", [])
    def _fmt_upg_row(x: str) -> str:
        # "pkg  →  new_ver" format (set by collect_upgradeable) or raw line
        if "→" in x:
            pkg, _, ver = x.partition("→")
            return (f"<tr><td class='mono small'>{esc(pkg.strip())}</td>"
                    f"<td class='mono small text-warn'>{esc(ver.strip())}</td></tr>")
        return f"<tr><td class='mono small' colspan='2'>{esc(x)}</td></tr>"

    upg_h = "".join(_fmt_upg_row(x) for x in upgrades[:300]) or \
            "<tr><td class='muted center' colspan='2'>No pending updates — system is up to date.</td></tr>"
    upg_thead = "<tr><th>Package</th><th>Available version</th></tr>"
    audit  = sys_data.get("audit", [])
    audit_h= "".join(f"<tr><td class='mono'>{esc(x)}</td></tr>" for x in audit) or "<tr><td class='muted center'>No audit rules.</td></tr>"
    _h = []
    _h.append(f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Security Report &mdash; {esc(hostname)}</title>
<style>{_CSS}</style></head><body><div class="page">
<header class="header">
  <div class="header-brand">{logo_html}
    <div>
      <h1>Security Hardening Report{(' &mdash; ' + esc(client_name)) if client_name else ''}</h1>
      <div class="header-meta">
        <span>{icon('server',14)} <b>Host:</b> {esc(hostname)}</span>
        <span>{icon('cpu',14)} <b>OS:</b> {esc(os_name)}</span>
        <span>{icon('settings',14)} <b>Kernel:</b> {esc(kernel)} {esc(arch)}</span>
        <span>{icon('calendar',14)} <b>Generated:</b> {esc(generated_at)}</span>
        <span>{icon('shield',14)} <b>Lynis:</b> {esc(lynis_ver)}</span>
        {(f"<span>{icon('users',14)} <b>Created by:</b> {esc(created_by)}</span>") if created_by else ""}
      </div>
    </div>
  </div>
</header>""")
    _h.append(f"""
<div class="kpi-strip">
  <div class="kpi"><div class="kpi-label">Hardening Score</div><div class="kpi-value {risk_css}">{score}<span style="font-size:1rem;font-weight:500">/100</span></div><div class="kpi-sub">Grade: <strong>{grade}</strong> &mdash; {esc(score_lbl)}</div></div>
  <div class="kpi"><div class="kpi-label">Risk Level</div><div class="kpi-value {risk_css}">{esc(risk_lbl)}</div><div class="kpi-sub">Based on Lynis</div></div>
  <div class="kpi"><div class="kpi-label">Warnings</div><div class="kpi-value {'danger' if warnings else 'ok'}">{len(warnings)}</div><div class="kpi-sub">Critical findings</div></div>
  <div class="kpi"><div class="kpi-label">Suggestions</div><div class="kpi-value {'warn' if suggestions else 'ok'}">{len(suggestions)}</div><div class="kpi-sub">Improvement items</div></div>
  <div class="kpi"><div class="kpi-label">Tests Done</div><div class="kpi-value">{tests_done}</div><div class="kpi-sub">{sc.get('passed',0)} passed &middot; {sc.get('skipped',0)} skipped</div></div>
  <div class="kpi"><div class="kpi-label">Sysctl Hardened</div><div class="kpi-value {'ok' if sysctl_fail==0 else ('warn' if sysctl_fail<=5 else 'danger')}">{sysctl_ok}/{sysctl_ok+sysctl_fail}</div><div class="kpi-sub">{sysctl_fail} non-compliant</div></div>
  <div class="kpi"><div class="kpi-label">Uptime</div><div class="kpi-value" style="font-size:1.1rem">{esc(sys.get('uptime','—'))}</div><div class="kpi-sub">Load: {esc(sys.get('load_avg','—'))}</div></div>
  <div class="kpi"><div class="kpi-label">Pending Updates</div><div class="kpi-value {'warn' if upgrades else 'ok'}">{len(upgrades)}</div><div class="kpi-sub">Packages to upgrade</div></div>
</div>
<div class="tabs">
  <button class="tab-btn active" data-tab="machine" type="button">{icon('server',15)} Machine Information</button>
  <button class="tab-btn" data-tab="lynis" type="button">{icon('shield',15)} Lynis Scan Results</button>
</div>
<div id="panel-machine" class="panel active">""")
    _h.append(f"""
<div class="card-grid" style="margin-bottom:14px">
  <div class="card">
    <div class="card-title">{icon('server',13)} Host &amp; Runtime</div>
    <div class="kv-list">
      <div class="kv-row"><span class="kv-key">Hostname</span><span class="kv-val mono">{esc(hostname)}</span></div>
      <div class="kv-row"><span class="kv-key">FQDN</span><span class="kv-val mono">{esc(sys.get('fqdn','—'))}</span></div>
      <div class="kv-row"><span class="kv-key">OS</span><span class="kv-val">{esc(os_name)}</span></div>
      <div class="kv-row"><span class="kv-key">Kernel</span><span class="kv-val mono">{esc(kernel)} {esc(arch)}</span></div>
      <div class="kv-row"><span class="kv-key">Uptime</span><span class="kv-val">{esc(sys.get('uptime','—'))}</span></div>
      <div class="kv-row"><span class="kv-key">Load Average</span><span class="kv-val mono">{esc(sys.get('load_avg','—'))}</span></div>
    </div>
  </div>
  <div class="card">
    <div class="card-title">{icon('cpu',13)} Hardware</div>
    <div class="kv-list">
      <div class="kv-row"><span class="kv-key">CPU</span><span class="kv-val">{esc(sys.get('cpu_model','—'))}</span></div>
      <div class="kv-row"><span class="kv-key">CPU Cores</span><span class="kv-val mono">{esc(sys.get('cpu_count','—'))}</span></div>
      <div class="kv-row"><span class="kv-key">Total RAM</span><span class="kv-val mono">{esc(sys.get('mem_total','—'))}</span></div>
      <div class="kv-row"><span class="kv-key">Available RAM</span><span class="kv-val mono">{esc(sys.get('mem_avail','—'))}</span></div>
      <div class="kv-row"><span class="kv-key">RAM Used</span><span class="kv-val mono">{esc(sys.get('mem_used_pct','—'))}</span></div>
      <div class="kv-row"><span class="kv-key">Timezone</span><span class="kv-val">{esc(sys.get('timezone','—'))}</span></div>
    </div>
  </div>
  <div class="card">
    <div class="card-title">{icon('lock',13)} Security Controls</div>
    <div class="kv-list">
      <div class="kv-row"><span class="kv-key">Secure Boot</span><span class="kv-val">{esc(sys.get('secure_boot','—'))}</span></div>
      <div class="kv-row"><span class="kv-key">TPM</span><span class="kv-val">{esc(sys.get('tpm','—'))}</span></div>
      <div class="kv-row"><span class="kv-key">Encryption</span><span class="kv-val">{esc(sys.get('encryption','—'))}</span></div>
      <div class="kv-row"><span class="kv-key">MAC Security</span><span class="kv-val">{mac_b} {esc(mac_status)}</span></div>
      <div class="kv-row"><span class="kv-key">NTP Sync</span><span class="kv-val">{ntp_b} via {esc(ntp_tool)}</span></div>
      <div class="kv-row"><span class="kv-key">Package Manager</span><span class="kv-val">{esc(sys.get('pkg_mgr','—'))}</span></div>
    </div>
  </div>
  <div class="card">
    <div class="card-title">{icon('shield',13)} Hardening Score</div>
    {score_hero_html}
  </div>
</div>""")
    _h.append(f"""
<details open>
<summary>{icon('users')} Users &amp; Authentication <span class="caret">&#9658;</span></summary>
<div class="det-body">
  <p class="sec-desc">This section lists all user accounts with a UID &ge; 1000 (standard users) plus root. It shows the authentication method (password / key), interactive login capability, and group membership. Pay special attention to accounts with <em>locked passwords</em>, <em>SSH keys</em>, and any non-root account holding <em>UID 0</em>.</p>
  {uid0_alert}
  <div class="tbl-wrap scrollable" style="margin-bottom:14px">
    <table><thead><tr><th>Username</th><th>UID</th><th>Home</th><th>Shell</th><th>Login</th><th>Password</th><th>SSH Keys</th><th>Key Preview</th><th>Groups</th></tr></thead>
    <tbody>{"".join(user_rows_html)}</tbody></table>
  </div>
  <div style="font-size:.82rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:8px">Password Aging Policy</div>
  <div class="tbl-wrap scrollable">
    <table><thead><tr><th>User</th><th>Max Days</th><th>Min Days</th><th>Warn Days</th><th>Last Changed</th><th>Expires</th><th>Acct Expires</th></tr></thead>
    <tbody>{"".join(aging_rows_html)}</tbody></table>
  </div>
</div>
</details>
<details>
<summary>{icon('activity')} Services <span class="badge badge-gray" style="margin-left:4px">{len(services)}</span> <span class="caret">&#9658;</span></summary>
<div class="det-body" style="padding:0">
  <p class="sec-desc" style="margin:12px 16px 0">Services running on a system represent its attack surface. Each unnecessary or misconfigured service is a potential entry point for an attacker. <em>Active/enabled</em> services should be reviewed and any service not required for the system&apos;s purpose should be disabled. Services in a <em>failed</em> state may indicate tampering or configuration issues.</p>
  <div class="filter-bar"><span class="muted small">All systemd services &mdash; load, active state, enablement</span><span class="spacer"></span><input class="search-input" id="svc-search" placeholder="Search services..." type="search"/></div>
  <div class="tbl-wrap scrollable"><table id="svc-tbl"><thead><tr><th style="width:240px">Service Unit</th><th style="width:80px">Load</th><th style="width:90px">Active</th><th style="width:90px">Sub-state</th><th style="width:90px">Enabled</th><th>Description</th></tr></thead>
  <tbody>{"".join(svc_rows_html)}</tbody></table></div>
</div>
</details>
<details>
<summary>{icon('globe')} Network &amp; Open Ports <span class="caret">&#9658;</span></summary>
<div class="det-body" style="padding:0">
  <p class="sec-desc" style="margin:12px 16px 0">Open ports represent active network listeners. Each exposed port increases the system&apos;s attack surface. Only ports required by the system&apos;s function should be open. Port information is collected via <code>ss -tulpen</code>. Ports listening on <em>0.0.0.0</em> or <em>::</em> are accessible from any network interface.</p>
  <div class="filter-bar"><span class="muted small">Listening sockets (TCP/UDP) &mdash; <code>ss -tulpen</code></span><span class="spacer"></span><input class="search-input" id="port-search" placeholder="Search ports, process..." type="search"/></div>
  <div class="tbl-wrap scrollable"><table id="port-tbl"><thead><tr><th>Protocol</th><th>State</th><th>Local Address</th><th>Port</th><th>Process</th><th>PID</th></tr></thead>
  <tbody>{"".join(port_rows_html)}</tbody></table></div>
</div>
</details>
<details>
<summary>{icon('flame')} Firewall <span class="badge badge-{'green' if fw_type!='none' else 'red'}">{esc(fw_type)}</span> <span class="caret">&#9658;</span></summary>
<div class="det-body" style="display:flex;flex-direction:column;gap:18px">
  <p class="sec-desc">Firewall rules control which network traffic is allowed to enter, leave, or traverse the system. The rules below are collected from all active firewall backends detected on this host. A missing or permissive ruleset significantly increases exposure to network-based attacks.</p>

  <div class="subsection">
    <div class="subsec-hdr">{icon('flame',14)} NFTables {badge(str(len(fw.get('nft_parsed',[])))+ ' rules', 'green' if fw.get('nft_parsed') else 'gray')}</div>
    <div class="tbl-wrap scrollable"><table>{nft_lines}</table></div>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('flame',14)} iptables / ip6tables {badge(str(len(fw.get('ipt_parsed',[])))+ ' rules', 'green' if fw.get('ipt_parsed') else 'gray')}</div>
    <div class="tbl-wrap scrollable"><table>{ipt_lines}</table></div>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('flame',14)} UFW (Uncomplicated Firewall) {badge('active','green') if ufw_active else badge('inactive','gray')}</div>
    <div class="tbl-wrap scrollable"><table>{ufw_lines}</table></div>
  </div>
</div>
</details>""")
    _h.append(f"""
<details>
<summary>{icon('drive')} Filesystem &amp; Storage <span class="caret">&#9658;</span></summary>
<div class="det-body" style="display:flex;flex-direction:column;gap:18px">
  <p class="sec-desc">Filesystem security covers disk usage monitoring, mount point options (e.g. <code>noexec</code>, <code>nosuid</code>), file ownership and permissions on sensitive paths, and detection of privilege escalation vectors such as SUID/SGID files and world-writable locations.</p>

  <div class="subsection">
    <div class="subsec-hdr">{icon('database',14)} Disk Usage</div>
    <div class="tbl-wrap"><table><thead><tr><th>Mountpoint</th><th>Device</th><th>Total</th><th>Used</th><th>Available</th><th style="min-width:180px">Usage</th></tr></thead><tbody>{"".join(disk_rows_html)}</tbody></table></div>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('drive',14)} Mount Points &amp; Options</div>
    <p class="sec-desc">Mount options like <code>noexec</code>, <code>nosuid</code>, and <code>nodev</code> provide important hardening. For example, <em>/tmp</em> and <em>/home</em> should ideally be mounted with <code>noexec</code> to prevent executing files placed there by an attacker.</p>
    <div class="tbl-wrap scrollable"><table><thead><tr><th>Target</th><th>Source</th><th>Filesystem</th><th>Options</th></tr></thead><tbody>{"".join(mount_rows_html)}</tbody></table></div>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('lock',14)} Important Path Permissions</div>
    <p class="sec-desc">Critical system files and directories must have strict permissions. World-writable entries or incorrect ownership on files like <em>/etc/shadow</em>, <em>/etc/sudoers</em>, or <em>/etc/crontab</em> can be exploited for privilege escalation. Permissions in <em class="text-danger">red</em> indicate world-writable access.</p>
    <div class="tbl-wrap"><table><thead><tr><th>Path</th><th>Mode</th><th>Owner</th><th>Group</th></tr></thead><tbody>{"".join(imp_path_rows)}</tbody></table></div>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('alert',14)} SUID / SGID Files <span class="muted small">(sampled from key directories)</span></div>
    <p class="sec-desc">SUID/SGID files run with elevated privileges regardless of who executes them. Unexpected SUID binaries are a common persistence and privilege escalation vector. Any binary not part of the base OS distribution should be investigated.</p>
    <div class="tbl-wrap" style="max-height:300px"><table><thead><tr><th>File</th></tr></thead><tbody>{suid_h}</tbody></table></div>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('alert',14)} World-Writable Files <span class="muted small">(sampled from key directories)</span></div>
    <p class="sec-desc">World-writable files can be modified by any user or process, making them potential targets for injection attacks or backdoors. Files in <em>/etc</em>, <em>/usr</em>, and web roots should never be world-writable.</p>
    <div class="tbl-wrap" style="max-height:300px"><table><thead><tr><th>File</th></tr></thead><tbody>{ww_h}</tbody></table></div>
  </div>
</div>
</details>
<details>
<summary>{icon('settings')} Hardening Baseline <span class="badge {'badge-green' if sysctl_fail==0 else 'badge-orange'}">{sysctl_ok}/{sysctl_ok+sysctl_fail} sysctl</span> <span class="caret">&#9658;</span></summary>
<div class="det-body" style="display:flex;flex-direction:column;gap:18px">

  <div class="subsection">
    <div class="subsec-hdr">{icon('settings',14)} Security Sysctl Parameters {badge(f'{sysctl_ok} hardened','green')} {badge(f'{sysctl_fail} non-compliant','red' if sysctl_fail else 'gray')}</div>
    <p class="sec-desc">Kernel hardening parameters control how the OS responds to various security-relevant events. Each parameter is compared against the recommended hardening value. Non-compliant values increase the attack surface and should be corrected in <code>/etc/sysctl.conf</code>.</p>
    <div class="tbl-wrap scrollable"><table><thead><tr><th>Parameter</th><th>Current Value</th><th>Compliance</th><th>Description</th></tr></thead><tbody>{"".join(sysctl_rows_h)}</tbody></table></div>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('lock',14)} SSH Daemon Effective Configuration <span class="muted small">(sshd -T)</span></div>
    <p class="sec-desc">The effective SSH configuration is extracted live from the SSH daemon using <code>sshd -T</code>. Security-relevant directives are highlighted. Key settings like <em>PermitRootLogin</em>, <em>PasswordAuthentication</em>, and <em>X11Forwarding</em> directly affect the attack surface exposed via SSH.</p>
    <div class="tbl-wrap" style="max-height:480px"><table><thead><tr><th>Directive</th><th>Value</th></tr></thead><tbody>{"".join(sshd_rows_h)}</tbody></table></div>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('shield',14)} Mandatory Access Control (MAC) &mdash; {esc(mac_type)}</div>
    <p class="sec-desc">MAC frameworks like AppArmor and SELinux enforce mandatory security policies that restrict what processes can do, even when running as root. They provide an important additional layer of defence against privilege escalation and malware.</p>
    <div style="margin-bottom:8px">{mac_b} {esc(mac_status)}</div>
    <pre class="code-block">{esc(mac_detail[:1500])}</pre>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('info',14)} NTP Time Synchronisation &mdash; {esc(ntp_tool)}</div>
    <p class="sec-desc">Accurate time is critical for log integrity, certificate validation, Kerberos authentication, and forensic analysis. An out-of-sync clock can invalidate certificates, corrupt logs, and break authentication mechanisms.</p>
    <div style="margin-bottom:8px">{ntp_b}</div>
    <pre class="code-block">{esc(ntp_detail[:1000])}</pre>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('settings',14)} Audit Rules (auditd) {badge(str(len(audit)),'green' if audit else 'gray')}</div>
    <p class="sec-desc">The Linux Audit Framework records security-relevant system calls and file access events. Effective audit rules ensure accountability and support forensic investigation. The absence of rules means no security events are logged at the kernel level.</p>
    <div class="tbl-wrap" style="max-height:300px"><table><thead><tr><th>Audit Rule</th></tr></thead><tbody>{audit_h}</tbody></table></div>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('package',14)} Pending Software Updates {badge(str(len(upgrades)),'warn' if upgrades else 'green')}</div>
    <p class="sec-desc">Unpatched software is one of the leading causes of security breaches. Each pending update may contain fixes for known CVEs. Systems should be updated regularly, and a patch management process should be established.</p>
    <div class="tbl-wrap" style="max-height:300px"><table><thead>{upg_thead}</thead><tbody>{upg_h}</tbody></table></div>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('database',14)} TLS Certificate Expiry</div>
    <p class="sec-desc">Expired or soon-to-expire certificates cause service disruptions and erode trust. Certificates expiring within 30 days are flagged as warnings. Automated certificate management (e.g. Let&apos;s Encrypt / certbot) is recommended where applicable.</p>
    <div class="tbl-wrap" style="max-height:360px"><table><thead><tr><th>File</th><th>Subject</th><th>Expires</th><th>Days left</th><th>Status</th></tr></thead><tbody>{"".join(cert_h)}</tbody></table></div>
  </div>

</div>
</details>
<details>
<summary>{icon('login')} Login Activity <span class="caret">&#9658;</span></summary>
<div class="det-body" style="display:flex;flex-direction:column;gap:18px">
  <p class="sec-desc">Login history provides accountability and helps detect unauthorised access. Multiple failed logins from the same source may indicate a brute-force attempt. Successful logins from unexpected sources or at unusual times should be investigated.</p>

  <div class="subsection">
    <div class="subsec-hdr">{icon('login',14)} Recent Successful Logins (last 50)</div>
    <div class="tbl-wrap scrollable"><table><thead><tr><th>User</th><th>TTY</th><th>Host / Source</th><th>Date &amp; Duration</th></tr></thead><tbody>{"".join(login_rows_h)}</tbody></table></div>
  </div>

  <div class="subsection">
    <div class="subsec-hdr">{icon('alert',14)} Failed Login Attempts (last 50) <span class="muted small">&mdash; requires root for <code>lastb</code></span></div>
    <div class="tbl-wrap scrollable"><table><thead><tr><th>User</th><th>TTY</th><th>Host / Source</th><th>Date</th></tr></thead><tbody>{"".join(failed_rows_h)}</tbody></table></div>
  </div>
</div>
</details>
<details>
<summary>{icon('calendar')} Scheduled Tasks <span class="caret">&#9658;</span></summary>
<div class="det-body">
  <p class="sec-desc">Scheduled tasks (cron jobs and systemd timers) run automatically and can be used by attackers to maintain persistence. Any unexpected or unauthorised scheduled task should be removed. Tasks running as root are particularly sensitive and must be reviewed carefully.</p>
  <div class="tbl-wrap scrollable"><table><thead><tr><th style="width:200px">Source</th><th style="width:80px">Type</th><th>Entry / Command</th></tr></thead><tbody>{"".join(cron_rows_h)}</tbody></table></div>
</div>
</details>
<details>
<summary>{icon('file')} Critical Configuration Files <span class="caret">&#9658;</span></summary>
<div class="det-body">
  <p class="sec-desc">Key system configuration files control authentication, access policies, and security behaviour. Their presence, permissions, and content are audited here. Files with incorrect permissions or unexpected content may indicate misconfiguration or tampering. Comments are stripped from the preview for readability.</p>
  <div class="tbl-wrap scrollable"><table><thead><tr><th style="width:180px">Path</th><th style="width:65px">Present</th><th style="width:70px">Mode</th><th style="width:130px">Owner:Group</th><th style="width:80px">Size</th><th>Content Preview</th></tr></thead><tbody>{"".join(imp_file_rows_h)}</tbody></table></div>
</div>
</details>
</div>""")
    _h.append(f"""
<div id="panel-lynis" class="panel">

{score_full_html}

<div class="card-grid" style="margin-bottom:14px">
  <div class="card"><div class="card-title">{icon('check',13)} Test Results</div><div class="kv-list">
    <div class="kv-row"><span class="kv-key">Passed</span><span class="kv-val text-ok">{sc.get('passed',0)}</span></div>
    <div class="kv-row"><span class="kv-key">Suggestions</span><span class="kv-val text-warn">{sc.get('suggestion',0)}</span></div>
    <div class="kv-row"><span class="kv-key">Warnings</span><span class="kv-val text-danger">{sc.get('warning',0)}</span></div>
    <div class="kv-row"><span class="kv-key">Manual review</span><span class="kv-val">{sc.get('manual',0)}</span></div>
    <div class="kv-row"><span class="kv-key">Skipped</span><span class="kv-val muted">{sc.get('skipped',0)}</span></div>
    <div class="kv-row" style="border:none"><span class="kv-key">Total checks</span><span class="kv-val">{total_chk}</span></div>
  </div></div>
  <div class="card"><div class="card-title">{icon('alert',13)} Priority Distribution</div><div class="kv-list">
    <div class="kv-row"><span class="kv-key">{badge('P1','red')} Critical</span><span class="kv-val text-danger">{pc.get('P1',0)}</span></div>
    <div class="kv-row"><span class="kv-key">{badge('P2','orange')} Important</span><span class="kv-val text-warn">{pc.get('P2',0)}</span></div>
    <div class="kv-row"><span class="kv-key">{badge('P3','blue')} Low</span><span class="kv-val">{pc.get('P3',0)}</span></div>
  </div></div>
  <div class="card"><div class="card-title">{icon('info',13)} Scan Info</div><div class="kv-list">
    <div class="kv-row"><span class="kv-key">Lynis version</span><span class="kv-val mono">{esc(lynis_ver)}</span></div>
    <div class="kv-row"><span class="kv-key">Scan started</span><span class="kv-val mono">{esc(scan_start)}</span></div>
    <div class="kv-row"><span class="kv-key">Scan ended</span><span class="kv-val mono">{esc(scan_end)}</span></div>
    <div class="kv-row" style="border:none"><span class="kv-key">Report file</span><span class="kv-val mono small">{esc(str(lynis_path))}</span></div>
  </div></div>
</div>
<div class="section"><div class="section-hdr"><div><div class="section-title">{icon('alert')} Priority Action Plan</div><div class="section-sub">Top findings sorted by priority &mdash; requiring attention</div></div></div>
<div class="tbl-wrap scrollable"><table><thead><tr><th style="width:70px">Priority</th><th style="width:110px">Test ID</th><th style="width:100px">Type</th><th>Finding</th><th>Recommended Action</th></tr></thead>
<tbody>{"".join(top_rows)}</tbody></table></div></div>
<div class="section" style="margin-top:14px"><div class="section-hdr"><div class="section-title">{icon('alert')} Key Warnings ({len(warnings)})</div></div>
<div class="tbl-wrap"><table><thead><tr><th style="width:120px">Test ID</th><th>Warning Message</th></tr></thead>
<tbody>{"".join(warn_rows)}</tbody></table></div></div>
<div class="section" style="margin-top:14px"><div class="section-hdr"><div><div class="section-title">{icon('check')} All Test Results</div><div class="section-sub">Filter by status or priority &mdash; search by test ID or keyword</div></div></div>
<div class="filter-bar">
  <div id="sf" style="display:flex;gap:6px;flex-wrap:wrap">
    <button class="filter-btn active" data-filter="all">All</button><button class="filter-btn" data-filter="warning">Warning</button>
    <button class="filter-btn" data-filter="suggestion">Suggestion</button><button class="filter-btn" data-filter="manual">Manual</button>
    <button class="filter-btn" data-filter="passed">Passed</button><button class="filter-btn" data-filter="skipped">Skipped</button>
  </div>
  <div id="pf" style="display:flex;gap:6px;flex-wrap:wrap">
    <button class="filter-btn active" data-prio="all">All Priorities</button>
    <button class="filter-btn" data-prio="P1">P1</button><button class="filter-btn" data-prio="P2">P2</button><button class="filter-btn" data-prio="P3">P3</button>
  </div>
  <span class="spacer"></span><input class="search-input" id="test-search" placeholder="Search test ID or keyword..." type="search"/>
</div>
<div class="tbl-wrap scrollable"><table id="tests-tbl"><thead><tr>
  <th style="width:110px">Test ID</th><th style="width:100px">Status</th><th style="width:70px">Priority</th>
  <th>Finding</th><th>Recommendation</th><th style="width:120px">Component</th><th>Details</th>
</tr></thead><tbody>{"".join(test_rows)}</tbody></table></div></div>
<details style="margin-top:14px"><summary>{icon('info')} Recommendations ({len(suggestions)}) <span class="caret">&#9658;</span></summary>
<div class="det-body" style="padding:0"><div class="tbl-wrap scrollable"><table><thead><tr><th style="width:120px">Test ID</th><th>Finding</th><th>Recommendation</th></tr></thead>
<tbody>{"".join(rec_rows)}</tbody></table></div></div></details>
<details style="margin-top:12px"><summary>{icon('check')} Manual Verification Tasks ({len(manual_lst)}) <span class="caret">&#9658;</span></summary>
<div class="det-body"><ul style="padding-left:20px;line-height:2.2">{"".join(manual_rows)}</ul></div></details>
<details style="margin-top:12px"><summary>{icon('info')} Skipped Tests ({sc.get('skipped',0)}) <span class="caret">&#9658;</span></summary>
<div class="det-body" style="padding:0"><div class="tbl-wrap scrollable"><table><thead><tr><th style="width:110px">Test ID</th><th style="width:80px">Family</th><th>Reason</th></tr></thead>
<tbody>{"".join(skipped_rows)}</tbody></table></div></div></details>
</div>
</div>

<footer class="report-footer">
  <div>
    <span class="footer-brand">{icon('shield',13)} Security Hardening Report</span>
    {(f'&mdash; <strong>{esc(client_name)}</strong>') if client_name else ''}
    &nbsp;&middot;&nbsp; Generated {esc(generated_at)}
    {(f'&nbsp;&middot;&nbsp; {esc(created_by)}') if created_by else ''}
  </div>
  {(f'<div class="footer-disclaimer">{icon("alert",12)} {esc(disclaimer)}</div>') if disclaimer else ''}
</footer>

<script>{_JS}</script></body></html>""")
    return "".join(_h)

# ── main ──────────────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Security Hardening Report Generator — collects system data, runs Lynis, generates HTML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--output",      "-o", type=Path, default=None,
                        help="Output HTML path (default: results/report_<host>_<date>.html)")
    parser.add_argument("--logo",        type=Path, default=None,
                        help="Path to a PNG logo to embed in the report (overrides report.conf)")
    parser.add_argument("--report",      "-r", type=Path, default=None,
                        help="Existing Lynis .dat report file (skips Lynis run)")
    parser.add_argument("--log-file",    type=Path, default=None,
                        help="Existing Lynis log file for richer skip reasons")
    parser.add_argument("--report-only", action="store_true",
                        help="Only generate the HTML from an existing report, no scans")
    parser.add_argument("--config",      "-c", type=Path, default=None,
                        help="Path to report.conf config file (default: ./report.conf)")
    args = parser.parse_args()

    default_report, default_log, default_html = default_paths()
    output_path = args.output or default_html
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lynis_report_path = args.report or default_report
    lynis_log_path    = args.log_file or default_log

    if args.report_only:
        if not lynis_report_path.exists():
            print(f"[ERROR] Report file not found: {lynis_report_path}", file=sys.stderr)
            return 1
        print(f"[INFO] Report-only mode, using {lynis_report_path}")
    else:
        try:
            install_lynis()
        except Exception as e:
            print(f"[WARN] Could not install Lynis: {e}", file=sys.stderr)
        try:
            run_lynis(lynis_report_path, lynis_log_path)
        except Exception as e:
            print(f"[WARN] Lynis scan failed: {e}", file=sys.stderr)
            if not lynis_report_path.exists():
                print("[ERROR] No Lynis report available. Exiting.", file=sys.stderr)
                return 1

    sys_data = collect_all()

    cfg = load_config(args.config)
    lynis = parse_lynis_report(lynis_report_path)

    # --logo arg overrides report.conf logo
    logo_uri = ""
    logo_src = str(args.logo) if args.logo else cfg.get("logo", "").strip()
    if logo_src:
        try:
            logo_uri = build_logo_uri(logo_src)
        except Exception as e:
            print(f"[WARN] Could not load logo: {e}", file=sys.stderr)

    print("[INFO] Generating HTML report...")
    html = render_html(
        sys_data=sys_data,
        lynis=lynis,
        lynis_path=lynis_report_path,
        log_path=lynis_log_path if lynis_log_path.exists() else None,
        logo_uri=logo_uri,
        cfg=cfg,
    )
    output_path.write_text(html, encoding="utf-8")
    print(f"[DONE] Report saved to: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
