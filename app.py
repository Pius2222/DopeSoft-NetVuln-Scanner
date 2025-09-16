# app.py
"""
DopeSoft NetVuln Scanner - Streamlit-safe single-file app
- No heavy work runs at import time.
- Scanning runs only when the user clicks the Start Scan button.
- Uses pure-Python socket-based port scanning (no external nmap dependency).
- Uses ThreadPoolExecutor to scan ports concurrently (adjustable threads).
- Produces a DataFrame, simple charts, and CSV download.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import ipaddress
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
import time
import csv
import io

# ----------------------
# Page configuration
# ----------------------
st.set_page_config(page_title="DopeSoft NetVuln Scanner", layout="wide")
st.title("🛡️ DopeSoft NetVuln Scanner")
st.markdown(
    "A lightweight, Streamlit-friendly network port scanner. "
    "Scans only run when you press **Start Scan**."
)

# ----------------------
# Session state
# ----------------------
if "scan_results" not in st.session_state:
    st.session_state.scan_results = []
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

# ----------------------
# Utilities
# ----------------------
def validate_target_input(text: str) -> bool:
    """Return True if the input is a valid IPv4/IPv6 address, range or CIDR."""
    text = text.strip()
    if not text:
        return False
    # single IP
    try:
        ipaddress.ip_address(text)
        return True
    except Exception:
        pass
    # CIDR
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except Exception:
        pass
    # dash range like 192.168.1.1-10
    if "-" in text:
        try:
            base, rng = text.split("-", 1)
            # ensure base is IP and rng is int or ip
            ipaddress.ip_address(base)
            return True
        except Exception:
            return False
    # comma separated list: validate each
    if "," in text:
        parts = [p.strip() for p in text.split(",") if p.strip()]
        return all(validate_target_input(p) for p in parts)
    return False

def parse_target_input(text: str) -> List[str]:
    """
    Parse user input into a list of individual IP strings.
    Supports:
      - single IP
      - comma separated
      - CIDR (192.168.1.0/24)
      - range (192.168.1.1-10) -> expands last octet range
    """
    text = text.strip()
    targets = []
    if "," in text:
        for piece in text.split(","):
            targets.extend(parse_target_input(piece.strip()))
        return targets

    # CIDR
    try:
        net = ipaddress.ip_network(text, strict=False)
        return [str(ip) for ip in net.hosts()]
    except Exception:
        pass

    # dash range (simple heuristic: last octet range)
    if "-" in text:
        try:
            base, rng = text.split("-", 1)
            base = base.strip()
            start_ip = ipaddress.ip_address(base)
            # if rng is a single integer, apply to last octet
            if "." in rng:
                end_ip = ipaddress.ip_address(rng.strip())
                # produce range start_ip..end_ip inclusive (careful)
                start_int = int(start_ip)
                end_int = int(end_ip)
                return [str(ipaddress.ip_address(i)) for i in range(start_int, end_int + 1)]
            else:
                # assume last octet range
                base_parts = base.split(".")
                if len(base_parts) == 4:
                    start_octet = int(base_parts[-1])
                    end_octet = int(rng)
                    prefix = ".".join(base_parts[:3])
                    return [f"{prefix}.{i}" for i in range(start_octet, end_octet + 1)]
        except Exception:
            pass

    # single ip
    return [text]

def parse_ports(port_string: str) -> List[int]:
    """
    Parse port input like:
      - "80,443,22"
      - "1-100"
      - "80" -> [80]
      - None or empty -> default common ports
    Returns sorted unique ports.
    """
    if not port_string or str(port_string).strip() == "":
        # default common ports
        default = [21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080]
        return sorted(set(default))
    port_string = port_string.strip()
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a,b = part.split("-",1)
                a = int(a); b = int(b)
                for p in range(a, b+1):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except Exception:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except Exception:
                continue
    return sorted(ports)

def scan_port(target: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """Attempt a TCP connect to detect open port. Returns a dict with result."""
    result = {"host": target, "port": port, "state": "closed", "protocol": "tcp"}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            rc = s.connect_ex((target, port))
            if rc == 0:
                result["state"] = "open"
            else:
                result["state"] = "closed"
    except Exception:
        result["state"] = "error"
    return result

def scan_host_ports(target: str, ports: List[int], timeout: float, threads: int, progress_callback=None) -> List[Dict[str, Any]]:
    """
    Scan a single host's ports using ThreadPoolExecutor.
    progress_callback should accept (scanned_count, total).
    """
    results = []
    total = len(ports)
    scanned = 0
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        future_to_port = {ex.submit(scan_port, target, p, timeout): p for p in ports}
        for future in as_completed(future_to_port):
            p = future_to_port[future]
            try:
                res = future.result()
            except Exception as e:
                res = {"host": target, "port": p, "state": "error", "protocol": "tcp", "error": str(e)}
            results.append(res)
            scanned += 1
            if progress_callback:
                progress_callback(scanned, total)
    # keep consistent ordering by port
    return sorted(results, key=lambda x: x["port"])

# ----------------------
# UI controls (sidebar)
# ----------------------
with st.sidebar:
    st.header("⚙️ Scan Configuration")
    target_input = st.text_input("Target(s)", placeholder="192.168.1.1, 192.168.1.0/24, 192.168.1.1-10")
    scan_type = st.selectbox("Scan Type", ["Quick Scan (Top ports)", "Common Ports", "Full Scan (1-1024)", "Custom Ports"])
    custom_ports = None
    if scan_type == "Custom Ports":
        custom_ports = st.text_input("Custom Ports (e.g. 80,443,1-1024)")
    aggressive = st.checkbox("🎯 Aggressive (service detection - best-effort)", value=False)
    timeout = st.slider("⏱️ Timeout (seconds per port)", min_value=0.5, max_value=10.0, value=1.0, step=0.5)
    threads = st.slider("🧵 Threads", min_value=1, max_value=200, value=50, step=1)
    enable_cve = st.checkbox("🔍 CVE Lookup (disabled in cloud unless implemented)", value=False)
    scan_button = st.button("🚀 Start Scan")

# ----------------------
# Scanning orchestration
# ----------------------
def run_scan_button_handler():
    if not target_input or not validate_target_input(target_input):
        st.error("Please enter a valid target (single IP, CIDR, range or comma-separated list).")
        return

    # parse targets and ports
    targets = parse_target_input(target_input)
    if scan_type == "Quick Scan (Top ports)":
        ports = [22,80,443,8080,3306,3389]  # a small quick set
    elif scan_type == "Common Ports":
        ports = parse_ports("")  # default set in parse_ports
    elif scan_type == "Full Scan (1-1024)":
        ports = list(range(1, 1025))
    else:
        ports = parse_ports(custom_ports)

    total_work = len(targets) * len(ports)
    progress_bar = st.progress(0.0)
    status_text = st.empty()
    start_all = time.time()

    aggregated_results = []
    work_done = 0

    for target in targets:
        status_text.markdown(f"🔍 Scanning **{target}** — {len(ports)} ports")
        # progress callback updates host-level progress (we'll update global below)
        def progress_cb(scanned, total):
            nonlocal work_done
            # scanned is per-host; we compute fraction of global work done
            current = work_done + scanned
            progress_bar.progress(min(current / total_work, 1.0))

        host_results = scan_host_ports(target, ports, timeout, threads, progress_callback=progress_cb)
        aggregated_results.extend(host_results)
        work_done += len(ports)

    elapsed = time.time() - start_all
    progress_bar.progress(1.0)
    status_text.markdown(f"✅ Scan completed in {elapsed:.2f} seconds. Scanned {len(targets)} target(s).")

    # Collapse results per-host to a structured dict list
    structured = []
    by_host = {}
    for r in aggregated_results:
        host = r["host"]
        by_host.setdefault(host, []).append(r)
    for host, port_entries in by_host.items():
        open_ports = [e["port"] for e in port_entries if e["state"] == "open"]
        structured.append({
            "host": host,
            "status": "up" if open_ports else "up" ,  # we keep 'up' for any scanned host
            "open_ports": open_ports,
            "services": [],  # placeholder (service detection not implemented)
            "vulnerabilities": [],  # placeholder
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    # store in session
    st.session_state.scan_results = structured
    st.session_state.scan_history.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "targets": target_input,
        "results_count": len(structured)
    })

# Trigger scan only when button is clicked
if scan_button:
    run_scan_button_handler()

# ----------------------
# Display results if available
# ----------------------
def display_results(results):
    if not results:
        st.info("No scan results available yet.")
        return

    total_hosts = len(results)
    hosts_up = len([r for r in results if r["status"] == "up"])
    total_open_ports = sum(len(r["open_ports"]) for r in results)
    total_vulns = sum(len(r["vulnerabilities"]) for r in results)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Hosts Scanned", total_hosts)
    col2.metric("Hosts Up", hosts_up)
    col3.metric("Open Ports", total_open_ports)
    col4.metric("Vulnerabilities", total_vulns)

    tab1, tab2, tab3 = st.tabs(["🖥️ Hosts", "🔓 Open Ports", "📋 Raw Data"])

    with tab1:
        hosts_rows = []
        for r in results:
            hosts_rows.append({
                "Host": r["host"],
                "Status": r["status"],
                "Open Ports": len(r["open_ports"]),
                "Vulnerabilities": len(r["vulnerabilities"]),
                "Scan Time": r["scan_time"]
            })
        df_hosts = pd.DataFrame(hosts_rows)
        st.dataframe(df_hosts, use_container_width=True)

    with tab2:
        port_records = []
        for r in results:
            for p in r["open_ports"]:
                port_records.append({"Host": r["host"], "Port": p})
        if port_records:
            df_ports = pd.DataFrame(port_records)
            st.dataframe(df_ports, use_container_width=True)

            # simple chart: top ports
            port_counts = df_ports["Port"].value_counts().head(10)
            fig = px.bar(x=port_counts.index.astype(str), y=port_counts.values,
                         labels={"x": "Port", "y": "Count"}, title="Top Open Ports")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No open ports detected.")

    with tab3:
        st.json(results)

    # Export options
    st.subheader("📥 Export Results")
    csv_io = io.StringIO()
    writer = csv.writer(csv_io)
    writer.writerow(["host", "status", "open_ports", "scan_time"])
    for r in results:
        writer.writerow([r["host"], r["status"], ";".join(map(str, r["open_ports"])), r["scan_time"]])
    csv_bytes = csv_io.getvalue().encode("utf-8")

    st.download_button("⬇️ Download CSV", csv_bytes, file_name=f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")

# Show results if we have them
if st.session_state.scan_results:
    st.markdown("---")
    st.header("Scan Results")
    display_results(st.session_state.scan_results)

# ----------------------
# Sidebar: History
# ----------------------
with st.sidebar:
    st.markdown("---")
    st.subheader("📚 Scan History")
    history = st.session_state.scan_history
    if not history:
        st.info("No previous scans")
    else:
        for i, h in enumerate(reversed(history[-10:]), 1):
            st.markdown(f"**{h['timestamp']}** — `{h['targets']}` — {h['results_count']} hosts")

# ----------------------
# Helpful note
# ----------------------
st.markdown(
    "<small>Note: This scanner uses simple TCP connect checks and is intended for small, ethical scans in "
    "trusted environments. Do not scan networks you don't have permission to test.</small>",
    unsafe_allow_html=True
)
