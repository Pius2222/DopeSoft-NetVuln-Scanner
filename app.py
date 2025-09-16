import streamlit as st
import asyncio
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import ipaddress
import time

from scanner.network_scanner import NetworkScanner
from scanner.vulnerability_checker import VulnerabilityChecker
from scanner.cve_lookup import CVELookup
from utils.report_generator import ReportGenerator
from utils.helpers import validate_target, parse_target_input

# Page configuration
st.set_page_config(
    page_title="🛡️ NetVuln Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for lemon green and black aesthetic
st.markdown("""
<style>
    /* Main background and text colors */
    .stApp {
        background: linear-gradient(135deg, #0D0D0D 0%, #1A1A1A 100%);
        color: #E6FFE6;
    }
    
    /* Header styling */
    h1, h2, h3 {
        color: #9ACD32 !important;
        text-shadow: 0 0 10px rgba(154, 205, 50, 0.3);
        font-weight: bold;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #0D0D0D 0%, #1A1A1A 100%);
        border-right: 2px solid #9ACD32;
    }
    
    /* Button styling */
    .stButton > button {
        background: linear-gradient(45deg, #9ACD32, #7CCD7C);
        color: #0D0D0D;
        border: none;
        border-radius: 10px;
        font-weight: bold;
        box-shadow: 0 4px 15px rgba(154, 205, 50, 0.4);
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        background: linear-gradient(45deg, #7CCD7C, #9ACD32);
        box-shadow: 0 6px 20px rgba(154, 205, 50, 0.6);
        transform: translateY(-2px);
    }
    
    /* Input field styling */
    .stTextInput > div > div > input {
        background-color: #1A1A1A;
        border: 2px solid #9ACD32;
        border-radius: 8px;
        color: #E6FFE6;
    }
    
    .stSelectbox > div > div > select {
        background-color: #1A1A1A;
        border: 2px solid #9ACD32;
        border-radius: 8px;
        color: #E6FFE6;
    }
    
    /* Metric cards styling */
    [data-testid="metric-container"] {
        background: linear-gradient(135deg, #1A1A1A 0%, #262626 100%);
        border: 2px solid #9ACD32;
        border-radius: 12px;
        padding: 1rem;
        box-shadow: 0 4px 15px rgba(154, 205, 50, 0.2);
    }
    
    [data-testid="metric-container"] > div {
        color: #E6FFE6;
    }
    
    [data-testid="metric-container"] [data-testid="metric-value"] {
        color: #9ACD32 !important;
        font-size: 2rem !important;
        font-weight: bold;
        text-shadow: 0 0 8px rgba(154, 205, 50, 0.5);
    }
    
    /* Progress bar styling */
    .stProgress .st-bo {
        background-color: #1A1A1A;
    }
    
    .stProgress .st-bp {
        background: linear-gradient(90deg, #9ACD32, #7CCD7C);
        box-shadow: 0 0 10px rgba(154, 205, 50, 0.5);
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #1A1A1A;
        border-radius: 10px;
        border: 2px solid #9ACD32;
    }
    
    .stTabs [data-baseweb="tab"] {
        color: #E6FFE6;
        background-color: transparent;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(45deg, #9ACD32, #7CCD7C);
        color: #0D0D0D !important;
        font-weight: bold;
    }
    
    /* Table styling */
    .stDataFrame {
        background-color: #1A1A1A;
        border: 2px solid #9ACD32;
        border-radius: 10px;
        overflow: hidden;
    }
    
    /* Alert styling */
    .stAlert {
        background-color: #1A1A1A;
        border-left: 4px solid #9ACD32;
        color: #E6FFE6;
    }
    
    /* Sidebar header */
    .css-1lcbmhc {
        background: linear-gradient(45deg, #9ACD32, #7CCD7C);
        color: #0D0D0D;
        font-weight: bold;
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        box-shadow: 0 4px 15px rgba(154, 205, 50, 0.3);
    }
    
    /* Scanner title glow effect */
    .scanner-title {
        background: linear-gradient(45deg, #9ACD32, #7CCD7C);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        margin: 2rem 0;
        filter: drop-shadow(0 0 20px rgba(154, 205, 50, 0.5));
    }
    
    /* Vulnerability severity badges */
    .vuln-critical {
        background: linear-gradient(45deg, #FF0000, #8B0000);
        color: white;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        font-weight: bold;
        box-shadow: 0 2px 8px rgba(255, 0, 0, 0.3);
    }
    
    .vuln-high {
        background: linear-gradient(45deg, #FF8C00, #FF4500);
        color: white;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        font-weight: bold;
        box-shadow: 0 2px 8px rgba(255, 140, 0, 0.3);
    }
    
    .vuln-medium {
        background: linear-gradient(45deg, #FFD700, #FFA500);
        color: #0D0D0D;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        font-weight: bold;
        box-shadow: 0 2px 8px rgba(255, 215, 0, 0.3);
    }
    
    .vuln-low {
        background: linear-gradient(45deg, #9ACD32, #7CCD7C);
        color: #0D0D0D;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        font-weight: bold;
        box-shadow: 0 2px 8px rgba(154, 205, 50, 0.3);
    }
    
    /* Animated scanning indicator */
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    
    .scanning-indicator {
        animation: pulse 2s infinite;
        color: #9ACD32;
        font-weight: bold;
    }
    
    /* Card containers */
    .scan-card {
        background: linear-gradient(135deg, #1A1A1A 0%, #262626 100%);
        border: 2px solid #9ACD32;
        border-radius: 15px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 8px 25px rgba(154, 205, 50, 0.2);
    }
    
    /* Success messages */
    .success-message {
        background: linear-gradient(45deg, #9ACD32, #7CCD7C);
        color: #0D0D0D;
        padding: 1rem;
        border-radius: 10px;
        font-weight: bold;
        box-shadow: 0 4px 15px rgba(154, 205, 50, 0.3);
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = []
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []
if 'current_scan' not in st.session_state:
    st.session_state.current_scan = None

def main():
    # Enhanced Header with lemon green aesthetic
    st.markdown('<h1 class="scanner-title">🛡️ NetVuln Scanner</h1>', unsafe_allow_html=True)
    st.markdown("""
    <div class="scan-card">
        <h3 style="text-align: center; margin: 0;">⚡ Professional Network Security Assessment Tool ⚡</h3>
        <p style="text-align: center; color: #9ACD32; margin: 0.5rem 0;">
            Advanced vulnerability detection with 18+ attack vector analysis by Favour Mike
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar configuration
    with st.sidebar:
        st.markdown("""
        <div style="background: linear-gradient(45deg, #9ACD32, #7CCD7C); 
                    color: #0D0D0D; padding: 1rem; border-radius: 10px; 
                    text-align: center; margin-bottom: 1rem;
                    box-shadow: 0 4px 15px rgba(154, 205, 50, 0.3);">
            <h3 style="margin: 0; color: #0D0D0D;">⚙️ Scan Configuration</h3>
        </div>
        """, unsafe_allow_html=True)
        
        # Target input
        target_input = st.text_input(
            "Target(s)",
            placeholder="192.168.1.1, 192.168.1.1-10, or 192.168.1.0/24",
            help="Enter single IP, IP range, or subnet (CIDR notation)"
        )
        
        # Port selection
        scan_type = st.selectbox(
            "Scan Type",
            ["Quick Scan (Top 100 ports)", "Common Ports", "Full Scan", "Custom Ports"]
        )
        
        if scan_type == "Custom Ports":
            custom_ports = st.text_input(
                "Custom Ports",
                placeholder="80,443,22,21",
                help="Comma-separated port numbers"
            )
        else:
            custom_ports = None
        
        # Scan options
        st.markdown("""
        <div style="background: linear-gradient(135deg, #1A1A1A 0%, #262626 100%); 
                    border: 2px solid #9ACD32; border-radius: 10px; 
                    padding: 1rem; margin: 1rem 0;">
            <h4 style="color: #9ACD32; margin-top: 0;">🔧 Advanced Options</h4>
        </div>
        """, unsafe_allow_html=True)
        
        aggressive_scan = st.checkbox("🎯 Aggressive Scan", help="Enable OS detection and version scanning")
        timeout = st.slider("⏱️ Timeout (seconds)", 1, 30, 10)
        threads = st.slider("🧵 Threads", 1, 50, 10)
        
        # CVE lookup
        enable_cve = st.checkbox("🔍 CVE Vulnerability Lookup", value=True)
        
        # Scan button
        scan_button = st.button("🚀 Start Scan", type="primary", use_container_width=True)
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Scan execution
        if scan_button and target_input:
            if validate_target(target_input):
                targets = parse_target_input(target_input)
                
                # Initialize scanners
                network_scanner = NetworkScanner(timeout=timeout, threads=threads)
                vuln_checker = VulnerabilityChecker()
                cve_lookup = CVELookup() if enable_cve else None
                
                # Configure ports
                if scan_type == "Quick Scan (Top 100 ports)":
                    ports = "1-100"
                elif scan_type == "Common Ports":
                    ports = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080"
                elif scan_type == "Full Scan":
                    ports = "1-65535"
                else:
                    ports = custom_ports if custom_ports else "80,443,22"
                
                # Progress tracking with enhanced styling
                st.markdown("""
                <div class="scan-card">
                    <h4 style="color: #9ACD32; text-align: center; margin: 0;">
                        🚀 Scanning in Progress...
                    </h4>
                </div>
                """, unsafe_allow_html=True)
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                scan_results_container = st.empty()
                
                # Run scan
                try:
                    scan_results = run_scan(
                        targets, ports, network_scanner, vuln_checker, cve_lookup,
                        aggressive_scan, progress_bar, status_text
                    )
                    
                    if scan_results:
                        st.session_state.scan_results = scan_results
                        st.session_state.scan_history.append({
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'targets': target_input,
                            'results_count': len(scan_results)
                        })
                        
                        display_scan_results(scan_results)
                    else:
                        st.warning("No hosts discovered or scan completed with no results.")
                        
                except Exception as e:
                    st.error(f"Scan failed: {str(e)}")
                    
            else:
                st.error("Invalid target format. Please check your input.")
        
        elif scan_button:
            st.error("Please enter a target to scan.")
        
        # Display previous results if available
        elif st.session_state.scan_results:
            st.subheader("📊 Latest Scan Results")
            display_scan_results(st.session_state.scan_results)
    
    with col2:
        # Scan statistics
        if st.session_state.scan_results:
            display_scan_statistics(st.session_state.scan_results)
        
        # Scan history
        display_scan_history()

def run_scan(targets, ports, network_scanner, vuln_checker, cve_lookup, aggressive, progress_bar, status_text):
    """Execute the network scan with progress tracking"""
    all_results = []
    total_targets = len(targets)
    
    for i, target in enumerate(targets):
        # Update progress with enhanced styling
        progress = (i + 1) / total_targets
        progress_bar.progress(progress)
        status_text.markdown(f"""
        <div class="scanning-indicator" style="text-align: center; font-size: 1.2rem;">
            🔍 Scanning {target}... ({i+1}/{total_targets})
        </div>
        """, unsafe_allow_html=True)
        
        try:
            # Host discovery
            if network_scanner.is_host_alive(target):
                # Port scan
                open_ports = network_scanner.scan_ports(target, ports)
                
                if open_ports:
                    host_result = {
                        'host': target,
                        'status': 'up',
                        'open_ports': open_ports,
                        'services': [],
                        'vulnerabilities': [],
                        'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    # Service detection
                    for port in open_ports:
                        service_info = network_scanner.detect_service(target, port, aggressive)
                        host_result['services'].append(service_info)
                        
                        # Vulnerability checking
                        vulns = vuln_checker.check_service_vulnerabilities(service_info)
                        if vulns:
                            host_result['vulnerabilities'].extend(vulns)
                        
                        # CVE lookup
                        if cve_lookup and service_info.get('version'):
                            cves = cve_lookup.lookup_cves(service_info)
                            if cves:
                                host_result['vulnerabilities'].extend(cves)
                    
                    all_results.append(host_result)
                else:
                    # Host is up but no open ports
                    all_results.append({
                        'host': target,
                        'status': 'up',
                        'open_ports': [],
                        'services': [],
                        'vulnerabilities': [],
                        'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
            else:
                # Host is down
                all_results.append({
                    'host': target,
                    'status': 'down',
                    'open_ports': [],
                    'services': [],
                    'vulnerabilities': [],
                    'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
        
        except Exception as e:
            st.error(f"Error scanning {target}: {str(e)}")
            continue
    
    progress_bar.progress(1.0)
    status_text.markdown("""
    <div class="success-message" style="text-align: center;">
        ✅ Scan completed successfully!
    </div>
    """, unsafe_allow_html=True)
    
    return all_results

def display_scan_results(results):
    """Display scan results in organized format"""
    if not results:
        return
    
    # Summary metrics
    total_hosts = len(results)
    hosts_up = len([r for r in results if r['status'] == 'up'])
    total_ports = sum(len(r['open_ports']) for r in results)
    total_vulns = sum(len(r['vulnerabilities']) for r in results)
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Hosts Scanned", total_hosts)
    col2.metric("Hosts Up", hosts_up)
    col3.metric("Open Ports", total_ports)
    col4.metric("Vulnerabilities", total_vulns)
    
    # Results tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🖥️ Hosts", "🔓 Open Ports", "⚠️ Vulnerabilities", "📋 Raw Data"])
    
    with tab1:
        display_hosts_table(results)
    
    with tab2:
        display_ports_table(results)
    
    with tab3:
        display_vulnerabilities_table(results)
    
    with tab4:
        display_raw_data(results)
    
    # Export options
    st.subheader("📥 Export Results")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📄 Export as JSON"):
            json_data = json.dumps(results, indent=2)
            st.download_button(
                label="Download JSON",
                data=json_data,
                file_name=f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col2:
        if st.button("📊 Export as CSV"):
            csv_data = ReportGenerator.generate_csv_report(results)
            st.download_button(
                label="Download CSV",
                data=csv_data,
                file_name=f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

def display_hosts_table(results):
    """Display hosts information in table format"""
    hosts_data = []
    for result in results:
        hosts_data.append({
            'Host': result['host'],
            'Status': result['status'],
            'Open Ports': len(result['open_ports']),
            'Services': len(result['services']),
            'Vulnerabilities': len(result['vulnerabilities']),
            'Scan Time': result['scan_time']
        })
    
    if hosts_data:
        df = pd.DataFrame(hosts_data)
        st.dataframe(df, use_container_width=True)

def display_ports_table(results):
    """Display open ports information"""
    ports_data = []
    for result in results:
        for port in result['open_ports']:
            service = next((s for s in result['services'] if s['port'] == port), {})
            ports_data.append({
                'Host': result['host'],
                'Port': port,
                'Protocol': service.get('protocol', 'tcp'),
                'Service': service.get('service', 'unknown'),
                'Version': service.get('version', 'unknown'),
                'Banner': service.get('banner', '')[:50] + '...' if len(service.get('banner', '')) > 50 else service.get('banner', '')
            })
    
    if ports_data:
        df = pd.DataFrame(ports_data)
        st.dataframe(df, use_container_width=True)
        
        # Port distribution chart
        if len(ports_data) > 0:
            port_counts = df['Port'].value_counts().head(10)
            fig = px.bar(
                x=port_counts.index,
                y=port_counts.values,
                title="Top 10 Most Common Open Ports",
                labels={'x': 'Port', 'y': 'Count'},
                color_discrete_sequence=['#9ACD32']
            )
            # Update chart styling for dark theme
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(26,26,26,0.8)',
                font_color='#E6FFE6',
                title_font_color='#9ACD32',
                title_font_size=16
            )
            fig.update_traces(marker_color='#9ACD32')
            st.plotly_chart(fig, use_container_width=True)

def display_vulnerabilities_table(results):
    """Display vulnerabilities information"""
    vuln_data = []
    for result in results:
        for vuln in result['vulnerabilities']:
            vuln_data.append({
                'Host': result['host'],
                'Vulnerability': vuln.get('name', 'Unknown'),
                'Severity': vuln.get('severity', 'Unknown'),
                'CVE': vuln.get('cve', 'N/A'),
                'Description': vuln.get('description', '')[:100] + '...' if len(vuln.get('description', '')) > 100 else vuln.get('description', ''),
                'Port': vuln.get('port', 'N/A')
            })
    
    if vuln_data:
        df = pd.DataFrame(vuln_data)
        
        # Enhanced vulnerability display with custom styling
        for _, row in df.iterrows():
            severity = str(row['Severity']).lower()
            severity_class = f"vuln-{severity}"
            
            st.markdown(f"""
            <div class="scan-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong style="color: #9ACD32;">{row['Host']}</strong> - Port {row['Port']}
                        <br><span style="color: #E6FFE6;">{row['Vulnerability']}</span>
                    </div>
                    <span class="{severity_class}">{str(row['Severity']).upper()}</span>
                </div>
                <p style="color: #E6FFE6; margin: 0.5rem 0;">{row['Description']}</p>
                {f'<p style="color: #9ACD32; font-size: 0.9rem; margin: 0;"><strong>CVE:</strong> {row["CVE"]}</p>' if row['CVE'] != 'N/A' else ''}
            </div>
            """, unsafe_allow_html=True)
        
        # Vulnerability severity distribution
        severity_counts = df['Severity'].value_counts()
        if len(severity_counts) > 0:
            fig = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Vulnerability Severity Distribution",
                color_discrete_map={
                    'Critical': '#FF0000',
                    'High': '#FF8C00', 
                    'Medium': '#FFD700',
                    'Low': '#9ACD32'
                }
            )
            # Update chart styling for dark theme
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(26,26,26,0.8)',
                font_color='#E6FFE6',
                title_font_color='#9ACD32',
                title_font_size=16
            )
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No vulnerabilities detected in this scan.")

def display_raw_data(results):
    """Display raw scan data"""
    st.json(results)

def display_scan_statistics(results):
    """Display scan statistics in sidebar"""
    st.markdown("""
    <div style="background: linear-gradient(45deg, #9ACD32, #7CCD7C); 
                color: #0D0D0D; padding: 1rem; border-radius: 10px; 
                text-align: center; margin-bottom: 1rem;
                box-shadow: 0 4px 15px rgba(154, 205, 50, 0.3);">
        <h4 style="margin: 0; color: #0D0D0D;">📈 Scan Statistics</h4>
    </div>
    """, unsafe_allow_html=True)
    
    if not results:
        st.markdown("""
        <div class="scan-card">
            <p style="text-align: center; color: #9ACD32;">No scan data available</p>
        </div>
        """, unsafe_allow_html=True)
        return
    
    # Basic stats
    total_hosts = len(results)
    hosts_up = len([r for r in results if r['status'] == 'up'])
    uptime_percent = (hosts_up / total_hosts) * 100 if total_hosts > 0 else 0
    
    st.markdown(f"""
    <div class="scan-card">
        <div style="text-align: center;">
            <h3 style="color: #9ACD32; margin: 0; text-shadow: 0 0 8px rgba(154, 205, 50, 0.5);">
                {uptime_percent:.1f}%
            </h3>
            <p style="color: #E6FFE6; margin: 0;">Host Uptime</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Service distribution
    all_services = []
    for result in results:
        for service in result['services']:
            all_services.append(service.get('service', 'unknown'))
    
    if all_services:
        service_counts = pd.Series(all_services).value_counts().head(5)
        st.markdown("""
        <div class="scan-card">
            <h5 style="color: #9ACD32; margin-top: 0;">🔧 Top Services</h5>
        """, unsafe_allow_html=True)
        for service, count in service_counts.items():
            st.markdown(f"""
            <div style="display: flex; justify-content: space-between; margin: 0.3rem 0;">
                <span style="color: #E6FFE6;">• {service}</span>
                <span style="color: #9ACD32; font-weight: bold;">{count}</span>
            </div>
            """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    
    # Vulnerability levels
    all_vulns = []
    for result in results:
        for vuln in result['vulnerabilities']:
            all_vulns.append(vuln.get('severity', 'unknown'))
    
    if all_vulns:
        vuln_counts = pd.Series(all_vulns).value_counts()
        st.markdown("""
        <div class="scan-card">
            <h5 style="color: #9ACD32; margin-top: 0;">⚠️ Vulnerability Levels</h5>
        """, unsafe_allow_html=True)
        
        for level, count in vuln_counts.items():
            level_str = str(level).lower()
            emoji_color = {
                'critical': '🔴',
                'high': '🟠', 
                'medium': '🟡',
                'low': '🟢'
            }.get(level_str, '⚪')
            
            badge_class = f"vuln-{level_str}"
            st.markdown(f"""
            <div style="display: flex; justify-content: space-between; align-items: center; margin: 0.5rem 0;">
                <span style="color: #E6FFE6;">{emoji_color} {str(level).title()}</span>
                <span class="{badge_class}">{count}</span>
            </div>
            """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

def display_scan_history():
    """Display scan history in sidebar"""
    st.markdown("""
    <div style="background: linear-gradient(45deg, #9ACD32, #7CCD7C); 
                color: #0D0D0D; padding: 1rem; border-radius: 10px; 
                text-align: center; margin-bottom: 1rem;
                box-shadow: 0 4px 15px rgba(154, 205, 50, 0.3);">
        <h4 style="margin: 0; color: #0D0D0D;">📚 Scan History</h4>
    </div>
    """, unsafe_allow_html=True)
    
    if not st.session_state.scan_history:
        st.markdown("""
        <div class="scan-card">
            <p style="text-align: center; color: #9ACD32;">No previous scans</p>
        </div>
        """, unsafe_allow_html=True)
        return
    
    for i, scan in enumerate(reversed(st.session_state.scan_history[-5:])):  # Show last 5
        scan_number = len(st.session_state.scan_history) - i
        with st.expander(f"🔍 Scan #{scan_number}", expanded=False):
            st.markdown(f"""
            <div class="scan-card">
                <div style="color: #E6FFE6;">
                    <strong style="color: #9ACD32;">⏰ Time:</strong> {scan['timestamp']}<br>
                    <strong style="color: #9ACD32;">🎯 Targets:</strong> {scan['targets']}<br>
                    <strong style="color: #9ACD32;">📊 Results:</strong> {scan['results_count']} hosts
                </div>
            </div>
            """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
