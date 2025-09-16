# NetVuln Scanner - Professional Network Vulnerability Assessment Tool

## Overview
NetVuln Scanner is a professional network security assessment tool with a stunning lemon green and black cybersecurity aesthetic. The application provides comprehensive vulnerability scanning capabilities including network discovery, port scanning, service detection, and vulnerability assessment.

## Features
- **Modern Aesthetic Design**: Custom lemon green (#9ACD32) and black color scheme with glowing effects
- **Comprehensive Scanning**: 18+ attack vector detection including SQL Injection, XSS, CSRF, DoS/DDoS
- **Real-time Visualization**: Interactive charts and live progress tracking
- **Professional Reports**: Export results in JSON and CSV formats
- **CVE Integration**: Automatic vulnerability lookup with National Vulnerability Database
- **Intuitive Interface**: Streamlit-based web interface with dark cybersecurity theme

## Attack Vectors Detected
- SQL Injection (SQLi)
- Command Injection
- LDAP Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Credential Stuffing
- Session Hijacking
- Brute-Force Attacks
- Denial of Service (DoS/DDoS)
- Local/Remote File Inclusion (LFI/RFI)
- Directory Traversal
- Malware Upload
- Man-in-the-Middle (MitM)
- Business Logic Attacks
- DNS/ARP Spoofing

## Installation

### Prerequisites
- Python 3.8 or higher
- Nmap installed on your system

### Setup
1. Extract the package files
2. Install dependencies:
   ```bash
   pip install streamlit pandas plotly python-nmap requests
   ```

3. Run the application:
   ```bash
   streamlit run app.py --server.port 5000
   ```

## Usage
1. Open your browser to `http://127.0.0.1:5000`
2. Configure scan parameters in the sidebar
3. Enter target IP addresses or ranges
4. Click "Start Vulnerability Scan" 
5. View real-time results and export reports

## File Structure
```
├── app.py                     # Main Streamlit application
├── scanner/
│   ├── network_scanner.py     # Network scanning functionality
│   ├── vulnerability_checker.py # Vulnerability detection
│   └── cve_lookup.py         # CVE database integration
├── utils/
│   ├── helpers.py            # Utility functions
│   └── report_generator.py   # Report generation
└── .streamlit/
    └── config.toml           # Streamlit configuration
```

## Security Notice
This tool is designed for authorized security testing only. Use responsibly and only on networks you own or have explicit permission to test.

## License
For educational and authorized security testing purposes only.

## Programmer
Mike-Aghoghovwia Ogheneyoma Favour 

## IPaddress checker

https://dnschecker.org