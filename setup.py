#!/usr/bin/env python3
"""
NetVuln Scanner Setup Script
Professional Network Vulnerability Assessment Tool
"""

import subprocess
import sys
import os

def install_requirements():
    """Install required Python packages"""
    print("Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ Python dependencies installed successfully")
    except subprocess.CalledProcessError:
        print("✗ Failed to install Python dependencies")
        return False
    return True

def check_nmap():
    """Check if nmap is installed"""
    try:
        subprocess.check_output(["nmap", "--version"], stderr=subprocess.STDOUT)
        print("✓ Nmap is installed")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("✗ Nmap not found. Please install nmap:")
        print("  Ubuntu/Debian: sudo apt-get install nmap")
        print("  CentOS/RHEL: sudo yum install nmap")
        print("  macOS: brew install nmap")
        print("  Windows: Download from https://nmap.org/download.html")
        return False

def main():
    """Main setup function"""
    print("NetVuln Scanner Setup")
    print("=" * 30)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("✗ Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✓ Python {sys.version.split()[0]} detected")
    
    # Install requirements
    if not install_requirements():
        sys.exit(1)
    
    # Check nmap
    if not check_nmap():
        print("\nWarning: Nmap is required for network scanning functionality")
    
    print("\n" + "=" * 30)
    print("Setup complete! To run the scanner:")
    print("streamlit run app.py --server.port 5000")
    print("\nThen open http://localhost:5000 in your browser")

if __name__ == "__main__":
    main()