import ipaddress
import re
from typing import List, Union
import logging

def validate_target(target: str) -> bool:
    """Validate if target input is in correct format"""
    try:
        targets = parse_target_input(target)
        return len(targets) > 0
    except:
        return False

def parse_target_input(target_input: str) -> List[str]:
    """Parse target input and return list of IP addresses"""
    targets = []
    
    # Split by comma and clean whitespace
    raw_targets = [t.strip() for t in target_input.split(',') if t.strip()]
    
    for target in raw_targets:
        try:
            if '-' in target and '/' not in target:
                # IP range (e.g., 192.168.1.1-10 or 192.168.1.1-192.168.1.10)
                targets.extend(parse_ip_range(target))
            elif '/' in target:
                # CIDR notation (e.g., 192.168.1.0/24)
                targets.extend(parse_cidr(target))
            else:
                # Single IP or hostname
                if validate_single_target(target):
                    targets.append(target)
        except Exception as e:
            logging.warning(f"Error parsing target {target}: {e}")
            continue
    
    return list(set(targets))  # Remove duplicates

def parse_ip_range(ip_range: str) -> List[str]:
    """Parse IP range like 192.168.1.1-10 or 192.168.1.1-192.168.1.10"""
    if '-' not in ip_range:
        return []
    
    start_ip, end_part = ip_range.split('-', 1)
    start_ip = start_ip.strip()
    end_part = end_part.strip()
    
    try:
        start_addr = ipaddress.IPv4Address(start_ip)
        
        if '.' in end_part:
            # Full IP address (e.g., 192.168.1.1-192.168.1.10)
            end_addr = ipaddress.IPv4Address(end_part)
        else:
            # Just the last octet (e.g., 192.168.1.1-10)
            start_octets = str(start_addr).split('.')
            start_octets[-1] = end_part
            end_addr = ipaddress.IPv4Address('.'.join(start_octets))
        
        if start_addr > end_addr:
            start_addr, end_addr = end_addr, start_addr
        
        # Limit range to prevent excessive scanning
        if int(end_addr) - int(start_addr) > 254:
            raise ValueError("IP range too large (max 254 addresses)")
        
        targets = []
        current = start_addr
        while current <= end_addr:
            targets.append(str(current))
            current += 1
        
        return targets
        
    except Exception as e:
        raise ValueError(f"Invalid IP range format: {ip_range}")

def parse_cidr(cidr: str) -> List[str]:
    """Parse CIDR notation like 192.168.1.0/24"""
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        
        # Limit network size to prevent excessive scanning
        if network.num_addresses > 256:
            raise ValueError("Network too large (max /24)")
        
        targets = []
        for ip in network.hosts():
            targets.append(str(ip))
        
        # If it's a /32, include the network address itself
        if network.num_addresses == 1:
            targets.append(str(network.network_address))
        
        return targets
        
    except Exception as e:
        raise ValueError(f"Invalid CIDR notation: {cidr}")

def validate_single_target(target: str) -> bool:
    """Validate single IP address or hostname"""
    try:
        # Try to parse as IP address
        ipaddress.IPv4Address(target)
        return True
    except:
        # Try to validate as hostname
        return validate_hostname(target)

def validate_hostname(hostname: str) -> bool:
    """Validate hostname format"""
    if not hostname or len(hostname) > 255:
        return False
    
    # Remove trailing dot
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    
    # Check each label
    labels = hostname.split('.')
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
            return False
    
    return True

def format_port_list(ports: List[int]) -> str:
    """Format list of ports into readable string with ranges"""
    if not ports:
        return ""
    
    ports = sorted(set(ports))
    ranges = []
    start = ports[0]
    end = start
    
    for port in ports[1:]:
        if port == end + 1:
            end = port
        else:
            if start == end:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{end}")
            start = port
            end = port
    
    # Add the last range
    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{end}")
    
    return ", ".join(ranges)

def get_service_description(service_name: str, port: int) -> str:
    """Get human-readable description for common services"""
    service_descriptions = {
        'http': 'Web Server (HTTP)',
        'https': 'Secure Web Server (HTTPS)',
        'ssh': 'Secure Shell (SSH)',
        'ftp': 'File Transfer Protocol (FTP)',
        'telnet': 'Telnet Remote Access',
        'smtp': 'Simple Mail Transfer Protocol (SMTP)',
        'pop3': 'Post Office Protocol v3 (POP3)',
        'imap': 'Internet Message Access Protocol (IMAP)',
        'dns': 'Domain Name System (DNS)',
        'mysql': 'MySQL Database Server',
        'postgresql': 'PostgreSQL Database Server',
        'mssql': 'Microsoft SQL Server',
        'oracle': 'Oracle Database Server',
        'mongodb': 'MongoDB Database Server',
        'redis': 'Redis Cache Server',
        'elasticsearch': 'Elasticsearch Search Engine',
        'smb': 'Server Message Block (SMB)',
        'rdp': 'Remote Desktop Protocol (RDP)',
        'vnc': 'Virtual Network Computing (VNC)',
        'snmp': 'Simple Network Management Protocol (SNMP)'
    }
    
    # Try to get description by service name
    desc = service_descriptions.get(service_name.lower())
    if desc:
        return desc
    
    # Try to get description by port number
    port_descriptions = {
        21: 'File Transfer Protocol (FTP)',
        22: 'Secure Shell (SSH)',
        23: 'Telnet',
        25: 'Simple Mail Transfer Protocol (SMTP)',
        53: 'Domain Name System (DNS)',
        80: 'Web Server (HTTP)',
        110: 'Post Office Protocol v3 (POP3)',
        143: 'Internet Message Access Protocol (IMAP)',
        443: 'Secure Web Server (HTTPS)',
        993: 'Secure IMAP (IMAPS)',
        995: 'Secure POP3 (POP3S)',
        1433: 'Microsoft SQL Server',
        3306: 'MySQL Database Server',
        3389: 'Remote Desktop Protocol (RDP)',
        5432: 'PostgreSQL Database Server',
        5900: 'Virtual Network Computing (VNC)',
        6379: 'Redis Cache Server',
        9200: 'Elasticsearch HTTP',
        27017: 'MongoDB Database Server'
    }
    
    return port_descriptions.get(port, f"Service on port {port}")

def calculate_scan_duration(start_time: float, end_time: float) -> str:
    """Calculate and format scan duration"""
    duration = end_time - start_time
    
    if duration < 60:
        return f"{duration:.1f} seconds"
    elif duration < 3600:
        minutes = int(duration // 60)
        seconds = int(duration % 60)
        return f"{minutes}m {seconds}s"
    else:
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        return f"{hours}h {minutes}m"

def get_severity_color(severity: str) -> str:
    """Get color code for vulnerability severity"""
    colors = {
        'critical': '#dc3545',
        'high': '#fd7e14',
        'medium': '#ffc107',
        'low': '#28a745',
        'info': '#17a2b8',
        'informational': '#17a2b8'
    }
    return colors.get(severity.lower(), '#6c757d')

def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text to specified length with ellipsis"""
    if not text:
        return ""
    
    text = str(text).strip()
    if len(text) <= max_length:
        return text
    
    return text[:max_length-3] + "..."

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file system usage"""
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove multiple consecutive underscores
    filename = re.sub(r'_+', '_', filename)
    
    # Remove leading/trailing underscores and dots
    filename = filename.strip('_.')
    
    # Ensure filename is not empty
    if not filename:
        filename = "scan_results"
    
    return filename
