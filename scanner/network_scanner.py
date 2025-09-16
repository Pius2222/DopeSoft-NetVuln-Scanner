import nmap
import socket
import asyncio
import concurrent.futures
from typing import List, Dict, Any
import logging

class NetworkScanner:
    """Network scanner using python-nmap for host discovery and port scanning"""
    
    def __init__(self, timeout: int = 10, threads: int = 10):
        self.nm = nmap.PortScanner()
        self.timeout = timeout
        self.threads = threads
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def is_host_alive(self, host: str) -> bool:
        """Check if a host is alive using ping scan"""
        try:
            result = self.nm.scan(hosts=host, arguments='-sn')
            return len(result['scan']) > 0 and any(
                result['scan'][h]['status']['state'] == 'up' 
                for h in result['scan']
            )
        except Exception as e:
            self.logger.error(f"Error checking host {host}: {e}")
            return False
    
    def scan_ports(self, host: str, ports: str) -> List[int]:
        """Scan ports on a specific host"""
        try:
            # Perform port scan
            result = self.nm.scan(
                hosts=host,
                ports=ports,
                arguments=f'-sS -T4 --host-timeout {self.timeout}s'
            )
            
            open_ports = []
            if host in result['scan']:
                host_data = result['scan'][host]
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        if port_data['state'] == 'open':
                            open_ports.append(port)
            
            return sorted(open_ports)
            
        except Exception as e:
            self.logger.error(f"Error scanning ports on {host}: {e}")
            return []
    
    def detect_service(self, host: str, port: int, aggressive: bool = False) -> Dict[str, Any]:
        """Detect service information for a specific port"""
        try:
            # Service detection arguments
            args = '-sV'
            if aggressive:
                args += ' -A -O'
            
            result = self.nm.scan(
                hosts=host,
                ports=str(port),
                arguments=f'{args} -T4 --host-timeout {self.timeout}s'
            )
            
            service_info = {
                'port': port,
                'protocol': 'tcp',
                'service': 'unknown',
                'version': '',
                'banner': '',
                'product': '',
                'extra_info': ''
            }
            
            if host in result['scan'] and 'tcp' in result['scan'][host]:
                port_data = result['scan'][host]['tcp'].get(port, {})
                
                service_info.update({
                    'service': port_data.get('name', 'unknown'),
                    'version': port_data.get('version', ''),
                    'product': port_data.get('product', ''),
                    'extra_info': port_data.get('extrainfo', '')
                })
            
            # Attempt banner grabbing
            banner = self._grab_banner(host, port)
            if banner:
                service_info['banner'] = banner
            
            return service_info
            
        except Exception as e:
            self.logger.error(f"Error detecting service on {host}:{port}: {e}")
            return {
                'port': port,
                'protocol': 'tcp',
                'service': 'unknown',
                'version': '',
                'banner': '',
                'product': '',
                'extra_info': ''
            }
    
    def _grab_banner(self, host: str, port: int) -> str:
        """Attempt to grab banner from a service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send common probes
            probes = [b'GET / HTTP/1.0\r\n\r\n', b'\r\n', b'HELP\r\n']
            
            for probe in probes:
                try:
                    sock.send(probe)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        return banner[:200]  # Limit banner length
                except:
                    continue
            
            sock.close()
            return ''
            
        except Exception as e:
            return ''
    
    def scan_network_range(self, network: str) -> List[str]:
        """Discover live hosts in a network range"""
        try:
            result = self.nm.scan(hosts=network, arguments='-sn')
            live_hosts = []
            
            for host in result['scan']:
                if result['scan'][host]['status']['state'] == 'up':
                    live_hosts.append(host)
            
            return sorted(live_hosts)
            
        except Exception as e:
            self.logger.error(f"Error scanning network range {network}: {e}")
            return []
    
    def get_host_info(self, host: str) -> Dict[str, Any]:
        """Get detailed host information"""
        try:
            result = self.nm.scan(
                hosts=host,
                arguments='-sS -O -sV -sC --host-timeout 300s'
            )
            
            host_info = {
                'hostname': '',
                'os': '',
                'mac_address': '',
                'vendor': ''
            }
            
            if host in result['scan']:
                host_data = result['scan'][host]
                
                # Hostname
                if 'hostnames' in host_data and host_data['hostnames']:
                    host_info['hostname'] = host_data['hostnames'][0].get('name', '')
                
                # OS detection
                if 'osmatch' in host_data and host_data['osmatch']:
                    host_info['os'] = host_data['osmatch'][0].get('name', '')
                
                # MAC address and vendor
                if 'addresses' in host_data:
                    addresses = host_data['addresses']
                    if 'mac' in addresses:
                        host_info['mac_address'] = addresses['mac']
                
                if 'vendor' in host_data and host_data['vendor']:
                    for mac, vendor in host_data['vendor'].items():
                        host_info['vendor'] = vendor
                        break
            
            return host_info
            
        except Exception as e:
            self.logger.error(f"Error getting host info for {host}: {e}")
            return {
                'hostname': '',
                'os': '',
                'mac_address': '',
                'vendor': ''
            }
