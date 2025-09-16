import json
import csv
import io
from typing import List, Dict, Any
from datetime import datetime
import pandas as pd

class ReportGenerator:
    """Generate reports from scan results in various formats"""
    
    @staticmethod
    def generate_json_report(scan_results: List[Dict[str, Any]], 
                           include_metadata: bool = True) -> str:
        """Generate JSON report from scan results"""
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'scanner': 'NetVuln Scanner v1.0',
                'total_hosts': len(scan_results),
                'hosts_up': len([r for r in scan_results if r['status'] == 'up']),
                'total_vulnerabilities': sum(len(r['vulnerabilities']) for r in scan_results)
            } if include_metadata else {},
            'scan_results': scan_results
        }
        
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    @staticmethod
    def generate_csv_report(scan_results: List[Dict[str, Any]]) -> str:
        """Generate CSV report from scan results"""
        # Prepare data for CSV
        csv_data = []
        
        for result in scan_results:
            host = result['host']
            status = result['status']
            scan_time = result['scan_time']
            
            # If no open ports, add a single row
            if not result['open_ports']:
                csv_data.append({
                    'Host': host,
                    'Status': status,
                    'Port': '',
                    'Service': '',
                    'Version': '',
                    'Vulnerability': '',
                    'Severity': '',
                    'CVE': '',
                    'Description': '',
                    'Scan_Time': scan_time
                })
            else:
                # Add row for each port/service/vulnerability combination
                for port in result['open_ports']:
                    # Find corresponding service
                    service_info = next((s for s in result['services'] if s['port'] == port), {})
                    service_name = service_info.get('service', 'unknown')
                    service_version = service_info.get('version', '')
                    
                    # Find vulnerabilities for this port
                    port_vulns = [v for v in result['vulnerabilities'] if v.get('port') == port]
                    
                    if not port_vulns:
                        # No vulnerabilities for this port
                        csv_data.append({
                            'Host': host,
                            'Status': status,
                            'Port': port,
                            'Service': service_name,
                            'Version': service_version,
                            'Vulnerability': '',
                            'Severity': '',
                            'CVE': '',
                            'Description': '',
                            'Scan_Time': scan_time
                        })
                    else:
                        # Add row for each vulnerability
                        for vuln in port_vulns:
                            csv_data.append({
                                'Host': host,
                                'Status': status,
                                'Port': port,
                                'Service': service_name,
                                'Version': service_version,
                                'Vulnerability': vuln.get('name', ''),
                                'Severity': vuln.get('severity', ''),
                                'CVE': vuln.get('cve', ''),
                                'Description': vuln.get('description', '')[:200] + '...' if len(vuln.get('description', '')) > 200 else vuln.get('description', ''),
                                'Scan_Time': scan_time
                            })
        
        # Convert to CSV string
        if not csv_data:
            return "No data to export"
        
        df = pd.DataFrame(csv_data)
        return df.to_csv(index=False)
    
    @staticmethod
    def generate_html_report(scan_results: List[Dict[str, Any]]) -> str:
        """Generate HTML report from scan results"""
        # Calculate summary statistics
        total_hosts = len(scan_results)
        hosts_up = len([r for r in scan_results if r['status'] == 'up'])
        total_ports = sum(len(r['open_ports']) for r in scan_results)
        total_vulns = sum(len(r['vulnerabilities']) for r in scan_results)
        
        # Count vulnerabilities by severity
        vuln_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for result in scan_results:
            for vuln in result['vulnerabilities']:
                severity = vuln.get('severity', 'unknown').lower()
                if severity in vuln_counts:
                    vuln_counts[severity] += 1
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Vulnerability Scan Report</title>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
                .summary-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
                .summary-number {{ font-size: 2em; font-weight: bold; color: #3498db; }}
                .table-container {{ background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; margin-bottom: 20px; }}
                .table-header {{ background-color: #34495e; color: white; padding: 15px; font-weight: bold; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #ecf0f1; font-weight: bold; }}
                .severity-critical {{ background-color: #e74c3c; color: white; padding: 4px 8px; border-radius: 4px; }}
                .severity-high {{ background-color: #e67e22; color: white; padding: 4px 8px; border-radius: 4px; }}
                .severity-medium {{ background-color: #f39c12; color: white; padding: 4px 8px; border-radius: 4px; }}
                .severity-low {{ background-color: #27ae60; color: white; padding: 4px 8px; border-radius: 4px; }}
                .status-up {{ color: #27ae60; font-weight: bold; }}
                .status-down {{ color: #e74c3c; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Network Vulnerability Scan Report</h1>
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <div class="summary-card">
                    <div class="summary-number">{total_hosts}</div>
                    <div>Hosts Scanned</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{hosts_up}</div>
                    <div>Hosts Up</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{total_ports}</div>
                    <div>Open Ports</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{total_vulns}</div>
                    <div>Vulnerabilities</div>
                </div>
            </div>
        """
        
        # Vulnerability summary
        if total_vulns > 0:
            html_content += f"""
            <div class="table-container">
                <div class="table-header">Vulnerability Summary</div>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                        <th>Percentage</th>
                    </tr>
            """
            for severity, count in vuln_counts.items():
                if count > 0:
                    percentage = (count / total_vulns) * 100
                    html_content += f"""
                    <tr>
                        <td><span class="severity-{severity}">{severity.title()}</span></td>
                        <td>{count}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
                    """
            html_content += "</table></div>"
        
        # Hosts table
        html_content += """
        <div class="table-container">
            <div class="table-header">Host Summary</div>
            <table>
                <tr>
                    <th>Host</th>
                    <th>Status</th>
                    <th>Open Ports</th>
                    <th>Services</th>
                    <th>Vulnerabilities</th>
                    <th>Scan Time</th>
                </tr>
        """
        
        for result in scan_results:
            status_class = "status-up" if result['status'] == 'up' else "status-down"
            html_content += f"""
            <tr>
                <td>{result['host']}</td>
                <td><span class="{status_class}">{result['status'].upper()}</span></td>
                <td>{len(result['open_ports'])}</td>
                <td>{len(result['services'])}</td>
                <td>{len(result['vulnerabilities'])}</td>
                <td>{result['scan_time']}</td>
            </tr>
            """
        
        html_content += "</table></div>"
        
        # Detailed vulnerabilities table
        if total_vulns > 0:
            html_content += """
            <div class="table-container">
                <div class="table-header">Detailed Vulnerabilities</div>
                <table>
                    <tr>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Vulnerability</th>
                        <th>Severity</th>
                        <th>CVE</th>
                        <th>Description</th>
                    </tr>
            """
            
            for result in scan_results:
                for vuln in result['vulnerabilities']:
                    severity = vuln.get('severity', 'unknown').lower()
                    html_content += f"""
                    <tr>
                        <td>{result['host']}</td>
                        <td>{vuln.get('port', 'N/A')}</td>
                        <td>{vuln.get('service', 'N/A')}</td>
                        <td>{vuln.get('name', 'Unknown')}</td>
                        <td><span class="severity-{severity}">{severity.title()}</span></td>
                        <td>{vuln.get('cve', 'N/A')}</td>
                        <td>{vuln.get('description', '')[:150] + '...' if len(vuln.get('description', '')) > 150 else vuln.get('description', '')}</td>
                    </tr>
                    """
            
            html_content += "</table></div>"
        
        html_content += """
            <div style="text-align: center; margin-top: 40px; color: #7f8c8d;">
                <p>Report generated by NetVuln Scanner v1.0</p>
            </div>
        </body>
        </html>
        """
        
        return html_content
    
    @staticmethod
    def generate_executive_summary(scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate executive summary of scan results"""
        total_hosts = len(scan_results)
        hosts_up = len([r for r in scan_results if r['status'] == 'up'])
        total_ports = sum(len(r['open_ports']) for r in scan_results)
        
        # Vulnerability analysis
        all_vulnerabilities = []
        for result in scan_results:
            all_vulnerabilities.extend(result['vulnerabilities'])
        
        vuln_by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in all_vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            if severity in vuln_by_severity:
                vuln_by_severity[severity] += 1
        
        # Risk assessment
        risk_score = 0
        risk_score += vuln_by_severity['critical'] * 10
        risk_score += vuln_by_severity['high'] * 7
        risk_score += vuln_by_severity['medium'] * 4
        risk_score += vuln_by_severity['low'] * 1
        
        if risk_score >= 50:
            risk_level = "Critical"
        elif risk_score >= 30:
            risk_level = "High"
        elif risk_score >= 15:
            risk_level = "Medium"
        elif risk_score > 0:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
        
        # Top vulnerabilities
        top_vulnerabilities = sorted(
            all_vulnerabilities,
            key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x.get('severity', 'low').lower(), 1),
            reverse=True
        )[:5]
        
        # Common services
        all_services = []
        for result in scan_results:
            for service in result['services']:
                all_services.append(service.get('service', 'unknown'))
        
        service_counts = {}
        for service in all_services:
            service_counts[service] = service_counts.get(service, 0) + 1
        
        top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'scan_summary': {
                'total_hosts': total_hosts,
                'hosts_up': hosts_up,
                'uptime_percentage': (hosts_up / total_hosts * 100) if total_hosts > 0 else 0,
                'total_open_ports': total_ports,
                'total_vulnerabilities': len(all_vulnerabilities)
            },
            'vulnerability_breakdown': vuln_by_severity,
            'risk_assessment': {
                'risk_level': risk_level,
                'risk_score': risk_score,
                'description': f"Network poses {risk_level.lower()} security risk based on vulnerability analysis"
            },
            'top_vulnerabilities': [
                {
                    'name': vuln.get('name', 'Unknown'),
                    'severity': vuln.get('severity', 'Unknown'),
                    'hosts_affected': len([r for r in scan_results if any(v.get('name') == vuln.get('name') for v in r['vulnerabilities'])])
                }
                for vuln in top_vulnerabilities
            ],
            'common_services': [
                {'service': service, 'count': count}
                for service, count in top_services
            ],
            'recommendations': ReportGenerator._generate_recommendations(vuln_by_severity, top_vulnerabilities)
        }
    
    @staticmethod
    def _generate_recommendations(vuln_by_severity: Dict[str, int], 
                                top_vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        if vuln_by_severity['critical'] > 0:
            recommendations.append("Immediately address all critical vulnerabilities - these pose immediate security risks")
        
        if vuln_by_severity['high'] > 0:
            recommendations.append("Prioritize patching of high-severity vulnerabilities within 48 hours")
        
        if vuln_by_severity['medium'] > 0:
            recommendations.append("Schedule remediation of medium-severity vulnerabilities within one week")
        
        # Service-specific recommendations
        for vuln in top_vulnerabilities[:3]:
            if vuln.get('recommendation'):
                recommendations.append(vuln['recommendation'])
        
        # General recommendations
        recommendations.extend([
            "Implement network segmentation to limit attack surface",
            "Enable logging and monitoring for all network services",
            "Regularly update and patch all systems and services",
            "Implement strong authentication mechanisms",
            "Consider using a Web Application Firewall (WAF) for web services"
        ])
        
        return list(dict.fromkeys(recommendations))  # Remove duplicates while preserving order
