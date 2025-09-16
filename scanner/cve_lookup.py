import requests
import time
import json
import os
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime, timedelta

class CVELookup:
    """CVE lookup service using National Vulnerability Database API"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Network-Vulnerability-Scanner/1.0'
        })
        self.rate_limit_delay = 6  # NVD API rate limit: 10 requests per minute
        self.cache = {}
        self.cache_duration = timedelta(days=1)
    
    def lookup_cves(self, service_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Look up CVEs for a service"""
        try:
            product = service_info.get('product', '').lower()
            service = service_info.get('service', '').lower()
            version = service_info.get('version', '')
            port = service_info.get('port')
            
            if not product and not service:
                return []
            
            # Prepare search terms
            search_terms = []
            if product:
                search_terms.append(product)
            elif service:
                search_terms.append(service)
            
            vulnerabilities = []
            
            for term in search_terms:
                cves = self._search_cves(term, version)
                if cves:
                    for cve in cves[:5]:  # Limit to top 5 CVEs per service
                        vulnerability = {
                            'name': f"CVE Vulnerability: {cve['id']}",
                            'cve': cve['id'],
                            'severity': self._map_cvss_to_severity(cve.get('cvss_score', 0)),
                            'description': cve.get('description', ''),
                            'cvss_score': cve.get('cvss_score', 0),
                            'published_date': cve.get('published_date', ''),
                            'port': port,
                            'service': service,
                            'recommendation': f"Review and apply patches for {cve['id']}"
                        }
                        vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error looking up CVEs: {e}")
            return []
    
    def _search_cves(self, product: str, version: str = "") -> List[Dict[str, Any]]:
        """Search for CVEs related to a product"""
        try:
            # Check cache first
            cache_key = f"{product}_{version}"
            if cache_key in self.cache:
                cached_result, cached_time = self.cache[cache_key]
                if datetime.now() - cached_time < self.cache_duration:
                    return cached_result
            
            # Build search parameters
            params = {
                'keyword': product,
                'resultsPerPage': 10
            }
            
            if version:
                params['keyword'] += f" {version}"
            
            # Make API request with rate limiting
            time.sleep(self.rate_limit_delay)
            response = self.session.get(self.base_url, params=params, timeout=30)
            
            if response.status_code != 200:
                self.logger.warning(f"CVE API returned status {response.status_code}")
                return []
            
            data = response.json()
            cves = []
            
            if 'result' in data and 'CVE_Items' in data['result']:
                for item in data['result']['CVE_Items']:
                    cve_data = self._parse_cve_item(item)
                    if cve_data and self._is_relevant_cve(cve_data, product, version):
                        cves.append(cve_data)
            
            # Cache the result
            self.cache[cache_key] = (cves, datetime.now())
            
            return sorted(cves, key=lambda x: x.get('cvss_score', 0), reverse=True)
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error during CVE lookup: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error searching CVEs: {e}")
            return []
    
    def _parse_cve_item(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a CVE item from the NVD API response"""
        try:
            cve = item.get('cve', {})
            cve_id = cve.get('CVE_data_meta', {}).get('ID', '')
            
            if not cve_id:
                return None
            
            # Get description
            descriptions = cve.get('description', {}).get('description_data', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS score
            cvss_score = 0
            impact = item.get('impact', {})
            if 'baseMetricV3' in impact:
                cvss_score = impact['baseMetricV3'].get('cvssV3', {}).get('baseScore', 0)
            elif 'baseMetricV2' in impact:
                cvss_score = impact['baseMetricV2'].get('cvssV2', {}).get('baseScore', 0)
            
            # Get published date
            published_date = item.get('publishedDate', '')
            
            return {
                'id': cve_id,
                'description': description[:500] + '...' if len(description) > 500 else description,
                'cvss_score': float(cvss_score),
                'published_date': published_date
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing CVE item: {e}")
            return None
    
    def _is_relevant_cve(self, cve_data: Dict[str, Any], product: str, version: str) -> bool:
        """Check if CVE is relevant to the product/version"""
        try:
            description = cve_data.get('description', '').lower()
            product_lower = product.lower()
            
            # Check if product name appears in description
            if product_lower not in description:
                return False
            
            # If version is specified, check relevance
            if version and version.strip():
                version_clean = version.strip().lower()
                # Simple version relevance check
                if version_clean in description:
                    return True
                # Check for version patterns
                import re
                version_pattern = r'\b' + re.escape(version_clean) + r'\b'
                if re.search(version_pattern, description):
                    return True
            
            # Filter out very old CVEs (older than 5 years) unless high severity
            try:
                if cve_data.get('published_date'):
                    pub_date = datetime.fromisoformat(cve_data['published_date'].replace('Z', '+00:00'))
                    if datetime.now().replace(tzinfo=pub_date.tzinfo) - pub_date > timedelta(days=1825):  # 5 years
                        if cve_data.get('cvss_score', 0) < 7.0:  # Not high severity
                            return False
            except:
                pass
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking CVE relevance: {e}")
            return False
    
    def _map_cvss_to_severity(self, cvss_score: float) -> str:
        """Map CVSS score to severity level"""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        elif cvss_score > 0:
            return 'low'
        else:
            return 'informational'
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific CVE"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
            
            time.sleep(self.rate_limit_delay)
            response = self.session.get(url, timeout=30)
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            if 'result' in data and 'CVE_Items' in data['result']:
                items = data['result']['CVE_Items']
                if items:
                    return self._parse_cve_item(items[0])
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting CVE details for {cve_id}: {e}")
            return None
    
    def clear_cache(self):
        """Clear the CVE cache"""
        self.cache.clear()
        self.logger.info("CVE cache cleared")
