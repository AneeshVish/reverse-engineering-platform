import requests
import json
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

class ThreatIntelligence:
    """MISP and multi-source threat intelligence integration [10][11][12][14]"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.misp_url = None
        self.misp_key = None
        self.feeds = {
            'malwarebazaar': 'https://mb-api.abuse.ch/api/v1/',
            'threatminer': 'https://api.threatminer.org/v2/',
            'alienvault': 'https://otx.alienvault.com/api/v1/'
        }
        
    def configure_misp(self, url: str, api_key: str):
        """Configure MISP connection [10][14]"""
        self.misp_url = url.rstrip('/')
        self.misp_key = api_key
        self.logger.info("MISP configuration updated")
    
    def analyze_binary_hash(self, file_hash: str) -> Dict:
        """
        Analyze a binary hash against multiple threat intelligence sources [11][13]
        """
        results = {
            'hash': file_hash,
            'threats_detected': [],
            'reputation_score': 0,
            'sources': {},
            'iocs': [],
            'campaigns': []
        }
        
        # Check multiple sources in parallel
        sources_to_check = [
            ('malwarebazaar', self._check_malwarebazaar),
            ('threatminer', self._check_threatminer),
            ('alienvault', self._check_alienvault)
        ]
        
        for source_name, check_func in sources_to_check:
            try:
                source_result = check_func(file_hash)
                results['sources'][source_name] = source_result
                
                if source_result.get('malicious', False):
                    results['threats_detected'].append(source_name)
                    results['reputation_score'] += source_result.get('confidence', 0)
                    
            except Exception as e:
                results['sources'][source_name] = {'error': str(e)}
                self.logger.error(f"Error checking {source_name}: {e}")
        
        # Normalize reputation score
        if results['threats_detected']:
            results['reputation_score'] = min(100, results['reputation_score'] / len(results['threats_detected']))
        
        return results
    
    def _check_malwarebazaar(self, file_hash: str) -> Dict:
        """Check hash against MalwareBazaar [13]"""
        try:
            url = f"{self.feeds['malwarebazaar']}query/"
            data = {
                'query': 'get_info',
                'hash': file_hash
            }
            
            response = requests.post(url, data=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                return {
                    'malicious': result.get('query_status') == 'ok',
                    'confidence': 90 if result.get('query_status') == 'ok' else 0,
                    'family': result.get('data', [{}])[0].get('malware', 'Unknown'),
                    'tags': result.get('data', [{}])[0].get('tags', [])
                }
        except Exception as e:
            self.logger.error(f"MalwareBazaar check failed: {e}")
            return {'error': str(e)}
        
        return {'malicious': False, 'confidence': 0}
    
    def _check_threatminer(self, file_hash: str) -> Dict:
        """Check hash against ThreatMiner"""
        try:
            url = f"{self.feeds['threatminer']}sample.php"
            params = {
                'q': file_hash,
                'rt': 1  # Get sample metadata
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                result = response.json()
                return {
                    'malicious': result.get('status_code') == '200',
                    'confidence': 75,
                    'results': result.get('results', [])
                }
        except Exception as e:
            return {'error': str(e)}
        
        return {'malicious': False, 'confidence': 0}
    
    def _check_alienvault(self, file_hash: str) -> Dict:
        """Check hash against AlienVault OTX"""
        try:
            url = f"{self.feeds['alienvault']}indicators/file/{file_hash}/general"
            headers = {'X-OTX-API-KEY': 'your-api-key-here'}  # Would be configured
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                result = response.json()
                return {
                    'malicious': len(result.get('pulse_info', {}).get('pulses', [])) > 0,
                    'confidence': 80,
                    'pulses': result.get('pulse_info', {}).get('count', 0)
                }
        except Exception as e:
            return {'error': str(e)}
        
        return {'malicious': False, 'confidence': 0}
    
    def create_misp_event(self, binary_analysis: Dict) -> Optional[str]:
        """Create MISP event from binary analysis results [10][11]"""
        if not self.misp_url or not self.misp_key:
            return None
        
        event_data = {
            'Event': {
                'info': f"Binary Analysis: {binary_analysis.get('filename', 'Unknown')}",
                'threat_level_id': 2,  # Medium
                'analysis': 1,  # Ongoing
                'distribution': 1,  # Community only
                'Attribute': []
            }
        }
        
        # Add file hash as attribute
        if 'hash' in binary_analysis:
            event_data['Event']['Attribute'].append({
                'type': 'sha256',
                'value': binary_analysis['hash'],
                'category': 'Payload delivery',
                'to_ids': True
            })
        
        # Add IOCs found during analysis
        for ioc in binary_analysis.get('iocs', []):
            event_data['Event']['Attribute'].append({
                'type': ioc['type'],
                'value': ioc['value'],
                'category': 'Network activity',
                'comment': f"Found during binary analysis: {ioc.get('context', '')}"
            })
        
        try:
            headers = {
                'Authorization': self.misp_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.misp_url}/events",
                headers=headers,
                data=json.dumps(event_data),
                timeout=30
            )
            
            if response.status_code == 201:
                return response.json().get('Event', {}).get('id')
        
        except Exception as e:
            self.logger.error(f"MISP event creation failed: {e}")
        
        return None

class IOCExtractor:
    """Extract Indicators of Compromise from binary analysis [13][14]"""
    
    def __init__(self):
        self.ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        self.domain_pattern = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b'
        self.url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?'
        self.email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    def extract_from_strings(self, strings_list: List[str]) -> List[Dict]:
        """Extract IOCs from strings found in binary"""
        iocs = []
        
        for string in strings_list:
            # Extract IPs
            ips = re.findall(self.ip_pattern, string)
            for ip in ips:
                if self._is_valid_ip(ip):
                    iocs.append({
                        'type': 'ip-dst',
                        'value': ip,
                        'context': f'Found in string: {string[:50]}'
                    })
            
            # Extract domains
            domains = re.findall(self.domain_pattern, string)
            for domain in domains:
                if self._is_valid_domain(domain):
                    iocs.append({
                        'type': 'domain',
                        'value': domain,
                        'context': f'Found in string: {string[:50]}'
                    })
            
            # Extract URLs
            urls = re.findall(self.url_pattern, string)
            for url in urls:
                iocs.append({
                    'type': 'url',
                    'value': url,
                    'context': f'Found in string: {string[:50]}'
                })
            
            # Extract emails
            emails = re.findall(self.email_pattern, string)
            for email in emails:
                iocs.append({
                    'type': 'email-src',
                    'value': email,
                    'context': f'Found in string: {string[:50]}'
                })
        
        return self._deduplicate_iocs(iocs)
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address and filter private IPs"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            # Skip private/local IPs
            first_octet = int(parts[0])
            if first_octet in [10, 127] or (first_octet == 192 and int(parts[1]) == 168):
                return False
                
            return True
        except ValueError:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name and filter false positives"""
        if len(domain) < 4 or '.' not in domain:
            return False
        
        # Skip obvious false positives
        false_positives = ['localhost', 'example.com', 'test.com', 'google.com']
        return domain.lower() not in false_positives
    
    def _deduplicate_iocs(self, iocs: List[Dict]) -> List[Dict]:
        """Remove duplicate IOCs"""
        seen = set()
        unique_iocs = []
        
        for ioc in iocs:
            key = (ioc['type'], ioc['value'])
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        
        return unique_iocs
