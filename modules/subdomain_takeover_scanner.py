"""
modules/subdomain_takeover_scanner.py - Subdomain Takeover Detection
Dangling DNS, CNAME takeover, cloud service takeover
"""

import json
import logging
import socket
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urlparse, urljoin

from core.http_engine import HTTPClient

logger = logging.getLogger("recon.subdomain_takeover")


class SubdomainTakeoverScanner:
    """Detect subdomain takeover vulnerabilities"""
    
    def __init__(self, output_dir: str, timeout: int = 30):
        self.output_dir = output_dir
        self.timeout = timeout
        self.http_client = HTTPClient(timeout=timeout)
        self.findings_file = f"{output_dir}/subdomain_takeover_findings.json"
        
        # Cloud services fingerprints
        self.cloud_services = {
            'github': {
                'cnames': ['github.io', 'github.com'],
                'fingerprints': ['There isn\'t a GitHub Pages site here']
            },
            'heroku': {
                'cnames': ['herokuapp.com'],
                'fingerprints': ['No such app', 'Heroku | Application error']
            },
            'aws_s3': {
                'cnames': ['s3.amazonaws.com', 's3-'],
                'fingerprints': ['NoSuchBucket', 'The specified bucket does not exist']
            },
            'azure': {
                'cnames': ['azurewebsites.net'],
                'fingerprints': ['Azure', '404 - Web app not found']
            },
            'vercel': {
                'cnames': ['vercel.app'],
                'fingerprints': ['DEPLOYMENT_NOT_FOUND', 'The deployment does not exist']
            },
            'netlify': {
                'cnames': ['netlify.app', 'netlify.com'],
                'fingerprints': ['Page Not Found', 'Netlify - site not found']
            },
            'firebase': {
                'cnames': ['firebaseapp.com'],
                'fingerprints': ['Firebase hosting', 'does not exist']
            },
            'zendesk': {
                'cnames': ['zendesk.com'],
                'fingerprints': ['Help Center', 'does not exist']
            }
        }
    
    def scan(
        self,
        url: str,
        subdomains: Optional[List[str]] = None,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """Scan for subdomain takeover vulnerabilities"""
        result = {
            'url': url,
            'tool': 'subdomain_takeover',
            'type': 'subdomain_takeover',
            'subdomains_checked': 0,
            'vulnerable_subdomains': [],
            'dangling_dns': [],
            'cname_records': {}
        }
        
        if progress_cb:
            progress_cb('subdomain_takeover', 'takeover_scanner', 'Scanning subdomain takeover...')
        
        logger.info(f"[TAKEOVER] Scanning {url}")
        
        # Parse main domain
        parsed = urlparse(url)
        main_domain = parsed.netloc.split(':')[0]
        
        if not subdomains:
            subdomains = self._discover_subdomains(main_domain)
        
        result['subdomains_checked'] = len(subdomains)
        
        for subdomain in subdomains:
            try:
                if progress_cb:
                    progress_cb('subdomain_takeover', 'takeover_scanner', f'Checking {subdomain}...')
                
                # Check for takeover
                takeover = self._check_subdomain_takeover(subdomain)
                if takeover:
                    result['vulnerable_subdomains'].append(takeover)
                    logger.info(f"[TAKEOVER] VULNERABLE: {subdomain} - {takeover['reason']}")
                
                # Get CNAME
                cname = self._get_cname(subdomain)
                if cname:
                    result['cname_records'][subdomain] = cname
                    
                    # Check if CNAME points to cloud service
                    cloud_service = self._check_cloud_service_cname(cname)
                    if cloud_service:
                        result['dangling_dns'].append({
                            'subdomain': subdomain,
                            'cname': cname,
                            'service': cloud_service,
                            'severity': 'high'
                        })
            
            except Exception as e:
                logger.debug(f"[TAKEOVER] Error checking {subdomain}: {e}")
        
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"[TAKEOVER] Error saving: {e}")
        
        if progress_cb:
            vuln_count = len(result['vulnerable_subdomains'])
            progress_cb('subdomain_takeover', 'takeover_scanner', f'Found {vuln_count} takeover targets')
        
        return result
    
    def _discover_subdomains(self, domain: str) -> List[str]:
        """Discover common subdomains"""
        common_subs = [
            'www',
            'mail',
            'admin',
            'api',
            'app',
            'blog',
            'cdn',
            'cms',
            'dashboard',
            'dev',
            'docs',
            'ftp',
            'git',
            'jenkins',
            'portal',
            'shop',
            'staging',
            'status',
            'support',
            'test',
            'vpn',
            'wiki',
            'old',
            'new',
            'temp',
            's3',
            'assets',
            'images',
            'files',
            'download',
            'static',
            'media'
        ]
        
        subdomains = []
        for sub in common_subs:
            subdomains.append(f"{sub}.{domain}")
        
        return subdomains
    
    def _check_subdomain_takeover(self, subdomain: str) -> Optional[Dict]:
        """Check if subdomain is vulnerable to takeover"""
        try:
            url = f"http://{subdomain}"
            
            try:
                resp = self.http_client.get(url, timeout=self.timeout)
                response_text = resp.text.lower()
                
                # Check for cloud service fingerprints
                for service, config in self.cloud_services.items():
                    for fingerprint in config['fingerprints']:
                        if fingerprint.lower() in response_text:
                            return {
                                'subdomain': subdomain,
                                'service': service,
                                'reason': f"Found {service} takeover fingerprint",
                                'severity': 'critical'
                            }
            
            except socket.gaierror:
                # DNS doesn't resolve
                return {
                    'subdomain': subdomain,
                    'service': 'dangling_dns',
                    'reason': 'DNS does not resolve (dangling DNS)',
                    'severity': 'high'
                }
            
            except Exception as e:
                logger.debug(f"[TAKEOVER] Error: {e}")
        
        except Exception as e:
            logger.debug(f"[TAKEOVER] Error checking: {e}")
        
        return None
    
    def _get_cname(self, subdomain: str) -> Optional[str]:
        """Get CNAME record for subdomain"""
        try:
            import dns.resolver
            
            try:
                answers = dns.resolver.resolve(subdomain, 'CNAME')
                for rdata in answers:
                    return str(rdata.target).rstrip('.')
            except:
                pass
        except:
            # DNS library not available, try socket
            try:
                import socket
                result = socket.getfqdn(subdomain)
                if result != subdomain:
                    return result
            except:
                pass
        
        return None
    
    def _check_cloud_service_cname(self, cname: str) -> Optional[str]:
        """Check if CNAME points to takeable cloud service"""
        cname_lower = cname.lower()
        
        for service, config in self.cloud_services.items():
            for cname_pattern in config['cnames']:
                if cname_pattern.lower() in cname_lower:
                    return service
        
        return None
