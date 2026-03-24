"""
core/error_recovery.py - Self-Reflection and Error Recovery System
Analyzes failures and adapts strategy automatically
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
import json

logger = logging.getLogger("recon.error_recovery")


class ErrorRecovery:
    """
    Self-reflection and error recovery:
    - Tracks errors per phase/tool
    - Identifies root causes
    - Suggests alternative approaches
    - Adapts future attempts
    - Maintains retry state
    """

    # Error categories and mitigations
    ERROR_PATTERNS = {
        'timeout': {
            'causes': ['slow server', 'network issue', 'resource exhaustion'],
            'mitigations': ['increase timeout', 'reduce request rate', 'skip tool', 'reduce payload size']
        },
        'connection_refused': {
            'causes': ['service down', 'port blocked', 'firewall'],
            'mitigations': ['retry after delay', 'try alternate port', 'try HTTPS', 'skip tool']
        },
        'no_scheme_supplied': {
            'causes': ['URL normalization issue', 'missing scheme'],
            'mitigations': ['prepend https://', 'validate URL format', 'extract domain properly']
        },
        'invalid_url': {
            'causes': ['malformed URL', 'invalid characters', 'NameResolutionError', 'label empty'],
            'mitigations': ['URL-encode payload', 'skip malformed URL', 'validate URL structure']
        },
        'ssl_error': {
            'causes': ['invalid certificate', 'self-signed cert'],
            'mitigations': ['disable SSL verification', 'try HTTP instead', 'skip tool']
        },
        'permission_denied': {
            'causes': ['insufficient privileges', 'auth required', 'WAF block'],
            'mitigations': ['obtain credentials', 'try with auth', 'change IP', 'try alternate payload']
        },
        'rate_limited': {
            'causes': ['too many requests', 'rate limiting active'],
            'mitigations': ['increase delay', 'reduce workers', 'spread requests', 'wait and retry']
        },
        'no_response': {
            'causes': ['service unresponsive', 'timeout', 'network down'],
            'mitigations': ['increase timeout', 'retry', 'skip tool', 'check connectivity']
        },
    }

    def __init__(self):
        self.error_history = defaultdict(list)  # phase -> [errors]
        self.error_count = defaultdict(int)  # phase -> count
        self.phase_strategies = {}  # phase -> adaptive strategy
        self.phase_skip_reasons = {}  # phase -> reason to skip
        self.retry_state = {}  # phase -> retry info
        self.successful_approaches = defaultdict(list)  # phase -> working approaches

    def log_error(self, phase: str, tool: str, error: str, context: Dict = None) -> None:
        """
        Log an error with context
        """
        error_entry = {
            'phase': phase,
            'tool': tool,
            'error': error,
            'error_type': self._categorize_error(error),
            'context': context or {},
            'timestamp': logger.handlers[0].formatter.default_time_format if logger.handlers else None
        }
        
        self.error_history[phase].append(error_entry)
        self.error_count[phase] += 1
        
        logger.warning(f"[{phase}] {tool}: {error[:50]}")

    def log_success(self, phase: str, tool: str, approach: str = "") -> None:
        """
        Log successful approach for future reference
        """
        self.successful_approaches[phase].append({
            'tool': tool,
            'approach': approach,
            'timestamp': None
        })
        
        logger.info(f"[{phase}] Success with {tool}")

    def suggest_recovery(self, phase: str, tool: str, error: str) -> Dict[str, Any]:
        """
        Suggest recovery strategy for error
        
        Returns:
            {
                'root_cause': str,
                'mitigations': [str],
                'recommended_action': str,
                'skip': bool,
                'retry': bool,
                'timeout_increase': int or None
            }
        """
        error_type = self._categorize_error(error)
        
        recovery = {
            'root_cause': error,
            'error_type': error_type,
            'mitigations': [],
            'recommended_action': 'retry',
            'skip': False,
            'retry': True,
            'timeout_increase': None,
            'backoff_seconds': 1
        }

        # Get mitigations for error type
        if error_type in self.ERROR_PATTERNS:
            pattern = self.ERROR_PATTERNS[error_type]
            recovery['mitigations'] = pattern['mitigations']

        if error_type == 'invalid_url':
            recovery['recommended_action'] = 'skip'
            recovery['skip'] = True
            recovery['retry'] = False
            recovery['reason'] = 'Malformed URL detected - skipping to avoid cascading errors'
            return recovery

        # Decide on action based on error count
        error_count = self.error_count[phase]
        
        if error_count >= 3:
            # After 3 failures, consider skipping
            recovery['skip'] = True
            recovery['recommended_action'] = 'skip'
            recovery['retry'] = False
            recovery['reason'] = f"Too many failures in {phase}"
        
        elif error_count >= 2:
            # After 2 failures, try different approach
            recovery['recommended_action'] = 'try_alt'
            recovery['timeout_increase'] = 5
            recovery['backoff_seconds'] = 3
        
        else:
            # First failure, retry with same approach
            recovery['timeout_increase'] = 2
            recovery['backoff_seconds'] = 1

        # Check for successful alternatives from history
        if recovery['recommended_action'] == 'try_alt':
            successful = self.successful_approaches.get(phase, [])
            if successful:
                recovery['alternate_tool'] = successful[0]['tool']
            else:
                recovery['alternate_approach'] = self._suggest_alternate_approach(phase)

        return recovery

    def get_phase_strategy(self, phase: str, default_tools: List[str]) -> Dict[str, Any]:
        """
        Get adaptive strategy for phase based on error history
        """
        if phase in self.phase_strategies:
            return self.phase_strategies[phase]

        strategy = {
            'tools': default_tools,
            'timeout': 30,
            'workers': 5,
            'retry_count': 2,
            'skip': False,
            'adaptive_changes': []
        }

        # Adjust based on error history
        errors = self.error_history.get(phase, [])
        if errors:
            # Count error types
            timeout_errors = sum(1 for e in errors if 'timeout' in e['error'].lower())
            conn_errors = sum(1 for e in errors if 'connection' in e['error'].lower())
            
            if timeout_errors > 1:
                strategy['timeout'] = 60
                strategy['workers'] = max(1, strategy['workers'] - 1)
                strategy['adaptive_changes'].append('increased_timeout')
            
            if conn_errors > 1:
                strategy['workers'] = 1
                strategy['adaptive_changes'].append('reduced_workers')

        self.phase_strategies[phase] = strategy
        return strategy

    def should_skip_phase(self, phase: str) -> bool:
        """Check if phase should be skipped due to repeated failures"""
        return self.error_count[phase] >= 3

    def _categorize_error(self, error: str) -> str:
        """Categorize error type from message"""
        error_lower = error.lower()

        if 'timeout' in error_lower or 'timed out' in error_lower:
            return 'timeout'
        elif 'connection' in error_lower or 'refused' in error_lower or 'unreachable' in error_lower:
            return 'connection_refused'
        elif 'ssl' in error_lower or 'certificate' in error_lower or 'https' in error_lower:
            return 'ssl_error'
        elif 'scheme' in error_lower or 'no scheme' in error_lower:
            return 'no_scheme_supplied'
        elif 'nameresolutionerror' in error_lower or 'failed to resolve' in error_lower:
            return 'invalid_url'
        elif 'label empty' in error_lower or 'too long' in error_lower:
            return 'invalid_url'
        elif 'port could not be cast' in error_lower:
            return 'invalid_url'
        elif 'url' in error_lower or 'invalid' in error_lower or 'malformed' in error_lower:
            return 'invalid_url'
        elif 'permission' in error_lower or 'denied' in error_lower or 'forbidden' in error_lower:
            return 'permission_denied'
        elif 'rate' in error_lower or 'too many' in error_lower:
            return 'rate_limited'
        elif 'no response' in error_lower or 'empty' in error_lower:
            return 'no_response'
        
        return 'unknown'

    def _suggest_alternate_approach(self, phase: str) -> str:
        """Suggest alternate approach for phase"""
        approaches = {
            'recon': 'Try direct DNS enumeration or certificate transparency',
            'live_hosts': 'Try mass ping or ICMP sweep',
            'discovery': 'Try parameter fuzzing or wayback machine',
            'scan': 'Try smaller payload set or reduce concurrency',
            'exploit': 'Try SQL injection or XSS if available',
            'toolkit': 'Skip and continue to exploitation'
        }
        
        return approaches.get(phase, 'Continue to next phase')

    def generate_report(self) -> Dict[str, Any]:
        """Generate error recovery report"""
        return {
            'total_errors': sum(self.error_count.values()),
            'phases_affected': dict(self.error_count),
            'error_patterns': dict(self.error_history),
            'recovery_suggestions': {
                phase: self.suggest_recovery(phase, 'adaptive', str(errors[-1]) if errors else '')
                for phase, errors in self.error_history.items() if errors
            },
            'successful_approaches': dict(self.successful_approaches)
        }

    def reset_phase(self, phase: str) -> None:
        """Reset error tracking for phase to try again"""
        self.error_count[phase] = 0
        self.error_history[phase] = []
        if phase in self.phase_strategies:
            del self.phase_strategies[phase]
        
        logger.info(f"Reset error tracking for {phase}")


class ConditionalPlaybook:
    """
    Conditional execution playbook:
    - IF condition -> THEN action
    - Maintains playbook state
    - Routes attacks dynamically
    """

    def __init__(self):
        self.state = {}

    def check_condition(self, condition: str, context: Dict) -> bool:
        """Evaluate condition"""
        conditions = {
            'has_wp': lambda c: c.get('found_wordpress', False),
            'has_plugins': lambda c: len(c.get('plugins', [])) > 0,
            'has_upload': lambda c: c.get('has_upload_form', False),
            'has_auth': lambda c: c.get('auth_found', False),
            'credentials_found': lambda c: c.get('credentials', {}) and len(c['credentials']) > 0,
            'user_enum_success': lambda c: len(c.get('users', [])) > 0,
            'login_success': lambda c: c.get('session_active', False),
        }

        if condition in conditions:
            return conditions[condition](context)
        
        return False

    def execute_playbook(self, findings: Dict) -> List[str]:
        """
        Execute conditional playbook based on findings
        Returns: [actions to execute]
        """
        actions = []

        # IF WordPress found
        if self.check_condition('has_wp', findings):
            actions.append('wp_plugin_scan')
            
            if self.check_condition('has_plugins', findings):
                actions.append('wp_plugin_exploit')
                actions.append('wp_xmlrpc_bruteforce')
            
            if self.check_condition('user_enum_success', findings):
                actions.append('wp_login_attempt')

        # IF upload form found
        if self.check_condition('has_upload', findings):
            actions.append('test_file_upload')
            actions.append('upload_shell')

        # IF authentication required
        if self.check_condition('has_auth', findings):
            if self.check_condition('credentials_found', findings):
                actions.append('authenticated_scan')
            else:
                actions.append('login_bruteforce')

        # IF credentials obtained
        if self.check_condition('login_success', findings):
            actions.append('admin_actions')
            actions.append('privilege_escalation')

        return actions

    def update_state(self, key: str, value: Any) -> None:
        """Update playbook state"""
        self.state[key] = value

    def get_state(self, key: str, default=None) -> Any:
        """Get playbook state"""
        return self.state.get(key, default)
