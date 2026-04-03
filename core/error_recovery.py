"""
core/error_recovery.py - Self-Reflection and Error Recovery System
Analyzes failures and adapts strategy automatically

Enhanced with error location tracking - shows which tool failed, where (file:line:function)
"""

import logging
import traceback
import sys
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
import json

logger = logging.getLogger("recon.error_recovery")


class ErrorLocation:
    """Stores detailed error location information"""
    
    def __init__(self, filename: str, lineno: int, function: str, code_context: str = ""):
        self.filename = filename
        self.lineno = lineno
        self.function = function
        self.code_context = code_context
    
    def __str__(self) -> str:
        return f"{self.filename}:{self.lineno} in {self.function}()"
    
    def to_dict(self) -> Dict:
        return {
            'filename': self.filename,
            'lineno': self.lineno,
            'function': self.function,
            'code_context': self.code_context
        }


def get_error_location(exc_info=None) -> ErrorLocation:
    """
    Extract detailed error location from current exception or provided exc_info.
    Returns the innermost frame where the error occurred.
    """
    if exc_info is None:
        exc_info = sys.exc_info()
    
    if not exc_info or not exc_info[2]:
        return ErrorLocation("unknown", 0, "unknown", "")
    
    tb = exc_info[2]
    
    # Walk to the deepest frame
    deepest_frame = None
    while tb is not None:
        deepest_frame = tb.tb_frame
        tb = tb.tb_next
    
    if deepest_frame is None:
        return ErrorLocation("unknown", 0, "unknown", "")
    
    filename = deepest_frame.f_code.co_filename
    lineno = deepest_frame.tb_lineno if hasattr(deepest_frame, 'tb_lineno') else deepest_frame.f_lineno
    function = deepest_frame.f_code.co_name
    
    # Try to get code context
    code_context = ""
    try:
        import linecache
        line = linecache.getline(filename, lineno).strip()
        if line:
            code_context = line[:80]  # Limit length
    except:
        pass
    
    return ErrorLocation(filename, lineno, function, code_context)


def get_full_traceback(exc_info=None) -> List[Dict]:
    """
    Get full traceback as a list of frames with location info.
    """
    if exc_info is None:
        exc_info = sys.exc_info()
    
    if not exc_info or not exc_info[2]:
        return []
    
    frames = []
    tb = exc_info[2]
    while tb is not None:
        frame = tb.tb_frame
        frames.append({
            'filename': frame.f_code.co_filename,
            'lineno': tb.tb_lineno,
            'function': frame.f_code.co_name,
            'locals': {k: repr(v)[:50] for k, v in frame.f_locals.items() 
                      if not k.startswith('__') and not callable(v)}
        })
        tb = tb.tb_next
    
    return list(reversed(frames))  # Oldest first


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

    def log_error(self, phase: str, tool: str, error: str, context: Dict = None, 
                  exc_info=None, location: ErrorLocation = None) -> None:
        """
        Log an error with context and location information.
        
        Args:
            phase: The phase where the error occurred
            tool: The tool/module that failed
            error: The error message
            context: Additional context dictionary
            exc_info: Exception info from sys.exc_info() for traceback analysis
            location: Pre-computed ErrorLocation (if not provided, will extract from exc_info)
        """
        # Extract location from exception if available
        if location is None and exc_info is not None:
            location = get_error_location(exc_info)
        elif location is None:
            location = get_error_location()
        
        # Get full traceback frames
        frames = get_full_traceback(exc_info) if exc_info else []
        
        error_entry = {
            'phase': phase,
            'tool': tool,
            'error': error,
            'error_type': self._categorize_error(error),
            'context': context or {},
            'location': location.to_dict() if location else None,
            'traceback': frames,
            'timestamp': logger.handlers[0].formatter.default_time_format if logger.handlers else None
        }
        
        self.error_history[phase].append(error_entry)
        self.error_count[phase] += 1
        
        # Log with location info
        location_str = str(location) if location else ""
        logger.warning(f"[{phase}] {tool}: {error[:50]} @ {location_str}")

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

    def get_error_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all errors with locations.
        Returns a structured dict for display or reporting.
        """
        summary = {
            'total_errors': sum(self.error_count.values()),
            'phases': {}
        }
        
        for phase, errors in self.error_history.items():
            phase_errors = []
            for err in errors:
                error_info = {
                    'tool': err.get('tool', 'unknown'),
                    'error': err.get('error', '')[:100],
                    'error_type': err.get('error_type', 'unknown'),
                    'location': err.get('location'),
                    'timestamp': err.get('timestamp')
                }
                phase_errors.append(error_info)
            summary['phases'][phase] = {
                'count': len(phase_errors),
                'errors': phase_errors
            }
        
        return summary

    def print_error_report(self, use_colors: bool = True) -> None:
        """
        Print a formatted error report to stdout.
        Shows which tool failed, where (file:line:function), and the error message.
        """
        # ANSI color codes
        RED = '\033[91m' if use_colors else ''
        YELLOW = '\033[93m' if use_colors else ''
        CYAN = '\033[96m' if use_colors else ''
        GREEN = '\033[92m' if use_colors else ''
        BOLD = '\033[1m' if use_colors else ''
        DIM = '\033[2m' if use_colors else ''
        RESET = '\033[0m' if use_colors else ''
        
        total_errors = sum(self.error_count.values())
        
        if total_errors == 0:
            print(f"\n{GREEN}{BOLD}✅ No errors encountered during scan{RESET}")
            return
        
        print(f"\n{RED}{BOLD}{'═' * 70}")
        print(f"  🚨 ERROR REPORT - {total_errors} error(s) detected")
        print(f"{'═' * 70}{RESET}")
        
        for phase, errors in sorted(self.error_history.items()):
            if not errors:
                continue
            
            print(f"\n{YELLOW}{BOLD}┌─ Phase: {phase.upper()} ({len(errors)} error(s)){RESET}")
            print(f"{YELLOW}│{'─' * 66}{RESET}")
            
            for i, err in enumerate(errors, 1):
                tool = err.get('tool', 'unknown')
                error_msg = err.get('error', '')[:80]
                error_type = err.get('error_type', 'unknown')
                location = err.get('location')
                timestamp = err.get('timestamp', '')
                
                # Error #N
                print(f"{YELLOW}│{RESET}  {RED}#{i}{RESET}")
                
                # Tool name
                print(f"{YELLOW}│{RESET}    {BOLD}Tool:{RESET} {CYAN}{tool}{RESET}")
                
                # Error message
                print(f"{YELLOW}│{RESET}    {BOLD}Error:{RESET} {RED}{error_msg}{RESET}")
                
                # Error type
                print(f"{YELLOW}│{RESET}    {BOLD}Type:{RESET} {YELLOW}{error_type}{RESET}")
                
                # Location info
                if location:
                    filename = location.get('filename', 'unknown')
                    # Make filename relative if possible
                    if 'ai-recon-agent' in filename:
                        idx = filename.find('ai-recon-agent')
                        filename = filename[idx:]
                    lineno = location.get('lineno', '?')
                    function = location.get('function', '?')
                    code_context = location.get('code_context', '')
                    
                    print(f"{YELLOW}│{RESET}    {BOLD}Location:{RESET}")
                    print(f"{YELLOW}│{RESET}      📍 {GREEN}{filename}:{lineno}{RESET} in {CYAN}{function}(){RESET}")
                    if code_context:
                        print(f"{YELLOW}│{RESET}      {DIM}> {code_context}{RESET}")
                
                # Separator between errors
                if i < len(errors):
                    print(f"{YELLOW}│{RESET}")
            
            print(f"{YELLOW}└{'─' * 66}{RESET}")
        
        # Print summary
        print(f"\n{RED}{BOLD}{'═' * 70}")
        print(f"  Summary: {total_errors} total errors across {len(self.error_history)} phases")
        print(f"{'═' * 70}{RESET}")
        
        # Most common error types
        error_types = defaultdict(int)
        for phase_errors in self.error_history.values():
            for err in phase_errors:
                error_types[err.get('error_type', 'unknown')] += 1
        
        if error_types:
            print(f"\n{BOLD}Most common error types:{RESET}")
            for etype, count in sorted(error_types.items(), key=lambda x: -x[1]):
                print(f"  {YELLOW}{etype}{RESET}: {count} occurrence(s)")

    def get_errors_for_display(self) -> List[Dict]:
        """
        Get recent errors formatted for display in the dashboard.
        Returns list of dicts with: tool, phase, error, location_str
        """
        display_errors = []
        
        for phase, errors in self.error_history.items():
            for err in errors:
                tool = err.get('tool', 'unknown')
                error_msg = err.get('error', '')[:40]
                location = err.get('location')
                
                if location:
                    filename = location.get('filename', 'unknown')
                    if 'ai-recon-agent' in filename:
                        idx = filename.find('ai-recon-agent')
                        filename = filename[idx + len('ai-recon-agent/'):]  # Remove prefix
                    lineno = location.get('lineno', '?')
                    function = location.get('function', '?')
                    location_str = f"{filename}:{lineno}::{function}"
                else:
                    location_str = "unknown"
                
                display_errors.append({
                    'phase': phase,
                    'tool': tool,
                    'error': error_msg,
                    'location': location_str,
                    'error_type': err.get('error_type', 'unknown')
                })
        
        # Return most recent errors first (up to 10)
        return list(reversed(display_errors[-10:]))


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
