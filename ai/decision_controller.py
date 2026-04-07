"""
ai/decision_controller.py - AI Decision Controller for Execution Pipeline

FIX: This module provides AI-controlled execution of scanning and exploitation
workflows. Instead of just generating suggestions, the AI now directly controls
the execution pipeline based on real-time analysis.

Capabilities:
- Analyze scan results in real-time
- Make decisions about next scanning steps
- Control execution flow based on findings
- Prioritize targets and attack vectors
- Adapt scanning strategy based on results
"""

import json
import time
import logging
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from dataclasses import dataclass, field

from ai.llm_analyzer import LLMAnalyzer, AnalysisType, ConfidenceLevel, create_analyzer
from core.state_manager import StateManager

logger = logging.getLogger("recon.ai_decision")


class ExecutionPhase(Enum):
    """Phases of the execution pipeline"""
    RECON = "recon"
    SCANNING = "scanning"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class DecisionType(Enum):
    """Types of AI decisions"""
    CONTINUE = "continue"  # Continue current phase
    SWITCH_PHASE = "switch_phase"  # Move to next phase
    PRIORITIZE = "prioritize"  # Prioritize specific targets
    SKIP = "skip"  # Skip current target/module
    DEEP_DIVE = "deep_dive"  # Perform deeper analysis
    ABORT = "abort"  # Abort current operation
    ADAPT = "adapt"  # Adapt scanning strategy


@dataclass
class Decision:
    """AI decision for execution control"""
    decision_id: str
    decision_type: DecisionType
    confidence: float
    reasoning: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class AIDecisionController:
    """
    AI Decision Controller for Execution Pipeline
    
    FIX: This controller integrates AI analysis directly into the execution
    pipeline, allowing the AI to make real-time decisions about scanning
    and exploitation strategies.
    
    Features:
    - Real-time analysis of scan results
    - Dynamic execution flow control
    - Adaptive scanning strategies
    - Intelligent target prioritization
    - Attack chain optimization
    """
    
    def __init__(self, state: StateManager = None, llm_client = None):
        """
        Initialize AI Decision Controller.
        
        Args:
            state: State manager for sharing data between modules
            llm_client: Optional LLM client for analysis
        """
        self.state = state
        self.analyzer = create_analyzer(llm_client)
        
        # Execution state
        self.current_phase = ExecutionPhase.RECON
        self.phase_history: List[Dict[str, Any]] = []
        self.decisions: List[Decision] = []
        
        # Statistics
        self.stats = {
            'total_decisions': 0,
            'phase_transitions': 0,
            'targets_prioritized': 0,
            'operations_aborted': 0,
            'deep_dives_triggered': 0,
        }
        
        # Decision thresholds
        self.thresholds = {
            'high_confidence': 0.8,
            'medium_confidence': 0.6,
            'low_confidence': 0.4,
        }
        
        # Phase transition rules
        self._initialize_phase_rules()
    
    def _initialize_phase_rules(self):
        """Initialize phase transition rules"""
        self.phase_rules = {
            ExecutionPhase.RECON: {
                'completion_criteria': ['sufficient_hosts', 'subdomain_enumeration_complete'],
                'next_phase': ExecutionPhase.SCANNING,
                'min_findings': 5,
            },
            ExecutionPhase.SCANNING: {
                'completion_criteria': ['high_value_hosts_scanned', 'tech_stack_identified'],
                'next_phase': ExecutionPhase.VULNERABILITY_ASSESSMENT,
                'min_findings': 3,
            },
            ExecutionPhase.VULNERABILITY_ASSESSMENT: {
                'completion_criteria': ['vulnerabilities_identified', 'exploitability_analyzed'],
                'next_phase': ExecutionPhase.EXPLOITATION,
                'min_findings': 1,
            },
            ExecutionPhase.EXPLOITATION: {
                'completion_criteria': ['exploitation_attempted', 'access_gained'],
                'next_phase': ExecutionPhase.POST_EXPLOITATION,
                'min_findings': 1,
            },
            ExecutionPhase.POST_EXPLOITATION: {
                'completion_criteria': ['pivot_opportunities_explored'],
                'next_phase': ExecutionPhase.REPORTING,
                'min_findings': 0,
            },
            ExecutionPhase.REPORTING: {
                'completion_criteria': ['report_generated'],
                'next_phase': None,
                'min_findings': 0,
            },
        }
    
    def analyze_and_decide(
        self,
        current_data: Dict[str, Any],
        phase: ExecutionPhase = None,
    ) -> Decision:
        """
        Analyze current state and make execution decision.
        
        FIX: This is the main entry point for AI-controlled execution.
        It analyzes scan results and returns a decision for the execution
        pipeline to follow.
        
        Args:
            current_data: Current scan/execution data
            phase: Current execution phase
            
        Returns:
            Decision object with execution instructions
        """
        if phase:
            self.current_phase = phase
        
        # Generate decision ID
        decision_id = f"dec_{int(time.time())}_{hash(str(current_data)) % 10000:04d}"
        
        # Analyze current state
        analysis = self._analyze_state(current_data)
        
        # Make decision based on analysis
        decision = self._make_decision(decision_id, current_data, analysis)
        
        # Record decision
        self.decisions.append(decision)
        self.stats['total_decisions'] += 1
        
        # Log decision
        logger.info(f"[AI_DECISION] {decision.decision_type.value}: {decision.reasoning}")
        
        return decision
    
    def _analyze_state(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze current execution state.
        
        Args:
            data: Current execution data
            
        Returns:
            Analysis results
        """
        analysis = {
            'findings_count': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'exploitable': False,
            'phase_complete': False,
            'recommendations': [],
        }
        
        # Count findings
        findings = data.get('findings', [])
        analysis['findings_count'] = len(findings)
        
        # Count by severity
        for finding in findings:
            severity = finding.get('severity', 'LOW').upper()
            if severity in ['CRITICAL']:
                analysis['critical_findings'] += 1
            elif severity in ['HIGH']:
                analysis['high_findings'] += 1
        
        # Check if exploitable
        exploitable_indicators = [
            'rce', 'sql_injection', 'xss', 'file_upload',
            'auth_bypass', 'lfi', 'ssrf', 'deserialization'
        ]
        for finding in findings:
            vuln_type = finding.get('type', '').lower()
            if any(indicator in vuln_type for indicator in exploitable_indicators):
                analysis['exploitable'] = True
                break
        
        # Check phase completion
        phase_rule = self.phase_rules.get(self.current_phase, {})
        criteria = phase_rule.get('completion_criteria', [])
        
        # Simple heuristic for phase completion
        min_findings = phase_rule.get('min_findings', 5)
        if analysis['findings_count'] >= min_findings:
            analysis['phase_complete'] = True
        
        # Use LLM for deeper analysis if available
        if analysis['findings_count'] > 0:
            try:
                llm_result = self.analyzer.analyze(
                    analysis_type=AnalysisType.VULNERABILITY_ANALYSIS,
                    input_data={'findings': findings[:10]},  # Limit for token count
                    context=f"Current phase: {self.current_phase.value}"
                )
                analysis['llm_analysis'] = llm_result.content
                analysis['recommendations'] = llm_result.key_findings
            except Exception as e:
                logger.debug(f"[AI_DECISION] LLM analysis failed: {e}")
        
        return analysis
    
    def _make_decision(
        self,
        decision_id: str,
        data: Dict[str, Any],
        analysis: Dict[str, Any],
    ) -> Decision:
        """
        Make execution decision based on analysis.
        
        Args:
            decision_id: Unique decision ID
            data: Current execution data
            analysis: Analysis results
            
        Returns:
            Decision object
        """
        # Check for critical findings that need immediate attention
        if analysis['critical_findings'] > 0:
            return Decision(
                decision_id=decision_id,
                decision_type=DecisionType.DEEP_DIVE,
                confidence=0.9,
                reasoning=f"Found {analysis['critical_findings']} critical vulnerabilities - performing deep analysis",
                parameters={
                    'focus': 'critical_vulnerabilities',
                    'action': 'immediate_exploitation',
                }
            )
        
        # Check if phase is complete
        if analysis['phase_complete']:
            next_phase = self.phase_rules.get(self.current_phase, {}).get('next_phase')
            if next_phase:
                self.stats['phase_transitions'] += 1
                return Decision(
                    decision_id=decision_id,
                    decision_type=DecisionType.SWITCH_PHASE,
                    confidence=0.8,
                    reasoning=f"Phase {self.current_phase.value} complete - moving to {next_phase.value}",
                    parameters={
                        'current_phase': self.current_phase.value,
                        'next_phase': next_phase.value,
                    }
                )
        
        # Check for exploitable vulnerabilities
        if analysis['exploitable']:
            return Decision(
                decision_id=decision_id,
                decision_type=DecisionType.PRIORITIZE,
                confidence=0.85,
                reasoning="Exploitable vulnerabilities found - prioritizing exploitation",
                parameters={
                    'priority': 'exploitation',
                    'action': 'exploit_vulnerable_endpoints',
                }
            )
        
        # Check for high severity findings
        if analysis['high_findings'] > 0:
            return Decision(
                decision_id=decision_id,
                decision_type=DecisionType.DEEP_DIVE,
                confidence=0.75,
                reasoning=f"Found {analysis['high_findings']} high severity issues - deeper analysis needed",
                parameters={
                    'focus': 'high_severity_findings',
                    'action': 'detailed_analysis',
                }
            )
        
        # Check for sufficient findings to continue
        if analysis['findings_count'] >= 3:
            return Decision(
                decision_id=decision_id,
                decision_type=DecisionType.CONTINUE,
                confidence=0.7,
                reasoning=f"Found {analysis['findings_count']} findings - continuing current phase",
                parameters={
                    'action': 'continue_scanning',
                }
            )
        
        # Check for insufficient findings
        if analysis['findings_count'] < 2:
            return Decision(
                decision_id=decision_id,
                decision_type=DecisionType.ADAPT,
                confidence=0.6,
                reasoning="Insufficient findings - adapting scanning strategy",
                parameters={
                    'action': 'expand_scan_scope',
                    'new_targets': True,
                }
            )
        
        # Default: continue current phase
        return Decision(
            decision_id=decision_id,
            decision_type=DecisionType.CONTINUE,
            confidence=0.5,
            reasoning="No significant changes - continuing current operations",
            parameters={
                'action': 'continue',
            }
        )
    
    def should_execute_module(
        self,
        module_name: str,
        context: Dict[str, Any],
    ) -> tuple[bool, str]:
        """
        Determine if a module should be executed based on AI analysis.
        
        FIX: This method allows the AI to control which modules are executed,
        preventing wasted effort on low-value targets.
        
        Args:
            module_name: Name of the module to check
            context: Current execution context
            
        Returns:
            Tuple of (should_execute, reason)
        """
        # Analyze context
        analysis = self._analyze_state(context)
        
        # Module-specific rules
        module_rules = {
            'swagger_exploiter': {
                'requires': ['api_endpoints_found'],
                'skip_if': ['no_api_detected'],
            },
            'upload_rce_exploit': {
                'requires': ['upload_endpoints_found'],
                'skip_if': ['no_upload_detected'],
            },
            'parameter_miner': {
                'requires': ['endpoints_with_params'],
                'skip_if': ['soft_404_detected'],
            },
            'dirbusting': {
                'requires': ['valid_target_url'],
                'skip_if': ['wordpress_archive_path'],
            },
        }
        
        rule = module_rules.get(module_name, {})
        
        # Check requirements
        for req in rule.get('requires', []):
            if not context.get(req):
                return False, f"Missing requirement: {req}"
        
        # Check skip conditions
        for skip in rule.get('skip_if', []):
            if context.get(skip):
                return False, f"Skip condition met: {skip}"
        
        # Check if worth executing based on analysis
        if analysis['findings_count'] == 0 and module_name in ['exploiter', 'upload_rce_exploit']:
            return False, "No findings to exploit"
        
        return True, "Module should be executed"
    
    def prioritize_targets(
        self,
        targets: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Prioritize targets based on AI analysis.
        
        FIX: This method uses AI to rank targets by exploitation potential,
        ensuring the most valuable targets are scanned first.
        
        Args:
            targets: List of target dictionaries
            
        Returns:
            Sorted list of targets (highest priority first)
        """
        scored_targets = []
        
        for target in targets:
            score = 0
            url = target.get('url', '')
            
            # Score based on URL patterns
            high_value_patterns = [
                'admin', 'api', 'upload', 'login', 'auth',
                'staging', 'dev', 'test', 'beta',
            ]
            for pattern in high_value_patterns:
                if pattern in url.lower():
                    score += 10
            
            # Score based on status code
            status = target.get('status_code', 0)
            if status == 200:
                score += 5
            elif 300 <= status < 400:
                score += 3
            
            # Score based on technology detection
            tech_stack = target.get('technologies', [])
            exploitable_techs = ['wordpress', 'apache', 'nginx', 'tomcat', 'php']
            for tech in tech_stack:
                if tech.lower() in exploitable_techs:
                    score += 5
            
            # Score based on existing findings
            findings = target.get('findings', [])
            for finding in findings:
                severity = finding.get('severity', 'LOW').upper()
                if severity == 'CRITICAL':
                    score += 20
                elif severity == 'HIGH':
                    score += 10
                elif severity == 'MEDIUM':
                    score += 5
            
            scored_targets.append((score, target))
        
        # Sort by score (descending)
        scored_targets.sort(key=lambda x: x[0], reverse=True)
        
        self.stats['targets_prioritized'] += len(targets)
        
        return [target for _, target in scored_targets]
    
    def get_execution_plan(self, phase: ExecutionPhase) -> List[Dict[str, Any]]:
        """
        Get AI-generated execution plan for a phase.
        
        Args:
            phase: Execution phase
            
        Returns:
            List of execution steps
        """
        plans = {
            ExecutionPhase.RECON: [
                {'step': 'subdomain_enumeration', 'priority': 'high'},
                {'step': 'port_scanning', 'priority': 'high'},
                {'step': 'technology_detection', 'priority': 'medium'},
                {'step': 'wayback_analysis', 'priority': 'low'},
            ],
            ExecutionPhase.SCANNING: [
                {'step': 'directory_bruteforce', 'priority': 'high'},
                {'step': 'api_discovery', 'priority': 'high'},
                {'step': 'parameter_mining', 'priority': 'medium'},
                {'step': 'swagger_discovery', 'priority': 'medium'},
            ],
            ExecutionPhase.VULNERABILITY_ASSESSMENT: [
                {'step': 'vulnerability_scanning', 'priority': 'high'},
                {'step': 'authentication_testing', 'priority': 'high'},
                {'step': 'injection_testing', 'priority': 'medium'},
                {'step': 'xss_testing', 'priority': 'medium'},
            ],
            ExecutionPhase.EXPLOITATION: [
                {'step': 'rce_exploitation', 'priority': 'critical'},
                {'step': 'sql_injection_exploitation', 'priority': 'high'},
                {'step': 'file_upload_exploitation', 'priority': 'high'},
                {'step': 'auth_bypass_testing', 'priority': 'medium'},
            ],
        }
        
        return plans.get(phase, [])
    
    def get_stats(self) -> Dict[str, Any]:
        """Get controller statistics"""
        return {
            **self.stats,
            'current_phase': self.current_phase.value,
            'total_decisions': len(self.decisions),
            'decision_types': {
                dt.value: len([d for d in self.decisions if d.decision_type == dt])
                for dt in DecisionType
            },
        }
    
    def export_decisions(self, output_path: str):
        """Export decisions to JSON"""
        data = {
            'decisions': [
                {
                    'decision_id': d.decision_id,
                    'decision_type': d.decision_type.value,
                    'confidence': d.confidence,
                    'reasoning': d.reasoning,
                    'parameters': d.parameters,
                    'timestamp': d.timestamp,
                }
                for d in self.decisions
            ],
            'stats': self.get_stats(),
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"[AI_DECISION] Exported decisions to {output_path}")


# Convenience function
def create_decision_controller(state: StateManager = None, llm_client = None) -> AIDecisionController:
    """
    Create an AI Decision Controller instance.
    
    Args:
        state: Optional state manager
        llm_client: Optional LLM client
        
    Returns:
        AIDecisionController instance
    """
    return AIDecisionController(state=state, llm_client=llm_client)