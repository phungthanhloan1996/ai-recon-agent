"""
ai/llm_analyzer.py - LLM-based analysis for security findings

Provides LLM-powered analysis capabilities for:
- Analyzing scan results and generating insights
- Suggesting attack paths and exploitation strategies
- Generating human-readable reports
- Providing remediation recommendations
"""

import json
import time
import logging
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AnalysisType(Enum):
    """Types of LLM analysis"""
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    ATTACK_PATH_SUGGESTION = "attack_path_suggestion"
    RISK_ASSESSMENT = "risk_assessment"
    REMEDIATION_ADVICE = "remediation_advice"
    REPORT_GENERATION = "report_generation"
    EVIDENCE_CORRELATION = "evidence_correlation"


class ConfidenceLevel(Enum):
    """Confidence levels for analysis"""
    VERY_HIGH = "very_high"  # 90-100%
    HIGH = "high"  # 70-89%
    MEDIUM = "medium"  # 50-69%
    LOW = "low"  # 30-49%
    VERY_LOW = "very_low"  # <30%


@dataclass
class AnalysisRequest:
    """Request for LLM analysis"""
    request_id: str
    analysis_type: AnalysisType
    input_data: Dict[str, Any]
    context: Optional[str] = None
    max_tokens: int = 2000
    temperature: float = 0.3


@dataclass
class AnalysisResult:
    """Result of LLM analysis"""
    result_id: str
    request_id: str
    analysis_type: AnalysisType
    content: str
    confidence: ConfidenceLevel
    key_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    related_vulns: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    processing_time: float = 0.0


class LLMAnalyzer:
    """
    LLM-based analyzer for security findings.
    
    Features:
    - Analyze vulnerability scan results
    - Suggest attack paths based on findings
    - Generate risk assessments
    - Provide remediation recommendations
    - Create executive summaries
    """
    
    def __init__(self, llm_client=None):
        """
        Initialize LLM analyzer.
        
        Args:
            llm_client: LLM client (GroqClient, OpenAI, etc.)
        """
        self.llm_client = llm_client
        
        # Analysis history
        self.analysis_history: List[AnalysisResult] = []
        self.pending_requests: Dict[str, AnalysisRequest] = {}
        
        # Statistics
        self.stats = {
            'total_analyses': 0,
            'successful_analyses': 0,
            'failed_analyses': 0,
            'average_processing_time': 0.0,
        }
        
        # Analysis templates
        self._initialize_templates()
    
    def _initialize_templates(self):
        """Initialize analysis prompt templates"""
        self.templates = {
            AnalysisType.VULNERABILITY_ANALYSIS: """
Analyze the following vulnerability scan results and provide insights:

Scan Results:
{input_data}

Please provide:
1. Summary of critical findings
2. Potential attack vectors
3. Correlation between vulnerabilities
4. Risk assessment

Context: {context}
""",
            
            AnalysisType.ATTACK_PATH_SUGGESTION: """
Based on the following security findings, suggest potential attack paths:

Findings:
{input_data}

Target Environment: {context}

Please provide:
1. Step-by-step attack chains
2. Required conditions for each step
3. Likelihood of success
4. Alternative paths
""",
            
            AnalysisType.RISK_ASSESSMENT: """
Assess the risk level for the following security findings:

Findings:
{input_data}

Business Context: {context}

Please provide:
1. Overall risk score (1-10)
2. Risk breakdown by category
3. Business impact assessment
4. Urgency of remediation
""",
            
            AnalysisType.REMEDIATION_ADVICE: """
Provide remediation recommendations for:

Vulnerabilities:
{input_data}

Environment: {context}

Please provide:
1. Prioritized remediation steps
2. Specific technical fixes
3. Workarounds if immediate fix not possible
4. Prevention measures
""",
            
            AnalysisType.REPORT_GENERATION: """
Generate an executive security report based on:

Assessment Data:
{input_data}

Audience: {context}

Please provide:
1. Executive summary
2. Key findings
3. Risk assessment
4. Recommendations
5. Next steps
""",
        }
    
    def analyze(
        self,
        analysis_type: AnalysisType,
        input_data: Dict[str, Any],
        context: str = "",
        max_tokens: int = 2000,
        temperature: float = 0.3,
    ) -> AnalysisResult:
        """
        Perform LLM analysis on input data.
        
        Args:
            analysis_type: Type of analysis to perform
            input_data: Data to analyze
            context: Additional context
            max_tokens: Maximum response tokens
            temperature: LLM temperature
            
        Returns:
            AnalysisResult object
        """
        request_id = hashlib.md5(f"{analysis_type.value}:{time.time()}".encode()).hexdigest()[:12]
        
        request = AnalysisRequest(
            request_id=request_id,
            analysis_type=analysis_type,
            input_data=input_data,
            context=context,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        
        self.pending_requests[request_id] = request
        self.stats['total_analyses'] += 1
        
        start_time = time.time()
        
        try:
            # Build prompt
            prompt = self._build_prompt(request)
            
            # Call LLM
            if self.llm_client:
                response = self._call_llm(prompt, max_tokens, temperature)
            else:
                # Fallback to rule-based analysis
                response = self._rule_based_analysis(request)
            
            # Parse response
            result = self._parse_response(request, response)
            result.processing_time = time.time() - start_time
            
            self.analysis_history.append(result)
            self.stats['successful_analyses'] += 1
            
            # Update average processing time
            total = self.stats['successful_analyses']
            avg = self.stats['average_processing_time']
            self.stats['average_processing_time'] = ((avg * (total - 1)) + result.processing_time) / total
            
            if request_id in self.pending_requests:
                del self.pending_requests[request_id]
            
            return result
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            
            # Create error result
            result = AnalysisResult(
                result_id=hashlib.md5(f"error:{time.time()}".encode()).hexdigest()[:12],
                request_id=request_id,
                analysis_type=analysis_type,
                content=f"Analysis failed: {str(e)}",
                confidence=ConfidenceLevel.VERY_LOW,
            )
            result.processing_time = time.time() - start_time
            
            self.stats['failed_analyses'] += 1
            
            return result
    
    def _build_prompt(self, request: AnalysisRequest) -> str:
        """Build prompt from request"""
        template = self.templates.get(request.analysis_type, "")
        
        # Format input data
        if isinstance(request.input_data, dict):
            input_str = json.dumps(request.input_data, indent=2)
        else:
            input_str = str(request.input_data)
        
        prompt = template.format(
            input_data=input_str,
            context=request.context or "Not provided",
        )
        
        return prompt
    
    def _call_llm(self, prompt: str, max_tokens: int, temperature: float) -> str:
        """Call LLM with prompt"""
        if hasattr(self.llm_client, 'generate'):
            return self.llm_client.generate(
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature,
            )
        elif hasattr(self.llm_client, 'chat'):
            return self.llm_client.chat(
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature,
            )
        else:
            raise ValueError("LLM client does not support generate or chat methods")
    
    def _rule_based_analysis(self, request: AnalysisRequest) -> str:
        """Fallback rule-based analysis when LLM unavailable"""
        analysis_type = request.analysis_type
        input_data = request.input_data
        
        if analysis_type == AnalysisType.VULNERABILITY_ANALYSIS:
            return self._rule_vulnerability_analysis(input_data)
        elif analysis_type == AnalysisType.ATTACK_PATH_SUGGESTION:
            return self._rule_attack_path_analysis(input_data)
        elif analysis_type == AnalysisType.RISK_ASSESSMENT:
            return self._rule_risk_assessment(input_data)
        elif analysis_type == AnalysisType.REMEDIATION_ADVICE:
            return self._rule_remediation_advice(input_data)
        else:
            return "Analysis type not supported in rule-based mode"
    
    def _rule_vulnerability_analysis(self, data: Dict) -> str:
        """Rule-based vulnerability analysis"""
        findings = []
        
        # Analyze vulnerabilities
        vulns = data.get('vulnerabilities', [])
        critical_count = sum(1 for v in vulns if v.get('severity', '').lower() in ['critical', 'high'])
        medium_count = sum(1 for v in vulns if v.get('severity', '').lower() == 'medium')
        low_count = sum(1 for v in vulns if v.get('severity', '').lower() in ['low', 'informational'])
        
        findings.append(f"## Vulnerability Summary")
        findings.append(f"- Critical/High: {critical_count}")
        findings.append(f"- Medium: {medium_count}")
        findings.append(f"- Low/Info: {low_count}")
        findings.append(f"- Total: {len(vulns)}")
        
        findings.append(f"\n## Critical Findings")
        for v in vulns:
            if v.get('severity', '').lower() in ['critical', 'high']:
                findings.append(f"- **{v.get('name', 'Unknown')}**: {v.get('description', '')[:100]}")
        
        findings.append(f"\n## Attack Vectors")
        sqli_vulns = [v for v in vulns if 'sql' in v.get('name', '').lower()]
        xss_vulns = [v for v in vulns if 'xss' in v.get('name', '').lower()]
        rce_vulns = [v for v in vulns if 'rce' in v.get('name', '').lower() or 'command' in v.get('name', '').lower()]
        
        if sqli_vulns:
            findings.append(f"- SQL Injection: {len(sqli_vulns)} vulnerabilities detected")
        if xss_vulns:
            findings.append(f"- Cross-Site Scripting: {len(xss_vulns)} vulnerabilities detected")
        if rce_vulns:
            findings.append(f"- Remote Code Execution: {len(rce_vulns)} vulnerabilities detected")
        
        findings.append(f"\n## Risk Assessment")
        if critical_count > 0:
            findings.append("- **HIGH RISK**: Critical vulnerabilities require immediate attention")
        elif medium_count > 0:
            findings.append("- **MEDIUM RISK**: Medium severity issues should be addressed")
        else:
            findings.append("- **LOW RISK**: Minor issues detected")
        
        return "\n".join(findings)
    
    def _rule_attack_path_analysis(self, data: Dict) -> str:
        """Rule-based attack path analysis"""
        paths = []
        vulns = data.get('vulnerabilities', [])
        
        # Check for common attack chains
        has_sqli = any('sql' in v.get('name', '').lower() for v in vulns)
        has_upload = any('upload' in v.get('name', '').lower() for v in vulns)
        has_lfi = any('lfi' in v.get('name', '').lower() or 'file' in v.get('name', '').lower() for v in vulns)
        has_auth = any('auth' in v.get('name', '').lower() or 'bypass' in v.get('name', '').lower() for v in vulns)
        
        if has_sqli and has_upload:
            paths.append("1. SQL Injection → Data Extraction → Credential Dump → File Upload → RCE")
        
        if has_lfi and has_upload:
            paths.append("2. File Upload → LFI → Log Poisoning → RCE")
        
        if has_auth:
            paths.append("3. Authentication Bypass → Admin Access → Data Exfiltration")
        
        if has_sqli:
            paths.append("4. SQL Injection → Database Dump → Credential Reuse → Lateral Movement")
        
        result = "## Suggested Attack Paths\n\n"
        if paths:
            result += "\n".join(paths)
        else:
            result += "No clear attack chains identified. Manual analysis recommended."
        
        return result
    
    def _rule_risk_assessment(self, data: Dict) -> str:
        """Rule-based risk assessment"""
        vulns = data.get('vulnerabilities', [])
        
        # Calculate risk score
        score = 0
        for v in vulns:
            severity = v.get('severity', '').lower()
            if severity == 'critical':
                score += 10
            elif severity == 'high':
                score += 7
            elif severity == 'medium':
                score += 4
            elif severity == 'low':
                score += 1
        
        # Normalize to 1-10
        normalized_score = min(10, max(1, score / 5))
        
        result = f"## Risk Assessment\n\n"
        result += f"**Overall Risk Score: {normalized_score:.1f}/10**\n\n"
        
        if normalized_score >= 8:
            result += "**Risk Level: CRITICAL**\n"
            result += "Immediate action required. System is highly vulnerable."
        elif normalized_score >= 6:
            result += "**Risk Level: HIGH**\n"
            result += "Significant vulnerabilities detected. Priority remediation needed."
        elif normalized_score >= 4:
            result += "**Risk Level: MEDIUM**\n"
            result += "Moderate vulnerabilities detected. Schedule remediation."
        else:
            result += "**Risk Level: LOW**\n"
            result += "Minor issues detected. Address in regular maintenance."
        
        return result
    
    def _rule_remediation_advice(self, data: Dict) -> str:
        """Rule-based remediation advice"""
        vulns = data.get('vulnerabilities', [])
        
        advice = []
        advice.append("## Remediation Recommendations\n\n")
        
        # Group by type
        sqli = [v for v in vulns if 'sql' in v.get('name', '').lower()]
        xss = [v for v in vulns if 'xss' in v.get('name', '').lower()]
        auth = [v for v in vulns if 'auth' in v.get('name', '').lower()]
        
        if sqli:
            advice.append("### SQL Injection")
            advice.append("- Use parameterized queries/prepared statements")
            advice.append("- Implement input validation and sanitization")
            advice.append("- Apply Web Application Firewall (WAF) rules")
            advice.append("- Use ORM frameworks instead of raw SQL")
        
        if xss:
            advice.append("### Cross-Site Scripting")
            advice.append("- Implement Content Security Policy (CSP)")
            advice.append("- Sanitize and encode all user input")
            advice.append("- Use HTTPOnly and Secure flags on cookies")
            advice.append("- Implement input validation")
        
        if auth:
            advice.append("### Authentication Issues")
            advice.append("- Implement multi-factor authentication")
            advice.append("- Use strong password policies")
            advice.append("- Implement account lockout mechanisms")
            advice.append("- Use secure session management")
        
        return "\n".join(advice)
    
    def _parse_response(self, request: AnalysisRequest, response: str) -> AnalysisResult:
        """Parse LLM response into AnalysisResult"""
        result_id = hashlib.md5(f"{request.request_id}:result".encode()).hexdigest()[:12]
        
        # Extract key findings (simple heuristic)
        key_findings = []
        for line in response.split('\n'):
            line = line.strip()
            if line.startswith(('-', '*', '•')) and len(line) > 5:
                key_findings.append(line.lstrip('-*•').strip())
        
        # Determine confidence based on response quality
        if len(response) > 500 and len(key_findings) > 3:
            confidence = ConfidenceLevel.HIGH
        elif len(response) > 200 and len(key_findings) > 1:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW
        
        return AnalysisResult(
            result_id=result_id,
            request_id=request.request_id,
            analysis_type=request.analysis_type,
            content=response,
            confidence=confidence,
            key_findings=key_findings[:10],  # Limit to top 10
        )
    
    def analyze_vulnerabilities(
        self,
        vulnerabilities: List[Dict],
        context: str = "",
    ) -> AnalysisResult:
        """Convenience method for vulnerability analysis"""
        return self.analyze(
            analysis_type=AnalysisType.VULNERABILITY_ANALYSIS,
            input_data={'vulnerabilities': vulnerabilities},
            context=context,
        )
    
    def suggest_attack_paths(
        self,
        findings: Dict[str, Any],
        target_context: str = "",
    ) -> AnalysisResult:
        """Convenience method for attack path suggestion"""
        return self.analyze(
            analysis_type=AnalysisType.ATTACK_PATH_SUGGESTION,
            input_data=findings,
            context=target_context,
        )
    
    def assess_risk(
        self,
        findings: Dict[str, Any],
        business_context: str = "",
    ) -> AnalysisResult:
        """Convenience method for risk assessment"""
        return self.analyze(
            analysis_type=AnalysisType.RISK_ASSESSMENT,
            input_data=findings,
            context=business_context,
        )
    
    def get_remediation_advice(
        self,
        vulnerabilities: List[Dict],
        environment: str = "",
    ) -> AnalysisResult:
        """Convenience method for remediation advice"""
        return self.analyze(
            analysis_type=AnalysisType.REMEDIATION_ADVICE,
            input_data={'vulnerabilities': vulnerabilities},
            context=environment,
        )
    
    def generate_report(
        self,
        assessment_data: Dict[str, Any],
        audience: str = "technical",
    ) -> AnalysisResult:
        """Convenience method for report generation"""
        return self.analyze(
            analysis_type=AnalysisType.REPORT_GENERATION,
            input_data=assessment_data,
            context=f"Audience: {audience}",
        )
    
    def get_analysis_history(
        self,
        analysis_type: AnalysisType = None,
        limit: int = 10,
    ) -> List[AnalysisResult]:
        """Get analysis history"""
        history = self.analysis_history
        
        if analysis_type:
            history = [r for r in history if r.analysis_type == analysis_type]
        
        return history[-limit:]
    
    def get_stats(self) -> Dict:
        """Get analyzer statistics"""
        return {
            **self.stats,
            'pending_requests': len(self.pending_requests),
            'analysis_types': {
                at.value: len([r for r in self.analysis_history if r.analysis_type == at])
                for at in AnalysisType
            },
        }
    
    def export_results(self, output_path: str):
        """Export analysis results to JSON"""
        data = {
            'analyses': [
                {
                    'result_id': r.result_id,
                    'request_id': r.request_id,
                    'analysis_type': r.analysis_type.value,
                    'content': r.content,
                    'confidence': r.confidence.value,
                    'key_findings': r.key_findings,
                    'recommendations': r.recommendations,
                    'created_at': r.created_at,
                    'processing_time': r.processing_time,
                }
                for r in self.analysis_history
            ],
            'stats': self.get_stats(),
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported LLM analysis results to {output_path}")


# Convenience function
def create_analyzer(llm_client=None) -> LLMAnalyzer:
    """
    Create an LLM analyzer instance.
    
    Args:
        llm_client: Optional LLM client
        
    Returns:
        LLMAnalyzer instance
    """
    return LLMAnalyzer(llm_client)