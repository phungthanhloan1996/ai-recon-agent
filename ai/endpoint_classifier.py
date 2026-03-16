"""
ai/endpoint_classifier.py - AI Endpoint Classifier
Uses Groq API to classify endpoints by type and risk level
"""

import json
import logging
from typing import Dict, Any, Optional
import urllib.request

logger = logging.getLogger("recon.endpoint_classifier")


class EndpointClassifier:
    """
    AI-powered endpoint classification using Groq API.
    Classifies URLs by type (upload, auth, admin, etc.) and risk level.
    """

    def __init__(self, groq_api_key: str):
        self.api_key = groq_api_key
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "llama-3.3-70b-versatile"

    def classify(self, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify an endpoint using AI analysis

        Args:
            endpoint_data: Dict containing 'url', 'path', 'parameters', 'context'

        Returns:
            Dict with 'endpoint_type', 'risk_level', 'confidence', 'reasoning'
        """
        if not self.api_key:
            return self._fallback_classification(endpoint_data)

        try:
            prompt = self._build_classification_prompt(endpoint_data)
            response = self._call_groq_api(prompt)
            return self._parse_classification_response(response, endpoint_data)

        except Exception as e:
            logger.warning(f"AI classification failed: {e}, using fallback")
            return self._fallback_classification(endpoint_data)

    def _build_classification_prompt(self, endpoint_data: Dict[str, Any]) -> str:
        """Build the classification prompt for the AI"""
        url = endpoint_data.get('url', '')
        path = endpoint_data.get('path', '')
        params = endpoint_data.get('parameters', [])
        context = endpoint_data.get('context', '')

        prompt = f"""Analyze this web endpoint and classify it:

URL: {url}
Path: {path}
Parameters: {', '.join(params) if params else 'None'}
Context: {context}

Classify the endpoint type and risk level. Consider:
- Endpoint types: file_upload, authentication, admin_panel, api_endpoint, search, file_download, user_profile, config, backup, logs, database, command_execution, file_inclusion, xss_vulnerable, sqli_vulnerable, other
- Risk levels: CRITICAL, HIGH, MEDIUM, LOW, INFO

Return JSON format:
{{
    "endpoint_type": "type_here",
    "risk_level": "level_here",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
}}

Be precise and consider security implications."""

        return prompt

    def _call_groq_api(self, prompt: str) -> str:
        """Call Groq API for classification"""
        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 500,
            "temperature": 0.3,
        }).encode()

        req = urllib.request.Request(
            self.api_url,
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.loads(resp.read().decode())
            return out.get("choices", [{}])[0].get("message", {}).get("content", "")

    def _parse_classification_response(self, response: str, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse the AI response into structured data"""
        try:
            # Try to extract JSON from response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end > start:
                json_str = response[start:end]
                result = json.loads(json_str)

                # Validate required fields
                result.setdefault('endpoint_type', 'other')
                result.setdefault('risk_level', 'MEDIUM')
                result.setdefault('confidence', 0.5)
                result.setdefault('reasoning', 'AI classification')

                return result
            else:
                raise ValueError("No JSON found in response")

        except Exception as e:
            logger.warning(f"Failed to parse AI response: {e}")
            return self._fallback_classification(endpoint_data)

    def _fallback_classification(self, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback classification when AI is unavailable"""
        url = endpoint_data.get('url', '').lower()
        path = endpoint_data.get('path', '').lower()

        # Simple rule-based classification
        if any(keyword in path for keyword in ['upload', 'file', 'image']):
            return {
                'endpoint_type': 'file_upload',
                'risk_level': 'HIGH',
                'confidence': 0.7,
                'reasoning': 'Contains upload/file keywords'
            }
        elif any(keyword in path for keyword in ['login', 'auth', 'signin']):
            return {
                'endpoint_type': 'authentication',
                'risk_level': 'MEDIUM',
                'confidence': 0.8,
                'reasoning': 'Authentication-related endpoint'
            }
        elif any(keyword in path for keyword in ['admin', 'dashboard', 'manage']):
            return {
                'endpoint_type': 'admin_panel',
                'risk_level': 'CRITICAL',
                'confidence': 0.9,
                'reasoning': 'Administrative interface'
            }
        elif any(keyword in path for keyword in ['api', 'json', 'xml']):
            return {
                'endpoint_type': 'api_endpoint',
                'risk_level': 'MEDIUM',
                'confidence': 0.6,
                'reasoning': 'API endpoint'
            }
        else:
            return {
                'endpoint_type': 'other',
                'risk_level': 'LOW',
                'confidence': 0.3,
                'reasoning': 'No specific classification'
            }