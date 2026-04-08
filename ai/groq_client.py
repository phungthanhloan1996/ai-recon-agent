"""
ai/groq_client.py - Enhanced Groq API Client with OpenRouter Fallback
With circuit breaker, exponential backoff, rate limiting, and real-time OpenRouter backup
"""

import time
import random
import logging
import urllib.request
import urllib.error
import json as json_module
from typing import Optional, Dict, Any, Tuple
from enum import Enum
import requests 
logger = logging.getLogger("recon.groq_client")


class CircuitState(Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing, use fallback
    HALF_OPEN = "half_open" # Testing if service recovered


class GroqClient:
    """
    Enhanced Groq API client with:
    - Circuit breaker pattern for 429/5xx errors
    - Exponential backoff with jitter
    - Global rate limiting
    - Real-time fallback to OpenRouter when Groq fails
    - Static fallback payloads when all providers fail
    """

    # ─── CIRCUIT BREAKER CONFIGURATION ──────────────────────────────────────────
    FAILURE_THRESHOLD = 3           # Number of failures before opening circuit
    SUCCESS_THRESHOLD = 2           # Number of successes to close circuit
    INITIAL_BACKOFF = 1.0           # Initial backoff in seconds
    MAX_BACKOFF = 120.0             # Maximum backoff (2 minutes)
    BACKOFF_MULTIPLIER = 2.0        # Multiplier for exponential backoff
    JITTER_RANGE = 0.5              # Random jitter range (0-0.5 seconds)

    # ─── RATE LIMITING CONFIGURATION ────────────────────────────────────────────
    MAX_CALLS_PER_MINUTE = 10       # Global rate limit for Groq
    MIN_CALL_INTERVAL = 1.0         # Minimum seconds between Groq calls

    # ─── OPENROUTER CONFIGURATION ───────────────────────────────────────────────
    OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
    OPENROUTER_SITE_URL = ""
    OPENROUTER_SITE_NAME = "ai-recon-agent"
    OPENROUTER_MODELS = [
        "meta-llama/llama-3.1-70b-instruct",
        "meta-llama/llama-3.1-8b-instruct", 
        "google/gemini-flash-1.5",
        "mistralai/mistral-large",
        "openai/gpt-3.5-turbo",
    ]

    # ─── STATIC FALLBACK PAYLOADS ───────────────────────────────────────────────
    # Used when ALL providers (Groq + OpenRouter) fail
    FALLBACK_PAYLOADS = {
        'sqli': [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND SLEEP(5)--",
            "1' ORDER BY 1--",
        ],
        'xss': [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'><script>alert(1)</script>",
        ],
        'rce': [
            "; id",
            "| id",
            "$(id)",
            "; cat /etc/passwd",
        ],
        'lfi': [
            "../../../../etc/passwd",
            "../../../../etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php",
        ],
    }

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile",
                 openrouter_api_key: str = None):
        self.api_key = api_key
        self.model = model
        self.openrouter_api_key = openrouter_api_key
        self._openrouter_enabled = bool(openrouter_api_key)
        self._openrouter_model_index = 0  # Round-robin through OpenRouter models
        
        # Circuit breaker state for Groq
        self._circuit_state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = 0.0
        self._current_backoff = self.INITIAL_BACKOFF
        
        # Rate limiting state for Groq
        self._call_timestamps = []
        self._last_call_time = 0.0
        
        # Statistics for monitoring
        self._total_calls = 0
        self._total_failures = 0
        self._total_fallbacks = 0
        self._total_openrouter_calls = 0
        self._total_static_fallbacks = 0
        
        # Track which provider is active
        self._current_provider = "groq"

    def generate(self, prompt: str, system: str = None, temperature: float = 0.3) -> str:
        """
        Generate response with real-time failover:
        1. Try Groq (if circuit allows)
        2. Fallback to OpenRouter if Groq fails
        3. Fallback to static payloads if all fail
        """
        # Check Groq circuit breaker
        if self._circuit_state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self._circuit_state = CircuitState.HALF_OPEN
                logger.info("[GROQ] Circuit breaker half-open, attempting reset")
            else:
                # Circuit is open, skip Groq and go directly to OpenRouter
                logger.warning(f"[GROQ] Circuit open, skipping to OpenRouter fallback")
                return self._call_openrouter(prompt, system, temperature)
        
        # Apply Groq rate limiting
        self._enforce_rate_limit()
        
        # Try Groq first
        try:
            response = self._call_groq_with_retry(prompt, system, temperature)
            self._current_provider = "groq"
            return response
        except Exception as e:
            logger.warning(f"[GROQ] Failed, attempting OpenRouter fallback: {e}")
            # Groq failed, try OpenRouter
            return self._call_openrouter(prompt, system, temperature)

    def _call_groq_with_retry(self, prompt: str, system: str, temperature: float, 
                               max_retries: int = 3) -> str:
        """Call Groq API with exponential backoff and retries."""
        last_error = None
        
        for attempt in range(max_retries):
            try:
                response = self._make_groq_api_call(prompt, system, temperature)
                self._on_success()
                return response
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    # 403 Forbidden - API key invalid or expired
                    logger.error(f"[GROQ] API key rejected (403 Forbidden). Switching to OpenRouter.")
                    self._circuit_state = CircuitState.OPEN
                    self._current_backoff = self.MAX_BACKOFF  # Long backoff for auth failures
                    raise  # Re-raise to trigger OpenRouter fallback
                elif e.code == 429:
                    self._on_failure()
                    if attempt < max_retries - 1:
                        delay = self._calculate_backoff(attempt)
                        logger.warning(f"[GROQ] Rate limited (429), attempt {attempt+1}/{max_retries}. "
                                     f"Backing off {delay:.1f}s")
                        time.sleep(delay)
                    else:
                        last_error = e
                        break
                elif e.code in [500, 502, 503]:
                    # Server errors - retry with backoff
                    if attempt < max_retries - 1:
                        delay = self._calculate_backoff(attempt)
                        logger.warning(f"[GROQ] Server error {e.code}, attempt {attempt+1}/{max_retries}. "
                                     f"Backing off {delay:.1f}s")
                        time.sleep(delay)
                    else:
                        last_error = e
                        break
                else:
                    # Client errors - don't retry
                    logger.error(f"[GROQ] API error {e.code}: {e}")
                    raise
            except Exception as e:
                logger.debug(f"[GROQ] Request failed (attempt {attempt+1}): {e}")
                if attempt < max_retries - 1:
                    delay = self._calculate_backoff(attempt)
                    time.sleep(delay)
                else:
                    last_error = e
                    break
        
        # All retries exhausted
        self._on_failure()
        raise last_error or Exception("Groq API call failed after all retries")

    def _make_groq_api_call(self, prompt: str, system: str, temperature: float) -> str:
        """Make actual API call to Groq."""
        url = "https://api.groq.com/openai/v1/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        data = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 500
        }
        
        response = requests.post(url, headers=headers, json=data, timeout=30)
        
        if response.status_code == 403:
            logger.error(f"[GROQ] 403 Forbidden: {response.text}")
            raise urllib.error.HTTPError(url, 403, response.text, response.headers, None)
        
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]

    def _call_openrouter(self, prompt: str, system: str, temperature: float) -> str:
        """
        Real-time fallback to OpenRouter API.
        Tries multiple models in round-robin fashion.
        """
        if not self._openrouter_enabled:
            logger.warning("[OPENROUTER] Not configured, using static fallback")
            self._total_static_fallbacks += 1
            return self._get_fallback_response(prompt)
        
        last_error = None
        max_models = len(self.OPENROUTER_MODELS)
        
        for i in range(max_models):
            # Round-robin model selection
            model_index = (self._openrouter_model_index + i) % max_models
            model = self.OPENROUTER_MODELS[model_index]
            
            try:
                logger.info(f"[OPENROUTER] Attempting with model: {model}")
                response = self._make_openrouter_call(prompt, system, temperature, model)
                self._openrouter_model_index = (model_index + 1) % max_models
                self._total_openrouter_calls += 1
                self._current_provider = "openrouter"
                logger.info(f"[OPENROUTER] Success with model: {model}")
                return response
            except Exception as e:
                logger.warning(f"[OPENROUTER] Model {model} failed: {e}")
                last_error = e
                continue
        
        # All OpenRouter models failed
        logger.error(f"[OPENROUTER] All models failed, using static fallback")
        self._total_static_fallbacks += 1
        return self._get_fallback_response(prompt)

    def _make_openrouter_call(self, prompt: str, system: str, temperature: float, 
                               model: str) -> str:
        """Make actual API call to OpenRouter."""
        headers = {
            "Authorization": f"Bearer {self.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": self.OPENROUTER_SITE_URL,
            "X-Title": self.OPENROUTER_SITE_NAME,
        }
        
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        data = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 500
        }
        
        response = requests.post(
            self.OPENROUTER_API_URL, 
            headers=headers, 
            json=data, 
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        if "choices" in result and len(result["choices"]) > 0:
            return result["choices"][0]["message"]["content"]
        elif "error" in result:
            raise Exception(f"OpenRouter error: {result['error']}")
        else:
            raise Exception(f"Unexpected OpenRouter response: {result}")

    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate backoff delay with exponential increase and jitter."""
        # Exponential backoff
        delay = min(
            self.INITIAL_BACKOFF * (self.BACKOFF_MULTIPLIER ** attempt),
            self.MAX_BACKOFF
        )
        
        # Add jitter to prevent thundering herd
        jitter = random.uniform(0, self.JITTER_RANGE)
        delay += jitter
        
        return delay

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt circuit reset."""
        if self._circuit_state != CircuitState.OPEN:
            return True
        
        time_since_failure = time.time() - self._last_failure_time
        return time_since_failure >= self._current_backoff

    def _on_success(self):
        """Handle successful Groq API call."""
        self._success_count += 1
        self._failure_count = 0  # Reset failure count
        
        if self._circuit_state == CircuitState.HALF_OPEN:
            if self._success_count >= self.SUCCESS_THRESHOLD:
                self._circuit_state = CircuitState.CLOSED
                self._current_backoff = self.INITIAL_BACKOFF
                self._success_count = 0
                logger.info("[GROQ] Circuit breaker CLOSED - service recovered")
        
        logger.debug(f"[GROQ] Success (state={self._circuit_state.value})")

    def _on_failure(self):
        """Handle failed Groq API call."""
        self._failure_count += 1
        self._total_failures += 1
        self._last_failure_time = time.time()
        self._success_count = 0
        
        if self._circuit_state == CircuitState.HALF_OPEN:
            self._circuit_state = CircuitState.OPEN
            self._current_backoff = min(
                self._current_backoff * self.BACKOFF_MULTIPLIER,
                self.MAX_BACKOFF
            )
            logger.warning(f"[GROQ] Circuit breaker OPEN (half-open failed)")
        elif self._circuit_state == CircuitState.CLOSED:
            if self._failure_count >= self.FAILURE_THRESHOLD:
                self._circuit_state = CircuitState.OPEN
                self._current_backoff = min(
                    self._current_backoff * self.BACKOFF_MULTIPLIER,
                    self.MAX_BACKOFF
                )
                logger.warning(f"[GROQ] Circuit breaker OPEN after {self._failure_count} failures")
        
        logger.debug(f"[GROQ] Failure (state={self._circuit_state.value}, "
                    f"backoff={self._current_backoff:.1f}s)")

    def _enforce_rate_limit(self):
        """Enforce global rate limiting for Groq."""
        now = time.time()
        
        # Remove timestamps older than 1 minute
        self._call_timestamps = [t for t in self._call_timestamps if now - t < 60]
        
        # Check if we've exceeded rate limit
        if len(self._call_timestamps) >= self.MAX_CALLS_PER_MINUTE:
            oldest_timestamp = self._call_timestamps[0]
            wait_time = 60 - (now - oldest_timestamp) + 1  # +1 for safety margin
            if wait_time > 0:
                logger.debug(f"[GROQ] Rate limit reached, waiting {wait_time:.1f}s")
                time.sleep(wait_time)
                self._enforce_rate_limit()  # Recursive check
            return
        
        # Ensure minimum interval between calls
        time_since_last_call = now - self._last_call_time
        if time_since_last_call < self.MIN_CALL_INTERVAL:
            wait_time = self.MIN_CALL_INTERVAL - time_since_last_call
            time.sleep(wait_time)
        
        # Record this call
        now = time.time()
        self._call_timestamps.append(now)
        self._last_call_time = now
        self._total_calls += 1

    def _get_fallback_response(self, prompt: str) -> str:
        """Generate fallback response when ALL providers are unavailable."""
        prompt_lower = prompt.lower()
        
        # Try to detect vulnerability type from prompt
        for vuln_type, payloads in self.FALLBACK_PAYLOADS.items():
            if vuln_type in prompt_lower:
                return json_module.dumps({
                    "payloads": payloads,
                    "source": "static_fallback",
                    "note": "Generated from static templates (all AI providers unavailable)",
                    "provider": "none"
                })
        
        # Generic fallback
        return json_module.dumps({
            "payloads": ["' OR '1'='1", "<script>alert(1)</script>"],
            "source": "static_fallback",
            "note": "Generic fallback payloads (all AI providers unavailable)",
            "provider": "none"
        })

    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status and statistics."""
        return {
            "circuit_state": self._circuit_state.value,
            "current_provider": self._current_provider,
            "groq": {
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "current_backoff": self._current_backoff,
                "total_calls": self._total_calls,
                "total_failures": self._total_failures,
                "rate_limit_calls_last_minute": len(self._call_timestamps),
            },
            "openrouter": {
                "enabled": self._openrouter_enabled,
                "total_calls": self._total_openrouter_calls,
                "current_model_index": self._openrouter_model_index,
            },
            "fallbacks": {
                "total_fallbacks": self._total_fallbacks,
                "static_fallbacks": self._total_static_fallbacks,
            }
        }

    def reset(self):
        """Reset circuit breaker to initial state."""
        self._circuit_state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._current_backoff = self.INITIAL_BACKOFF
        self._call_timestamps = []
        self._last_call_time = 0.0
        logger.info("[GROQ] Circuit breaker reset")

    def is_groq_available(self) -> bool:
        """Check if Groq is currently available (circuit closed or half-open)."""
        return self._circuit_state in [CircuitState.CLOSED, CircuitState.HALF_OPEN]

    def get_current_provider(self) -> str:
        """Get the name of the current active provider."""
        return self._current_provider


# ─── FACTORY FUNCTION ───────────────────────────────────────────────────────────

def create_groq_client(api_key: str = None, openrouter_api_key: str = None,
                       model: str = None) -> GroqClient:
    """
    Factory function to create GroqClient with configuration from environment.
    """
    import os
    
    if api_key is None:
        api_key = os.getenv('GROQ_API_KEY')
    if openrouter_api_key is None:
        openrouter_api_key = os.getenv('OPENROUTER_API_KEY')
    if model is None:
        model = os.getenv('PRIMARY_AI_MODEL', 'llama-3.3-70b-versatile')
    
    return GroqClient(
        api_key=api_key,
        model=model,
        openrouter_api_key=openrouter_api_key
    )