"""
ai/groq_client.py - Enhanced Groq API Client
With circuit breaker, exponential backoff, and rate limiting
"""

import time
import random
import logging
import urllib.request
import urllib.error
import json as json_module
from typing import Optional, Dict, Any
from enum import Enum

logger = logging.getLogger("recon.groq_client")


class CircuitState(Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing, reject requests
    HALF_OPEN = "half_open" # Testing if service recovered


class GroqClient:
    """
    Enhanced Groq API client with:
    - Circuit breaker pattern for 429 errors
    - Exponential backoff with jitter
    - Global rate limiting
    - Fallback to static templates when circuit is open
    """

    # ─── CIRCUIT BREAKER CONFIGURATION ──────────────────────────────────────────
    FAILURE_THRESHOLD = 3           # Number of failures before opening circuit
    SUCCESS_THRESHOLD = 2           # Number of successes to close circuit
    INITIAL_BACKOFF = 1.0           # Initial backoff in seconds
    MAX_BACKOFF = 120.0             # Maximum backoff (2 minutes)
    BACKOFF_MULTIPLIER = 2.0        # Multiplier for exponential backoff
    JITTER_RANGE = 0.5              # Random jitter range (0-0.5 seconds)

    # ─── RATE LIMITING CONFIGURATION ────────────────────────────────────────────
    MAX_CALLS_PER_MINUTE = 10       # Global rate limit
    MIN_CALL_INTERVAL = 1.0         # Minimum seconds between calls

    # ─── STATIC FALLBACK PAYLOADS ───────────────────────────────────────────────
    # Used when circuit is open to avoid calling Groq
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

    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model = model
        
        # Circuit breaker state
        self._circuit_state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = 0.0
        self._current_backoff = self.INITIAL_BACKOFF
        
        # Rate limiting state
        self._call_timestamps = []
        self._last_call_time = 0.0
        
        # Statistics for monitoring
        self._total_calls = 0
        self._total_failures = 0
        self._total_fallbacks = 0

    def generate(self, prompt: str, system: str = None, temperature: float = 0.3) -> str:
        """
        Generate response from Groq API with circuit breaker protection.
        
        Returns fallback content if circuit is open.
        """
        # Check circuit breaker
        if self._circuit_state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self._circuit_state = CircuitState.HALF_OPEN
                logger.info("[GROQ] Circuit breaker half-open, attempting reset")
            else:
                self._total_fallbacks += 1
                logger.warning(f"[GROQ] Circuit open, using fallback. Fallbacks: {self._total_fallbacks}")
                return self._get_fallback_response(prompt)
        
        # Apply rate limiting
        self._enforce_rate_limit()
        
        # Attempt API call with retries
        return self._call_with_retry(prompt, system, temperature)

    def _call_with_retry(self, prompt: str, system: str, temperature: float, 
                         max_retries: int = 3) -> str:
        """Call Groq API with exponential backoff and retries."""
        last_error = None
        
        for attempt in range(max_retries):
            try:
                response = self._make_api_call(prompt, system, temperature)
                self._on_success()
                return response
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    # 403 Forbidden - API key invalid or expired
                    logger.error(f"[GROQ] API key rejected (403 Forbidden). Disabling AI features.")
                    self._circuit_state = CircuitState.OPEN
                    self._current_backoff = self.MAX_BACKOFF  # Long backoff for auth failures
                    self._total_fallbacks += 1
                    return self._get_fallback_response(prompt)
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
        self._total_fallbacks += 1
        logger.warning(f"[GROQ] All retries exhausted, using fallback")
        return self._get_fallback_response(prompt)

    def _make_api_call(self, prompt: str, system: str, temperature: float) -> str:
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
            "temperature": temperature
        }

        payload = json_module.dumps(data).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        
        with urllib.request.urlopen(req, timeout=30) as resp:
            response_data = json_module.loads(resp.read().decode("utf-8"))
            return response_data["choices"][0]["message"]["content"]

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
        """Handle successful API call."""
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
        """Handle failed API call."""
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
        """Enforce global rate limiting."""
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
        """Generate fallback response when Groq is unavailable."""
        prompt_lower = prompt.lower()
        
        # Try to detect vulnerability type from prompt
        for vuln_type, payloads in self.FALLBACK_PAYLOADS.items():
            if vuln_type in prompt_lower:
                return json_module.dumps({
                    "payloads": payloads,
                    "source": "fallback",
                    "note": "Generated from static templates (Groq unavailable)"
                })
        
        # Generic fallback
        return json_module.dumps({
            "payloads": ["' OR '1'='1", "<script>alert(1)</script>"],
            "source": "fallback",
            "note": "Generic fallback payloads (Groq unavailable)"
        })

    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status and statistics."""
        return {
            "circuit_state": self._circuit_state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "current_backoff": self._current_backoff,
            "total_calls": self._total_calls,
            "total_failures": self._total_failures,
            "total_fallbacks": self._total_fallbacks,
            "rate_limit_calls_last_minute": len(self._call_timestamps),
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