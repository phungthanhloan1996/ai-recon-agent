"""
core/session_manager.py - Stateful Scanning with Sessions
Login and maintain sessions for authenticated scanning
"""

import json
import os
import logging
import requests
import time
from typing import Dict, Any

logger = logging.getLogger("recon.session")

class SessionManager:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.session_file = os.path.join(output_dir, "session.json")
        self.cookies = {}
        self.headers = {}
        self.roles = {}
        self._last_saved_payload = None
        self._last_save_ts = 0.0
        self._save_interval = float(os.getenv("SESSION_SAVE_INTERVAL_SECONDS", "5"))

    def login(self, login_url: str, credentials: Dict[str, str]) -> bool:
        """Attempt login and save session"""
        try:
            session = requests.Session()
            response = session.post(login_url, data=credentials, allow_redirects=True, timeout=10)
            
            if response.status_code == 200 and "login" not in response.url.lower():
                self.cookies = dict(session.cookies)
                self.headers = {"Authorization": f"Bearer {self.cookies.get('token', '')}"} if "token" in self.cookies else {}
                self._save_session(force=True)
                logger.info(f"[SESSION] Login successful at {login_url}")
                return True
            else:
                logger.warning(f"[SESSION] Login failed at {login_url}")
                return False
        except Exception as e:
            logger.error(f"[SESSION] Login error: {e}")
            return False

    def get_session_data(self) -> Dict:
        """Get cookies and headers for scanning"""
        return {"cookies": self.cookies, "headers": self.headers}

    def set_role_session(self, role: str, cookies: Dict[str, Any], headers: Dict[str, Any]):
        """Store authenticated session data for a role."""
        self.roles[role] = {"cookies": cookies or {}, "headers": headers or {}}
        self._save_session(force=True)

    def _save_session(self, force: bool = False):
        payload = {"cookies": self.cookies, "headers": self.headers, "roles": self.roles}
        serialized = json.dumps(payload, sort_keys=True, default=str)
        now = time.time()
        if not force:
            if serialized == self._last_saved_payload:
                return
            if now - self._last_save_ts < self._save_interval:
                return

        with open(self.session_file, "w") as f:
            json.dump(payload, f, indent=2)
        self._last_saved_payload = serialized
        self._last_save_ts = now
        logger.info(f"[SESSION] Saved session → {self.session_file}")

    def load_session(self):
        """Load existing session"""
        if os.path.exists(self.session_file):
            with open(self.session_file) as f:
                data = json.load(f)
                self.cookies = data.get("cookies", {})
                self.headers = data.get("headers", {})
                self.roles = data.get("roles", {})
            logger.info("[SESSION] Loaded existing session")

    def update_from_response(self, response: requests.Response):
        """Update session cookies from an HTTP response."""
        if hasattr(response, "cookies") and response.cookies:
            incoming = dict(response.cookies)
            changed = False
            for key, value in incoming.items():
                if self.cookies.get(key) != value:
                    self.cookies[key] = value
                    changed = True
            if changed:
                self._save_session(force=False)
                logger.debug("[SESSION] Updated cookies from response")
