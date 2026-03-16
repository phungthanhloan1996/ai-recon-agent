"""
core/session_manager.py - Stateful Scanning with Sessions
Login and maintain sessions for authenticated scanning
"""

import json
import os
import logging
import requests
from typing import Dict

logger = logging.getLogger("recon.session")

class SessionManager:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.session_file = os.path.join(output_dir, "session.json")
        self.cookies = {}
        self.headers = {}

    def login(self, login_url: str, credentials: Dict[str, str]) -> bool:
        """Attempt login and save session"""
        try:
            session = requests.Session()
            response = session.post(login_url, data=credentials, allow_redirects=True, timeout=10)
            
            if response.status_code == 200 and "login" not in response.url.lower():
                self.cookies = dict(session.cookies)
                self.headers = {"Authorization": f"Bearer {self.cookies.get('token', '')}"} if "token" in self.cookies else {}
                self._save_session()
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

    def _save_session(self):
        with open(self.session_file, "w") as f:
            json.dump({"cookies": self.cookies, "headers": self.headers}, f, indent=2)
        logger.info(f"[SESSION] Saved session → {self.session_file}")

    def load_session(self):
        """Load existing session"""
        if os.path.exists(self.session_file):
            with open(self.session_file) as f:
                data = json.load(f)
                self.cookies = data.get("cookies", {})
                self.headers = data.get("headers", {})
            logger.info("[SESSION] Loaded existing session")