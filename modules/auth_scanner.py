"""
modules/auth_scanner.py - Authenticated Scanning Engine
Attempts multi-role authentication and stores session artifacts.
"""

import json
import logging
import os
from typing import Dict, List, Any

from core.http_engine import HTTPClient
from core.state_manager import StateManager
from core.session_manager import SessionManager

logger = logging.getLogger("recon.auth")


class AuthScannerEngine:
    """
    Multi-role authenticated scanning bootstrap.

    auth_file schema:
    {
      "roles": [
        {
          "role": "admin",
          "login_url": "https://target/wp-login.php",
          "method": "POST",
          "username_field": "log",
          "password_field": "pwd",
          "username": "admin",
          "password": "secret",
          "success_indicators": ["wp-admin", "dashboard"]
        }
      ]
    }
    """

    def __init__(self, state: StateManager, output_dir: str, session: SessionManager):
        self.state = state
        self.output_dir = output_dir
        self.session = session
        self.http_client = HTTPClient(session)
        self.auth_results_file = os.path.join(output_dir, "auth_sessions.json")

    def run(self, auth_file: str) -> List[Dict[str, Any]]:
        if not auth_file:
            return []
        if not os.path.exists(auth_file):
            logger.warning(f"[AUTH] Auth file not found: {auth_file}")
            return []

        try:
            with open(auth_file, "r") as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"[AUTH] Failed to parse auth file: {e}")
            return []

        roles = data.get("roles", [])
        results = []
        for role_cfg in roles:
            result = self._login_role(role_cfg)
            results.append(result)

        with open(self.auth_results_file, "w") as f:
            json.dump(results, f, indent=2)

        self.state.update(authenticated_sessions=results)
        return results

    def _login_role(self, role_cfg: Dict[str, Any]) -> Dict[str, Any]:
        role_name = role_cfg.get("role", "unknown")
        login_url = role_cfg.get("login_url", "")
        method = role_cfg.get("method", "POST").upper()
        username_field = role_cfg.get("username_field", "username")
        password_field = role_cfg.get("password_field", "password")
        success_indicators = [s.lower() for s in role_cfg.get("success_indicators", [])]

        payload = {
            username_field: role_cfg.get("username", ""),
            password_field: role_cfg.get("password", ""),
        }

        result = {
            "role": role_name,
            "login_url": login_url,
            "success": False,
            "status_code": 0,
            "reason": "",
            "cookies": {},
            "headers": {},
        }

        if not login_url:
            result["reason"] = "missing_login_url"
            return result

        try:
            if method == "POST":
                response = self.http_client.post(login_url, data=payload, timeout=15)
            else:
                response = self.http_client.get(login_url, params=payload, timeout=15)

            body = response.text.lower()
            result["status_code"] = response.status_code
            result["cookies"] = dict(response.cookies)

            auth_success = response.status_code in (200, 302, 303)
            if success_indicators:
                auth_success = auth_success and any(i in body or i in response.url.lower() for i in success_indicators)

            result["success"] = bool(auth_success)
            if auth_success:
                self.session.set_role_session(role_name, result["cookies"], {})
                logger.info(f"[AUTH] Role '{role_name}' authenticated")
            else:
                result["reason"] = "indicator_mismatch_or_login_failed"
                logger.warning(f"[AUTH] Role '{role_name}' failed")

        except Exception as e:
            result["reason"] = str(e)
            logger.error(f"[AUTH] Role '{role_name}' error: {e}")

        return result
