"""
Session Manager for AI-Pentester
Handles authentication, token refresh, and session persistence.
"""

import requests
import time
import yaml
from pathlib import Path

class SessionManager:
    """
    Manages authenticated sessions with automatic refresh capabilities.
    """
    
    def __init__(self, auth_config_path="config/auth.yaml"):
        self.auth_config = self._load_auth_config(auth_config_path)
        self.session = None
        self.token = None
        self.token_expiry = None
        self.last_auth_time = None
        self.max_session_age = 3600  # 1 hour default
        self._init_session()
    
    def _load_auth_config(self, path):
        """Load authentication configuration."""
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as _e:
            return {}
    
    def _init_session(self):
        """Initialize a new requests session."""
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AI-Bounty-Tester/1.0"
        })
        
        if self.auth_config.get("enabled"):
            self._authenticate()
    
    def _authenticate(self):
        """
        Perform authentication based on config type.
        Supports: bearer, basic, cookie, api_key
        """
        auth_type = self.auth_config.get("type", "none")
        
        if auth_type == "bearer":
            token = self.auth_config.get("token")
            if token:
                self.session.headers["Authorization"] = f"Bearer {token}"
                self.token = token
                
        elif auth_type == "basic":
            username = self.auth_config.get("username")
            password = self.auth_config.get("password")
            if username and password:
                self.session.auth = (username, password)
                
        elif auth_type == "cookie":
            cookies = self.auth_config.get("cookies", {})
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
                
        elif auth_type == "api_key":
            key_name = self.auth_config.get("key_name", "X-API-Key")
            key_value = self.auth_config.get("key_value")
            if key_value:
                self.session.headers[key_name] = key_value
                
        elif auth_type == "login":
            # Perform login request
            login_url = self.auth_config.get("login_url")
            login_data = self.auth_config.get("login_data", {})
            if login_url:
                try:
                    resp = self.session.post(login_url, data=login_data, timeout=30)
                    if resp.status_code == 200:
                        # Extract token if in response
                        if "token" in resp.json():
                            self.token = resp.json()["token"]
                            self.session.headers["Authorization"] = f"Bearer {self.token}"
                except Exception as _e:
                    import logging; logging.getLogger(__name__).debug(f'[session_manager] token extract error: {_e}')
        
        self.last_auth_time = time.time()
    
    def needs_refresh(self):
        """Check if session needs to be refreshed."""
        if not self.last_auth_time:
            return True
            
        age = time.time() - self.last_auth_time
        
        # Check token expiry if set
        if self.token_expiry and time.time() >= self.token_expiry:
            return True
            
        # Check max session age
        if age > self.max_session_age:
            return True
            
        return False
    
    def refresh(self):
        """Refresh the session/token."""
        refresh_url = self.auth_config.get("refresh_url")
        
        if refresh_url and self.token:
            try:
                resp = self.session.post(refresh_url, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    if "token" in data:
                        self.token = data["token"]
                        self.session.headers["Authorization"] = f"Bearer {self.token}"
                        self.last_auth_time = time.time()
                        return True
            except Exception as _e:
                import logging; logging.getLogger(__name__).debug(f'[session_manager] re-auth error: {_e}')
        
        # Fallback: re-authenticate
        self._init_session()
        return True
    
    def get_session(self):
        """Get the current session, refreshing if needed."""
        if self.needs_refresh():
            self.refresh()
        return self.session
    
    def is_auth_valid(self, response):
        """
        Check if response indicates valid authentication.
        """
        # Unauthorized responses
        if response.status_code in (401, 403):
            return False
        
        # Common login page indicators
        login_indicators = [
            "login", "sign in", "signin", "log in",
            "authentication required", "session expired"
        ]
        
        text_lower = response.text.lower()
        
        # Short response with login indicator = likely redirected to login
        if len(response.text) < 5000:
            for indicator in login_indicators:
                if indicator in text_lower:
                    return False
        
        return True
    
    def handle_auth_failure(self, logger=None):
        """Handle authentication failure by refreshing."""
        if logger:
            logger.warning("[SessionManager] Auth failure detected, refreshing session...")
        
        success = self.refresh()
        
        if logger:
            if success:
                logger.info("[SessionManager] Session refreshed successfully")
            else:
                logger.error("[SessionManager] Failed to refresh session")
        
        return success


def create_managed_session(auth_config_path="config/auth.yaml"):
    """Factory function to create a managed session."""
    return SessionManager(auth_config_path)
