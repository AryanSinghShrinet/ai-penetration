"""
HTTP Request Helper with Retry and Proxy Support
"""

import time
import requests
from functools import wraps

class RequestHelper:
    """
    Wrapper for requests with retry logic and proxy support.
    """
    
    def __init__(self, config=None):
        self.config = config or {}
        self.proxy_config = self.config.get("proxy", {})
        self.retry_config = self.config.get("retry", {})
        
        # Setup proxies
        self.proxies = None
        if self.proxy_config.get("enabled"):
            self.proxies = {
                "http": self.proxy_config.get("http"),
                "https": self.proxy_config.get("https")
            }
        
        # SSL verification
        self.verify_ssl = self.proxy_config.get("verify_ssl", True)
        
        # Retry settings
        self.max_attempts = self.retry_config.get("max_attempts", 3)
        self.backoff_multiplier = self.retry_config.get("backoff_multiplier", 2)
        self.max_delay = self.retry_config.get("max_delay", 30)
    
    def configure_session(self, session):
        """
        Apply proxy and SSL settings to a session.
        """
        if self.proxies:
            session.proxies.update(self.proxies)
        
        session.verify = self.verify_ssl
        
        return session
    
    def request_with_retry(self, session, method, url, **kwargs):
        """
        Make a request with automatic retry on failure.
        """
        last_exception = None
        
        for attempt in range(1, self.max_attempts + 1):
            try:
                # Apply proxy settings if not already in session
                if self.proxies and "proxies" not in kwargs:
                    kwargs["proxies"] = self.proxies
                
                if "verify" not in kwargs:
                    kwargs["verify"] = self.verify_ssl
                
                # Make the request
                response = getattr(session, method.lower())(url, **kwargs)
                
                # Check for server errors that might be temporary
                if response.status_code >= 500 and attempt < self.max_attempts:
                    raise requests.exceptions.RequestException(
                        f"Server error: {response.status_code}"
                    )
                
                return response
                
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.RequestException) as e:
                last_exception = e
                
                if attempt < self.max_attempts:
                    delay = min(
                        self.backoff_multiplier ** (attempt - 1),
                        self.max_delay
                    )
                    time.sleep(delay)
        
        # All retries failed
        raise last_exception
    
    def get(self, session, url, **kwargs):
        """GET request with retry."""
        return self.request_with_retry(session, "GET", url, **kwargs)
    
    def post(self, session, url, **kwargs):
        """POST request with retry."""
        return self.request_with_retry(session, "POST", url, **kwargs)


def create_request_helper(config):
    """Factory function to create request helper."""
    return RequestHelper(config)


def with_retry(max_attempts=3, backoff=2, max_delay=30):
    """
    Decorator to add retry logic to any function.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts:
                        delay = min(backoff ** (attempt - 1), max_delay)
                        time.sleep(delay)
            
            raise last_exception
        return wrapper
    return decorator
