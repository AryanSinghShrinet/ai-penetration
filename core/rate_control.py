"""
Rate Controller with Persistence for AI-Pentester

KEY FIX: Cooldowns are now keyed on (endpoint, vuln_type) not just endpoint.
A blocked SQLi payload no longer stops XSS testing on the same URL.
Global backoff only triggers on 429/503 (true rate limiting), not 403.
"""

import time
import json
import sqlite3
import threading
import os
from pathlib import Path
from collections import defaultdict

try:
    import psycopg2
except ImportError:
    psycopg2 = None


class RateController:
    """
    Rate controller with per-(endpoint, vuln_type) cooldowns.

    Previous behaviour: one blocked response on /api/users stopped ALL further
    testing of /api/users for `per_ep_cooldown` seconds — regardless of vuln type.
    That meant a blocked SQLi payload silently killed XSS, CORS, IDOR, SSRF tests
    on the same endpoint.

    New behaviour:
      - Cooldown key = (endpoint, vuln_type)  → independent per vuln type
      - Global backoff ONLY on true WAF signals (429, 503, Retry-After)
      - 403 is normal app behaviour → never triggers backoff
    """

    def close(self):
        conn = getattr(self._local, "conn", None)
        if conn:
            try:
                conn.close()
            except Exception as _e:
                import logging; logging.getLogger(__name__).debug(f'[rate_control] close: {_e}')
            self._local.conn = None

    def __init__(self, rps, per_ep_cooldown, max_requests, backoff, persist_path=None):
        self.min_interval   = 1 / max(rps, 1)
        self.per_ep_cooldown = per_ep_cooldown
        self.max_requests   = max_requests
        self.backoff        = backoff

        self.last_request_ts = 0.0
        # KEY CHANGE: keyed on (endpoint, vuln_type) — str representation
        self.last_ep_ts     = defaultdict(float)
        self.request_count  = 0
        self.paused_until   = 0.0

        self._lock  = threading.RLock()
        self._local = threading.local()

        self.persist_path = persist_path or "data/rate_state.db"
        self._init_persistence()
        import atexit as _ae; _ae.register(self.close)

    # ── persistence ──────────────────────────────────────────────────────────

    def _is_postgres(self):
        url = os.environ.get("DATABASE_URL")
        return url is not None and url.startswith("postgres") and psycopg2 is not None

    def _get_connection(self):
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            if self._is_postgres():
                db_url = os.environ.get("DATABASE_URL")
                self._local.conn = psycopg2.connect(db_url)
            else:
                db_path = Path(self.persist_path)
                db_path.parent.mkdir(parents=True, exist_ok=True)
                self._local.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        return self._local.conn

    def _init_persistence(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        
        if self._is_postgres():
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rate_state (
                    key TEXT PRIMARY KEY, value REAL, updated_at REAL
                )""")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS endpoint_state (
                    endpoint TEXT PRIMARY KEY, last_request REAL, request_count INTEGER
                )""")
        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rate_state (
                    key TEXT PRIMARY KEY, value REAL, updated_at REAL
                )""")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS endpoint_state (
                    endpoint TEXT PRIMARY KEY, last_request REAL, request_count INTEGER
                )""")
        conn.commit()
        if hasattr(cursor, 'close'): cursor.close()
        self._load_state()

    def _load_state(self):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM rate_state")
            for key, value in cursor.fetchall():
                if key == "request_count": self.request_count = int(value)
                elif key == "paused_until": self.paused_until = value
                elif key == "last_request_ts": self.last_request_ts = value
                
            cursor.execute("SELECT endpoint, last_request FROM endpoint_state")
            for ep, last in cursor.fetchall():
                self.last_ep_ts[ep] = last
            if hasattr(cursor, 'close'): cursor.close()
        except Exception as _e:
            pass

    def _save_state(self):
        try:
            now = time.time()
            conn = self._get_connection()
            cursor = conn.cursor()
            with self._lock:
                for k, v in [("request_count", self.request_count),
                              ("paused_until", self.paused_until),
                              ("last_request_ts", self.last_request_ts)]:
                    if self._is_postgres():
                        cursor.execute(
                            "INSERT INTO rate_state (key,value,updated_at) VALUES(%s,%s,%s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
                            (k, v, now))
                    else:
                        cursor.execute(
                            "INSERT OR REPLACE INTO rate_state (key,value,updated_at) VALUES(?,?,?)",
                            (k, v, now))
                conn.commit()
            if hasattr(cursor, 'close'): cursor.close()
        except Exception as _e:
            pass

    def _save_endpoint_state(self, ep_key):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            with self._lock:
                if self._is_postgres():
                    cursor.execute(
                        "INSERT INTO endpoint_state (endpoint,last_request,request_count) VALUES(%s,%s,%s) ON CONFLICT (endpoint) DO UPDATE SET last_request = EXCLUDED.last_request",
                        (ep_key, self.last_ep_ts[ep_key], 1))
                else:
                    cursor.execute(
                        "INSERT OR REPLACE INTO endpoint_state (endpoint,last_request,request_count) VALUES(?,?,?)",
                        (ep_key, self.last_ep_ts[ep_key], 1))
                conn.commit()
            if hasattr(cursor, 'close'): cursor.close()
        except Exception as _e:
            pass
    # ── core API ─────────────────────────────────────────────────────────────

    @staticmethod
    def _ep_key(endpoint: str, vuln_type: str = "") -> str:
        """Cooldown key — per (endpoint, vuln_type) pair."""
        return f"{endpoint}::{vuln_type}" if vuln_type else endpoint

    def can_request(self, endpoint, logger=None, vuln_type: str = ""):
        now = time.time()
        ep_key = self._ep_key(endpoint, vuln_type)

        with self._lock:
            # Global backoff (only from true WAF signals)
            if now < self.paused_until:
                remaining = int(self.paused_until - now)
                if logger:
                    logger.warning(f"RateController: global backoff active ({remaining}s remaining)")
                return False, "PAUSED_BACKOFF"

            if self.request_count >= self.max_requests:
                if logger:
                    logger.warning("RateController: max requests per run reached")
                return False, "BUDGET_EXHAUSTED"

            # Per-(endpoint, vuln_type) cooldown
            if now - self.last_ep_ts[ep_key] < self.per_ep_cooldown:
                if logger:
                    logger.debug(f"RateController: cooldown active for {ep_key}")
                return False, "ENDPOINT_COOLDOWN"

        return True, "OK"

    def before_request(self, endpoint, logger=None, vuln_type: str = ""):
        ep_key = self._ep_key(endpoint, vuln_type)
        # Honour global min interval
        now = time.time()
        delta = now - self.last_request_ts
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)

        with self._lock:
            self.last_request_ts = time.time()
            self.last_ep_ts[ep_key] = self.last_request_ts
            self.request_count += 1

        self._save_state()
        self._save_endpoint_state(ep_key)

        if logger:
            logger.debug(f"RateController: request #{self.request_count} [{vuln_type}] {endpoint}")

    def on_block(self, logger=None, response=None):
        """
        Trigger global backoff ONLY for genuine WAF signals.
        403 Forbidden is normal app behaviour — never triggers global backoff.
        """
        if response is not None:
            # Only back off on true rate-limit/WAF signals
            if response.status_code not in (429, 503):
                if logger:
                    logger.debug(
                        f"RateController: HTTP {response.status_code} — "
                        "not a WAF signal, skipping global backoff"
                    )
                return
        with self._lock:
            self.paused_until = time.time() + self.backoff
        self._save_state()
        if logger:
            logger.warning(f"RateController: global backoff {self.backoff}s (genuine WAF/rate-limit)")

    def reset(self, logger=None):
        with self._lock:
            self.request_count = 0
            self.paused_until  = 0.0
            self.last_request_ts = 0.0
            self.last_ep_ts.clear()
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM rate_state")
            cursor.execute("DELETE FROM endpoint_state")
            conn.commit()
            if hasattr(cursor, 'close'): cursor.close()
        except Exception as _e:
            import logging; logging.getLogger(__name__).debug(f'[rate_control] db reset: {_e}')
        if logger:
            logger.info("RateController: state reset")

    def get_stats(self):
        with self._lock:
            return {
                "request_count":    self.request_count,
                "max_requests":     self.max_requests,
                "remaining":        self.max_requests - self.request_count,
                "is_paused":        time.time() < self.paused_until,
                "endpoints_tracked": len(self.last_ep_ts),
            }
