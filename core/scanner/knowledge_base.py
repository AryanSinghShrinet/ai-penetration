"""
Scanner Knowledge Base - Canonical Vulnerability Tracking

REFACTORED: Now uses VulnKey as the primary identification key.
One vulnerability = One VulnKey = One entry

Key improvements:
- VulnKey-based storage (not string keys)
- Evidence upgrade mechanism (higher score replaces lower)
- Scan mode awareness (discovery vs exploitation)
- Clean API for chaining and reporting
"""

import json
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict

from core.scanner.vuln_key import (
    VulnKey,
    Evidence,
    ScanMode,
    normalize_vuln_key,
    generate_poc_id,
    normalize_endpoint,
)


# State persistence directory
SCANNER_STATE_DIR = Path("data/scanner_state")
SCANNER_STATE_DIR.mkdir(parents=True, exist_ok=True)

# Thread lock for concurrent access safety
_KB_LOCK = threading.RLock()


@dataclass
class ConfirmedVuln:
    """A confirmed vulnerability with evidence."""
    vuln_key: VulnKey
    evidence: Evidence
    confirmed_at: str
    poc_id: str
    chains: List[str]  # VulnKey strings that chain from this


@dataclass
class EndpointPattern:
    """Stored pattern for similar endpoint behavior."""
    pattern: str
    framework: str
    behaviors: List[str]


class ScannerKnowledgeBase:
    """
    Canonical Vulnerability Knowledge Base.
    
    SINGLE SOURCE OF TRUTH for vulnerability confirmation.
    Uses VulnKey as the primary identification key.
    
    Golden Rule: One vulnerability = One VulnKey
    """
    
    # Memory limit for executed payloads tracking
    MAX_EXECUTED_TRACKING = 10000
    
    def __init__(self, run_id: str):
        """Initialize knowledge base for a scan run."""
        self.run_id = run_id
        self.state_file = SCANNER_STATE_DIR / f"{run_id}_kb.json"
        
        # Primary storage: VulnKey -> ConfirmedVuln
        self._confirmed_vulns: Dict[VulnKey, ConfirmedVuln] = {}
        
        # Secondary storage (legacy compatibility)
        self._endpoint_patterns: Dict[str, EndpointPattern] = {}
        self._executed_payloads: Set[str] = set()
        self._param_test_counts: Dict[str, int] = {}
        
        # Current scan mode
        self._scan_mode: ScanMode = ScanMode.DISCOVERY
        
        # Load existing state
        self._load_state()
    
    # =========================================================================
    # SCAN MODE CONTROL
    # =========================================================================
    
    def set_scan_mode(self, mode: ScanMode) -> None:
        """Set the current scan mode."""
        with _KB_LOCK:
            self._scan_mode = mode
    
    def get_scan_mode(self) -> ScanMode:
        """Get the current scan mode."""
        with _KB_LOCK:
            return self._scan_mode
    
    # =========================================================================
    # CANONICAL VULNERABILITY API (PRIMARY)
    # =========================================================================
    
    def is_vuln_confirmed(self, vuln_key: VulnKey) -> bool:
        """
        Check if a vulnerability has been confirmed.
        
        THIS IS THE CANONICAL CHECK.
        
        Args:
            vuln_key: Normalized VulnKey
        
        Returns:
            True if confirmed (STOP discovery payloads)
        """
        with _KB_LOCK:
            return vuln_key in self._confirmed_vulns
    
    def confirm_vulnerability(
        self,
        vuln_key: VulnKey,
        evidence: Evidence,
        chains: Optional[List[str]] = None
    ) -> bool:
        """
        Confirm a vulnerability with evidence.
        
        Evidence Upgrade Logic:
        - If vuln not confirmed: Add it
        - If vuln confirmed with lower score: Upgrade evidence
        - If vuln confirmed with higher score: Keep existing
        
        Args:
            vuln_key: Normalized VulnKey
            evidence: Evidence object with score
            chains: Optional list of chained VulnKey strings
        
        Returns:
            True if this was a new confirmation or upgrade
        """
        with _KB_LOCK:
            existing = self._confirmed_vulns.get(vuln_key)
            
            if not existing:
                # New confirmation
                self._confirmed_vulns[vuln_key] = ConfirmedVuln(
                    vuln_key=vuln_key,
                    evidence=evidence,
                    confirmed_at=datetime.utcnow().isoformat(),
                    poc_id=generate_poc_id(vuln_key),
                    chains=chains or []
                )
                self._save_state()
                return True
            
            elif evidence.score > existing.evidence.score:
                # Upgrade evidence (stronger proof found)
                self._confirmed_vulns[vuln_key] = ConfirmedVuln(
                    vuln_key=vuln_key,
                    evidence=evidence,
                    confirmed_at=existing.confirmed_at,  # Keep original time
                    poc_id=existing.poc_id,  # Keep same POC ID
                    chains=existing.chains + (chains or [])
                )
                self._save_state()
                return True
            
            else:
                # Existing evidence is stronger, add chains only
                if chains:
                    existing.chains.extend(chains)
                    self._save_state()
                return False
    
    def get_confirmed_vuln(self, vuln_key: VulnKey) -> Optional[ConfirmedVuln]:
        """Get the confirmed vulnerability record for a VulnKey."""
        with _KB_LOCK:
            return self._confirmed_vulns.get(vuln_key)
    
    def get_all_confirmed_vulns(self) -> List[ConfirmedVuln]:
        """Get all confirmed vulnerabilities."""
        with _KB_LOCK:
            return list(self._confirmed_vulns.values())
    
    def should_scan(self, vuln_key: VulnKey) -> Tuple[bool, str]:
        """
        Determine if scanning should proceed for this VulnKey.
        
        Decision logic based on scan mode:
        - DISCOVERY: Skip if vuln confirmed
        - EXPLOITATION: Allow if vuln confirmed
        - CHAINING: Allow if vuln confirmed
        
        Returns:
            Tuple of (should_scan: bool, reason: str)
        """
        with _KB_LOCK:
            is_confirmed = vuln_key in self._confirmed_vulns
            mode = self._scan_mode
            
            if mode == ScanMode.DISCOVERY:
                if is_confirmed:
                    return False, f"Vuln already confirmed: {vuln_key}"
                return True, ""
            
            elif mode in (ScanMode.EXPLOITATION, ScanMode.CHAINING):
                # In exploitation/chaining mode, we want confirmed vulns
                if is_confirmed:
                    return True, ""
                return False, f"Vuln not confirmed for exploitation: {vuln_key}"
            
            return True, ""
    
    # =========================================================================
    # LEGACY API (for backward compatibility)
    # =========================================================================
    
    def is_param_vulnerable(self, endpoint: str, param: str, location: str) -> bool:
        """Legacy API - Check if parameter has confirmed vuln."""
        # Build a VulnKey with empty vuln_type to check any vuln
        normalized_endpoint = normalize_endpoint(endpoint)
        with _KB_LOCK:
            for vk in self._confirmed_vulns.keys():
                if (vk.endpoint == normalized_endpoint and 
                    vk.parameter == param.lower() and
                    vk.parameter_location == location.lower()):
                    return True
            return False
    
    def mark_param_vulnerable(
        self,
        endpoint: str,
        param: str,
        location: str,
        vuln_type: str,
        payload: str = "",
        evidence: Optional[Dict] = None,
        confidence: float = 1.0
    ) -> None:
        """Legacy API - Mark parameter as vulnerable."""
        vuln_key = normalize_vuln_key(
            method="GET",  # Default for legacy
            url=endpoint,
            param=param,
            param_location=location,
            vuln_type=vuln_type
        )
        
        evidence_obj = Evidence(
            payload=payload,
            response_snippet=str(evidence) if evidence else "",
            score=int(confidence * 100),
            confidence="high" if confidence >= 0.7 else "medium" if confidence >= 0.4 else "low"
        )
        
        self.confirm_vulnerability(vuln_key, evidence_obj)
    
    def should_skip_param(self, endpoint: str, param: str, location: str) -> Tuple[bool, str]:
        """Legacy API - Check if param should be skipped."""
        if self.is_param_vulnerable(endpoint, param, location):
            return True, "Already confirmed vulnerable"
        return False, ""
    
    def get_confirmed_vulns(self) -> List[ConfirmedVuln]:
        """Get all confirmed vulnerabilities (alias)."""
        return self.get_all_confirmed_vulns()
    
    # =========================================================================
    # PAYLOAD TRACKING
    # =========================================================================
    
    def was_payload_executed(self, endpoint: str, param: str, payload: str) -> bool:
        """Check if payload was already executed."""
        with _KB_LOCK:
            key = f"{normalize_endpoint(endpoint)}|{param}|{hash(payload) % 10000000}"
            return key in self._executed_payloads
    
    def record_payload_executed(self, endpoint: str, param: str, payload: str) -> None:
        """Record that a payload was executed."""
        with _KB_LOCK:
            key = f"{normalize_endpoint(endpoint)}|{param}|{hash(payload) % 10000000}"
            
            # Memory limit check
            if len(self._executed_payloads) >= self.MAX_EXECUTED_TRACKING:
                # Prune oldest half
                items = list(self._executed_payloads)
                self._executed_payloads = set(items[len(items)//2:])
            
            self._executed_payloads.add(key)
    
    def increment_param_test_count(self, endpoint: str, param: str, location: str) -> int:
        """Increment and return the test count for a parameter."""
        with _KB_LOCK:
            key = f"{normalize_endpoint(endpoint)}|{param}|{location}"
            self._param_test_counts[key] = self._param_test_counts.get(key, 0) + 1
            return self._param_test_counts[key]
    
    def get_param_test_count(self, endpoint: str, param: str, location: str) -> int:
        """Get the current test count for a parameter."""
        with _KB_LOCK:
            key = f"{normalize_endpoint(endpoint)}|{param}|{location}"
            return self._param_test_counts.get(key, 0)
    
    # =========================================================================
    # EXPORT FOR POC GENERATOR & REPORTING
    # =========================================================================
    
    def export_for_exploitation(self) -> List[Dict]:
        """Export confirmed vulns in clean format for POC generation."""
        with _KB_LOCK:
            return [
                {
                    "poc_id": cv.poc_id,
                    "method": cv.vuln_key.method,
                    "endpoint": cv.vuln_key.endpoint,
                    "param": cv.vuln_key.parameter,
                    "location": cv.vuln_key.parameter_location,
                    "vuln_type": cv.vuln_key.vuln_type,
                    "payload": cv.evidence.payload,
                    "confidence": cv.evidence.confidence,
                    "score": cv.evidence.score,
                    "chains": cv.chains,
                }
                for cv in self._confirmed_vulns.values()
            ]
    
    def get_stats(self) -> Dict:
        """Get knowledge base statistics."""
        with _KB_LOCK:
            vulns_by_type = {}
            for cv in self._confirmed_vulns.values():
                vt = cv.vuln_key.vuln_type
                vulns_by_type[vt] = vulns_by_type.get(vt, 0) + 1
            
            return {
                "confirmed_vulns_count": len(self._confirmed_vulns),
                "executed_payloads_count": len(self._executed_payloads),
                "vulns_by_type": vulns_by_type,
                "scan_mode": self._scan_mode.value,
            }
    
    # =========================================================================
    # PERSISTENCE
    # =========================================================================
    
    def _load_state(self) -> None:
        """Load persisted state from disk."""
        with _KB_LOCK:
            if self.state_file.exists():
                try:
                    data = json.loads(self.state_file.read_text(encoding='utf-8'))
                    
                    # Restore confirmed vulns (convert dicts back to objects)
                    for vk_str, cv_data in data.get("confirmed_vulns", {}).items():
                        vk_parts = cv_data.get("vuln_key", {})
                        vuln_key = VulnKey(
                            method=vk_parts.get("method", "GET"),
                            endpoint=vk_parts.get("endpoint", ""),
                            parameter=vk_parts.get("parameter", ""),
                            parameter_location=vk_parts.get("parameter_location", "query"),
                            vuln_type=vk_parts.get("vuln_type", "")
                        )
                        
                        ev_data = cv_data.get("evidence", {})
                        evidence = Evidence(
                            payload=ev_data.get("payload", ""),
                            response_snippet=ev_data.get("response_snippet", ""),
                            score=ev_data.get("score", 50),
                            confidence=ev_data.get("confidence", "medium")
                        )
                        
                        self._confirmed_vulns[vuln_key] = ConfirmedVuln(
                            vuln_key=vuln_key,
                            evidence=evidence,
                            confirmed_at=cv_data.get("confirmed_at", ""),
                            poc_id=cv_data.get("poc_id", generate_poc_id(vuln_key)),
                            chains=cv_data.get("chains", [])
                        )
                    
                    self._executed_payloads = set(data.get("executed_payloads", []))
                    self._param_test_counts = data.get("param_test_counts", {})
                    
                except Exception as e:
                    print(f"[KB] Warning: Could not load state: {e}. Starting fresh.")
    
    def _save_state(self) -> None:
        """Persist state to disk atomically."""
        with _KB_LOCK:
            # Serialize confirmed vulns
            vulns_data = {}
            for vk, cv in self._confirmed_vulns.items():
                key_str = str(vk)
                vulns_data[key_str] = {
                    "vuln_key": vk.to_dict(),
                    "evidence": cv.evidence.to_dict(),
                    "confirmed_at": cv.confirmed_at,
                    "poc_id": cv.poc_id,
                    "chains": cv.chains,
                }
            
            data = {
                "run_id": self.run_id,
                "updated_at": datetime.utcnow().isoformat(),
                "confirmed_vulns": vulns_data,
                "executed_payloads": list(self._executed_payloads)[:1000],  # Limit size
                "param_test_counts": self._param_test_counts,
            }
            
            # Atomic write
            temp_file = self.state_file.with_suffix('.tmp')
            temp_file.write_text(json.dumps(data, indent=2), encoding='utf-8')
            temp_file.replace(self.state_file)
