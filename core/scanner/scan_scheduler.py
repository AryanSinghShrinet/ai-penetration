"""
Scan Scheduler - Canonical Vulnerability-Centric Scanning

REFACTORED: Now uses VulnKey for canonical decision-making.

Decision logic:
- "Is this vulnerability confirmed?" (NOT "Did I try this payload?")
- One VulnKey = One vulnerability = Skip all discovery payloads after confirmed

Rules enforced:
1. endpoint_must_be_in_scope
2. method_must_be_safe_to_attack
3. skip_if_vuln_confirmed (CANONICAL - uses VulnKey)
4. max_payloads_per_param (storm prevention)
"""

from typing import Tuple, Optional, Dict, List, Set
from dataclasses import dataclass
from enum import Enum

from core.scope import is_url_in_scope
from core.scanner.knowledge_base import ScannerKnowledgeBase
from core.scanner.attack_surface import InjectionPoint
from core.scanner.vuln_key import (
    VulnKey,
    Evidence,
    ScanMode,
    normalize_vuln_key,
    calculate_evidence_score,
    determine_confidence,
)


class SkipReason(Enum):
    """Reasons why scanning might be skipped."""
    NONE = "none"
    OUT_OF_SCOPE = "out_of_scope"
    UNSAFE_METHOD = "unsafe_method"
    NOT_INJECTABLE = "not_injectable"
    ALREADY_VULNERABLE = "already_vulnerable"
    MAX_TESTS_REACHED = "max_tests_reached"
    PAYLOAD_ALREADY_SENT = "payload_already_sent"
    PRECONDITIONS_NOT_MET = "preconditions_not_met"


@dataclass
class ScanDecision:
    """Result of a scan scheduling decision."""
    should_scan: bool
    skip_reason: SkipReason
    reason_detail: str
    
    @property
    def is_allowed(self) -> bool:
        return self.should_scan


class ScanScheduler:
    """
    Controls when and what to scan, enforcing all safety rules.
    
    This scheduler is the gatekeeper for active scanning. Every payload
    execution must pass through the scheduler's should_scan() method.
    """
    
    # Methods that are generally safe to test
    SAFE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
    
    # Methods that could be destructive - require extra caution
    DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH"}
    
    # Maximum payloads per parameter (prevent scan storms per-param)
    # REDUCED from 50 to 20 for tighter control
    MAX_PAYLOADS_PER_PARAM = 20
    
    # Maximum TOTAL payloads across all params (global storm prevention)
    MAX_TOTAL_PAYLOADS = 500
    
    def __init__(
        self,
        knowledge_base: ScannerKnowledgeBase,
        logger=None,
        allow_dangerous_methods: bool = False
    ):
        """
        Initialize the scan scheduler.
        
        Args:
            knowledge_base: Scanner knowledge base for state tracking
            logger: Optional logger instance
            allow_dangerous_methods: Whether to allow DELETE/PUT testing
        """
        self.kb = knowledge_base
        self.logger = logger
        self.allow_dangerous_methods = allow_dangerous_methods
        
        # Track payloads sent per parameter this run
        self._param_payload_counts: Dict[str, int] = {}
    
    def should_scan(
        self,
        endpoint: str,
        param: str,
        location: str,
        vuln_type: str,
        payload: str = "",
        method: str = "GET",
        injection_point: Optional[InjectionPoint] = None
    ) -> ScanDecision:
        """
        Determine if a scan should proceed.
        
        This is the MAIN ENTRY POINT for scan scheduling.
        All active scanning MUST call this before execution.
        
        Args:
            endpoint: Target URL
            param: Parameter name
            location: Parameter location (query, body, header, cookie)
            vuln_type: Vulnerability type being tested
            payload: Specific payload (for duplicate check)
            method: HTTP method
            injection_point: Optional InjectionPoint for context
        
        Returns:
            ScanDecision indicating whether to proceed
        """
        # RULE 1: Scope check (using existing scope module)
        # Create a dummy logger if none provided for scope check
        class DummyLogger:
            def debug(self, msg): pass
            def info(self, msg): pass
            def warning(self, msg): pass
            def error(self, msg): pass
        
        scope_logger = self.logger if self.logger else DummyLogger()
        
        if not is_url_in_scope(endpoint, scope_logger):
            return ScanDecision(
                should_scan=False,
                skip_reason=SkipReason.OUT_OF_SCOPE,
                reason_detail=f"Endpoint {endpoint} is out of scope"
            )
        
        # RULE 2: Method safety check
        method_upper = method.upper()
        if method_upper not in self.SAFE_METHODS:
            return ScanDecision(
                should_scan=False,
                skip_reason=SkipReason.UNSAFE_METHOD,
                reason_detail=f"Method {method_upper} is not in safe methods list"
            )
        
        if method_upper in self.DANGEROUS_METHODS and not self.allow_dangerous_methods:
            return ScanDecision(
                should_scan=False,
                skip_reason=SkipReason.UNSAFE_METHOD,
                reason_detail=f"Method {method_upper} is dangerous, not allowed by policy"
            )
        
        # RULE 3: CANONICAL CHECK - Is this vulnerability already confirmed?
        # Uses VulnKey for canonical identification
        vuln_key = normalize_vuln_key(
            method=method,
            url=endpoint,
            param=param,
            param_location=location,
            vuln_type=vuln_type
        )
        
        if self.kb.is_vuln_confirmed(vuln_key):
            return ScanDecision(
                should_scan=False,
                skip_reason=SkipReason.ALREADY_VULNERABLE,
                reason_detail=f"Vuln already confirmed: {vuln_key}"
            )
        
        # RULE 4: Check for duplicate payload execution
        if payload and self.kb.was_payload_executed(endpoint, param, payload):
            return ScanDecision(
                should_scan=False,
                skip_reason=SkipReason.PAYLOAD_ALREADY_SENT,
                reason_detail=f"Payload already executed for {param}"
            )
        
        # RULE 5: Check max payloads per parameter (scan storm prevention)
        param_key = f"{endpoint}|{param}|{location}"
        current_count = self._param_payload_counts.get(param_key, 0)
        if current_count >= self.MAX_PAYLOADS_PER_PARAM:
            return ScanDecision(
                should_scan=False,
                skip_reason=SkipReason.MAX_TESTS_REACHED,
                reason_detail=f"Max {self.MAX_PAYLOADS_PER_PARAM} payloads reached for {param}"
            )
        
        # RULE 5b: Check global payload limit (total scan storm prevention)
        total_payloads = sum(self._param_payload_counts.values())
        if total_payloads >= self.MAX_TOTAL_PAYLOADS:
            return ScanDecision(
                should_scan=False,
                skip_reason=SkipReason.MAX_TESTS_REACHED,
                reason_detail=f"Global max {self.MAX_TOTAL_PAYLOADS} payloads reached"
            )
        
        # RULE 6: Check preconditions if injection point provided
        if injection_point:
            precondition_result = self._check_preconditions(
                vuln_type, injection_point
            )
            if not precondition_result[0]:
                return ScanDecision(
                    should_scan=False,
                    skip_reason=SkipReason.PRECONDITIONS_NOT_MET,
                    reason_detail=precondition_result[1]
                )
        
        # All checks passed - allow scanning
        return ScanDecision(
            should_scan=True,
            skip_reason=SkipReason.NONE,
            reason_detail=""
        )
    
    def record_payload_sent(
        self,
        endpoint: str,
        param: str,
        location: str,
        payload: str,
        method: str = "GET"
    ) -> None:
        """Record that a payload was sent."""
        param_key = f"{endpoint}|{param}|{location}"
        self._param_payload_counts[param_key] = \
            self._param_payload_counts.get(param_key, 0) + 1
        
        if payload:
            self.kb.record_payload_executed(endpoint, param, payload)
    
    def record_vulnerability_confirmed(
        self,
        endpoint: str,
        param: str,
        location: str,
        vuln_type: str,
        payload: str,
        method: str = "GET",
        response_code: int = 200,
        response_body: str = "",
        evidence_dict: Optional[Dict] = None
    ) -> None:
        """
        Record a confirmed vulnerability using canonical VulnKey.
        
        Creates VulnKey and Evidence objects with proper scoring.
        After this, discovery payloads for this VulnKey will be SKIPPED.
        """
        # Build canonical VulnKey
        vuln_key = normalize_vuln_key(
            method=method,
            url=endpoint,
            param=param,
            param_location=location,
            vuln_type=vuln_type
        )
        
        # Calculate evidence score
        score = calculate_evidence_score(
            vuln_type=vuln_type,
            response_code=response_code,
            response_body=response_body,
            payload=payload
        )
        
        # Build Evidence object
        evidence = Evidence(
            payload=payload,
            response_snippet=response_body[:500] if response_body else str(evidence_dict or {}),
            score=score,
            confidence=determine_confidence(score),
            request_details=evidence_dict or {}
        )
        
        # Confirm in knowledge base (will upgrade if score is higher)
        was_new = self.kb.confirm_vulnerability(vuln_key, evidence)
        
        if self.logger:
            if was_new:
                self.logger.info(
                    f"[scheduler] CONFIRMED: {vuln_type} on {param}[{location}] "
                    f"(score={score}, confidence={evidence.confidence}). "
                    f"Further discovery payloads for this VulnKey will be SKIPPED."
                )
            else:
                self.logger.info(
                    f"[scheduler] Evidence not upgraded for {vuln_type} on {param} "
                    f"(new score={score} not higher than existing)"
                )
    
    def _check_preconditions(
        self,
        vuln_type: str,
        injection_point: InjectionPoint
    ) -> Tuple[bool, str]:
        """
        Check if vulnerability preconditions are met.
        
        Returns (passes: bool, reason: str)
        """
        # Import templates to avoid circular import
        from core.scanner.vuln_templates import VULNERABILITY_PRECONDITIONS
        
        preconditions = VULNERABILITY_PRECONDITIONS.get(vuln_type, [])
        
        for precond in preconditions:
            if precond == "string_or_numeric_parameter":
                if injection_point.data_type_guess not in ["string", "number"]:
                    return False, f"Parameter is {injection_point.data_type_guess}, not string/number"
            
            elif precond == "html_or_js_context":
                if injection_point.context not in ["html", "js", "generic"]:
                    return False, f"Context is {injection_point.context}, not html/js"
            
            elif precond == "parameter_reflection":
                if injection_point.reflection_behavior == "not_reflected":
                    return False, "Parameter is not reflected"
            
            elif precond == "url_like_input":
                if injection_point.data_type_guess != "url":
                    # Also check name patterns
                    if not any(x in injection_point.name.lower() 
                              for x in ["url", "link", "callback", "redirect"]):
                        return False, "Parameter doesn't appear to be URL-like"
            
            elif precond == "path_like_input":
                if injection_point.context != "path":
                    if not any(x in injection_point.name.lower()
                              for x in ["file", "path", "dir", "template", "include"]):
                        return False, "Parameter doesn't appear to be path-like"
        
        return True, ""
    
    def get_scan_stats(self) -> Dict:
        """Get scanning statistics."""
        return {
            "total_params_tested": len(self._param_payload_counts),
            "total_payloads_sent": sum(self._param_payload_counts.values()),
            "confirmed_vulns": len(self.kb.get_confirmed_vulns()),
            "knowledge_base_stats": self.kb.get_stats(),
        }
    
    def get_skipped_params(self) -> List[Dict]:
        """Get list of params that would be skipped due to confirmed vulns."""
        return [
            {
                "param": cv.vuln_key.parameter,
                "endpoint": cv.vuln_key.endpoint,
                "location": cv.vuln_key.parameter_location,
                "vuln_type": cv.vuln_key.vuln_type,
                "poc_id": cv.poc_id,
            }
            for cv in self.kb.get_confirmed_vulns()
        ]

