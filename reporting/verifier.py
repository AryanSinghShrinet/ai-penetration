"""
Vulnerability Verifier for AI-Pentester
Performs secondary confirmation of findings.
"""

import time

class VulnerabilityVerifier:
    """
    Verifies vulnerabilities with secondary tests and alternative payloads.
    """
    
    # Alternative payloads for each vulnerability type
    VERIFICATION_PAYLOADS = {
        "xss": [
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)//",
        ],
        "sqli": [
            "' OR '1'='1'--",
            "1' AND '1'='1",
            "1; SELECT SLEEP(2)--",
            "' UNION SELECT NULL--",
        ],
        "idor": [],  # IDOR verification needs context
        "ssrf_indicator": [
            "http://127.0.0.1:80",
            "http://localhost",
            "http://169.254.169.254/",
        ],
        "cmd_injection": [
            "; echo vulnerable",
            "| echo vulnerable",
            "$(echo vulnerable)",
        ],
    }
    
    def __init__(self, session, logger, min_confirmations=2):
        self.session = session
        self.logger = logger
        self.min_confirmations = min_confirmations
    
    def verify(self, finding, target):
        """
        Verify a finding with additional tests.
        
        Args:
            finding: dict with 'vuln', 'payload', 'evidence'
            target: target URL
        
        Returns:
            dict with 'confirmed', 'confidence', 'confirmations'
        """
        vuln_type = finding.get("vuln")
        original_payload = finding.get("payload")
        
        confirmations = 1  # Original finding counts as 1
        
        alt_payloads = self.VERIFICATION_PAYLOADS.get(vuln_type, [])
        
        for payload in alt_payloads[:3]:  # Test up to 3 alternatives
            try:
                result = self._test_payload(target, vuln_type, payload)
                if result.get("vulnerable"):
                    confirmations += 1
                    self.logger.info(f"[verifier] Confirmed {vuln_type} with alt payload")
                    
                    if confirmations >= self.min_confirmations:
                        break
                        
            except Exception as e:
                self.logger.debug(f"[verifier] Error testing payload: {e}")
        
        confidence = min(1.0, confirmations / 3)
        
        return {
            "confirmed": confirmations >= self.min_confirmations,
            "confidence": confidence,
            "confirmations": confirmations,
            "vuln_type": vuln_type
        }
    
    def _test_payload(self, target, vuln_type, payload):
        """Test a single payload."""
        params = {"test": payload}
        
        try:
            response = self.session.get(target, params=params, timeout=10)
            
            if vuln_type == "xss":
                # Check for reflection
                if payload in response.text:
                    return {"vulnerable": True, "reason": "reflected"}
                    
            elif vuln_type == "sqli":
                # Check for error messages
                from core.sqli import detect_error_based
                is_error, _ = detect_error_based(response.text)
                if is_error:
                    return {"vulnerable": True, "reason": "error_based"}
                    
            elif vuln_type == "cmd_injection":
                if "vulnerable" in response.text:
                    return {"vulnerable": True, "reason": "output_reflected"}
                    
        except Exception as _e:
            import logging; logging.getLogger(__name__).debug(f'[verifier] verification request failed: {_e}')
        
        return {"vulnerable": False}
    
    def verify_all(self, findings, target):
        """
        Verify multiple findings.
        
        Returns:
            list of verified findings with confirmation data
        """
        verified = []
        
        for finding in findings:
            result = self.verify(finding, target)
            finding["verification"] = result
            verified.append(finding)
            
            status = "✓" if result["confirmed"] else "✗"
            self.logger.info(
                f"[verifier] {finding['vuln']}: {status} "
                f"(conf: {result['confidence']:.0%}, checks: {result['confirmations']})"
            )
        
        return verified


def verify_finding(finding, target, session, logger):
    """Convenience function for single finding verification."""
    verifier = VulnerabilityVerifier(session, logger)
    return verifier.verify(finding, target)
