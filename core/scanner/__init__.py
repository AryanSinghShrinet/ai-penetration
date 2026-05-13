"""
Scanner Module - AI Web Spider + Active Scanner Engine

This module implements a Burp-style spider and scanner with:
- Knowledge base for confirmed vulnerability tracking
- Attack surface normalization
- Scan scheduling with preconditions
- Vulnerability templates with stop-after-confirmed rule

CRITICAL RULE: Once a vulnerability is CONFIRMED for a parameter,
NO further payloads will be sent to that parameter. This is enforced
at the system level and cannot be overridden.
"""

from core.scanner.knowledge_base import ScannerKnowledgeBase
from core.scanner.attack_surface import AttackSurfaceNormalizer, InjectionPoint
from core.scanner.scan_scheduler import ScanScheduler
from core.scanner.vuln_templates import VulnerabilityTemplates, check_preconditions

__all__ = [
    'ScannerKnowledgeBase',
    'AttackSurfaceNormalizer', 
    'InjectionPoint',
    'ScanScheduler',
    'VulnerabilityTemplates',
    'check_preconditions',
]
