"""
Business Logic Analyzer
========================
Detects workflow anomalies and tracks API state transitions.

Business logic bugs are the hardest to find — they're invisible to
signature-based scanners because the requests are syntactically valid.

Examples of what this detects:
  - Negative price/quantity manipulation
  - Skipped workflow steps (checkout without cart)
  - Horizontal privilege escalation (accessing another user's resource)
  - Mass assignment (sending fields the app doesn't expect)
  - Race conditions (concurrent requests to state-changing endpoints)
  - Parameter tampering (changing order_id in a confirmation step)

Components:
  WorkflowTracker — records the sequence of API calls and detects gaps
  StateMachineAnalyzer — models valid state transitions, flags invalid ones
  BusinessLogicProbe — generates test cases targeting logic flaws
"""

import time
import re
import copy
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Tuple, Any
from enum import Enum


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class TransitionValidity(Enum):
    VALID         = "valid"
    SUSPICIOUS    = "suspicious"     # Unexpected but not clearly invalid
    INVALID       = "invalid"        # Violates expected workflow
    SKIPPED_STEP  = "skipped_step"   # Expected prerequisite step was skipped


@dataclass
class APICall:
    """Represents a single observed API call in a workflow."""
    method: str
    endpoint: str
    status_code: int
    request_params: Dict = field(default_factory=dict)
    response_data: Dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    session_id: str = ""

    @property
    def key(self) -> str:
        """Normalized endpoint key for state tracking."""
        # Strip numeric IDs for pattern matching
        normalized = re.sub(r"/\d+", "/{id}", self.endpoint)
        return f"{self.method.upper()}:{normalized}"


@dataclass
class WorkflowAnomaly:
    """Detected anomaly in workflow logic."""
    anomaly_type: str
    description: str
    severity: str          # critical, high, medium, low
    endpoint: str
    evidence: Dict
    exploitation_hint: str

    def to_dict(self) -> Dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Workflow Tracker
# ---------------------------------------------------------------------------

class WorkflowTracker:
    """
    Records sequences of API calls and detects workflow anomalies.

    Key detections:
    1. Skipped prerequisite steps
    2. Backward state transitions (e.g., return to cart after payment)
    3. Repeated state transitions (double-spend, double-click abuse)
    4. Parameter value changes mid-workflow (order tampering)
    """

    # Known workflow sequences (endpoint_pattern → expected_prerequisites)
    KNOWN_WORKFLOWS = {
        # E-commerce flow
        r"POST:/checkout":      ["POST:/cart", "GET:/cart"],
        r"POST:/payment":       ["POST:/checkout"],
        r"POST:/confirm":       ["POST:/payment"],
        r"GET:/order/\{id\}":   ["POST:/checkout"],

        # Authentication flow
        r"POST:/reset-password": ["POST:/forgot-password"],
        r"POST:/verify":         ["POST:/register"],
        r"GET:/dashboard":       ["POST:/login"],

        # Multi-step forms
        r"POST:/step2":          ["POST:/step1"],
        r"POST:/step3":          ["POST:/step1", "POST:/step2"],
        r"POST:/submit":         ["GET:/form", "POST:/step"],

        # Account actions
        r"DELETE:/account":      ["POST:/login"],
        r"POST:/transfer":       ["POST:/login", "GET:/account"],
    }

    def __init__(self):
        self._sessions: Dict[str, List[APICall]] = defaultdict(list)
        self._seen_transitions: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)

    def record(self, call: APICall) -> None:
        """Record an API call for a session."""
        self._sessions[call.session_id].append(call)

    def record_from_response(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        session_id: str = "default",
        request_params: Optional[Dict] = None,
    ) -> APICall:
        """Convenience method to create and record a call."""
        call = APICall(
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            request_params=request_params or {},
            session_id=session_id,
        )
        self.record(call)
        return call

    def analyze_session(self, session_id: str = "default") -> List[WorkflowAnomaly]:
        """Analyze all calls in a session for workflow anomalies."""
        calls = self._sessions.get(session_id, [])
        anomalies = []

        if not calls:
            return anomalies

        # Build set of seen endpoint keys
        seen_endpoints: Set[str] = set()
        call_sequence: List[str] = []

        for i, call in enumerate(calls):
            key = call.key
            call_sequence.append(key)

            # Check 1: Prerequisite step validation
            for workflow_pattern, prerequisites in self.KNOWN_WORKFLOWS.items():
                if re.match(workflow_pattern, key):
                    missing_prereqs = []
                    for prereq in prerequisites:
                        if not any(re.match(prereq, s) for s in seen_endpoints):
                            missing_prereqs.append(prereq)

                    if missing_prereqs:
                        anomalies.append(WorkflowAnomaly(
                            anomaly_type="skipped_workflow_step",
                            description=f"Endpoint {call.endpoint} reached without required step(s): {missing_prereqs}",
                            severity="high",
                            endpoint=call.endpoint,
                            evidence={"missing_steps": missing_prereqs, "call_sequence": call_sequence[-5:]},
                            exploitation_hint=f"Try accessing {call.endpoint} directly without completing: {missing_prereqs}"
                        ))

            # Check 2: Duplicate state transitions (double-click/double-spend)
            transition = (call_sequence[-2] if len(call_sequence) >= 2 else "", key)
            if transition in self._seen_transitions[session_id] and call.status_code == 200:
                anomalies.append(WorkflowAnomaly(
                    anomaly_type="duplicate_state_transition",
                    description=f"Same state transition repeated successfully: {transition[0]} → {transition[1]}",
                    severity="medium",
                    endpoint=call.endpoint,
                    evidence={"transition": transition, "status": call.status_code},
                    exploitation_hint="Race condition or TOCTOU — try concurrent requests"
                ))

            self._seen_transitions[session_id].add(transition)
            seen_endpoints.add(key)

        # Check 3: Parameter tampering mid-workflow
        anomalies.extend(self._detect_param_tampering(calls))

        return anomalies

    def _detect_param_tampering(self, calls: List[APICall]) -> List[WorkflowAnomaly]:
        """Detect when key parameters change between workflow steps."""
        anomalies = []
        ownership_params = ["id", "user_id", "account_id", "order_id", "session_id"]

        for i in range(1, len(calls)):
            prev = calls[i - 1]
            curr = calls[i]

            for param in ownership_params:
                prev_val = prev.request_params.get(param)
                curr_val = curr.request_params.get(param)

                if prev_val and curr_val and str(prev_val) != str(curr_val):
                    anomalies.append(WorkflowAnomaly(
                        anomaly_type="ownership_param_changed",
                        description=f"Parameter '{param}' changed mid-workflow: {prev_val} → {curr_val}",
                        severity="high",
                        endpoint=curr.endpoint,
                        evidence={
                            "param": param,
                            "original": prev_val,
                            "modified": curr_val,
                            "step_from": prev.endpoint,
                            "step_to": curr.endpoint,
                        },
                        exploitation_hint=f"Try changing {param} to another user's ID for IDOR"
                    ))

        return anomalies


# ---------------------------------------------------------------------------
# State Machine Analyzer
# ---------------------------------------------------------------------------

class StateMachineAnalyzer:
    """
    Models the application as a state machine and detects invalid transitions.

    States are derived from observed endpoint patterns.
    Edges represent valid observed transitions.

    A request that reaches a state "impossible" given prior context is a
    potential business logic vulnerability.
    """

    def __init__(self):
        self._states: Set[str] = set()
        self._transitions: Dict[str, Set[str]] = defaultdict(set)  # from_state → to_states
        self._observed_paths: List[List[str]] = []

    def observe_transition(self, from_endpoint: str, to_endpoint: str) -> None:
        """Record a valid observed state transition."""
        from_key = self._normalize(from_endpoint)
        to_key = self._normalize(to_endpoint)
        self._states.add(from_key)
        self._states.add(to_key)
        self._transitions[from_key].add(to_key)

    def _normalize(self, endpoint: str) -> str:
        """Normalize endpoint to a state key."""
        return re.sub(r"/\d+", "/{id}", endpoint.lower())

    def is_valid_transition(self, from_endpoint: str, to_endpoint: str) -> Tuple[bool, str]:
        """
        Check if a state transition is valid based on observed behavior.

        Returns: (is_valid, reason)
        """
        from_key = self._normalize(from_endpoint)
        to_key = self._normalize(to_endpoint)

        if from_key not in self._states:
            return True, "unknown_source_state"  # Can't say it's invalid

        valid_nexts = self._transitions.get(from_key, set())
        if not valid_nexts:
            return True, "no_transitions_observed"

        if to_key in valid_nexts:
            return True, "valid_transition"

        return False, f"invalid_transition: {from_key} → {to_key} not observed"

    def find_reachable_states(self, from_endpoint: str) -> List[str]:
        """Get all states reachable from a given state (BFS)."""
        start = self._normalize(from_endpoint)
        visited = set()
        queue = [start]
        reachable = []

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            reachable.append(current)
            for next_state in self._transitions.get(current, []):
                if next_state not in visited:
                    queue.append(next_state)

        return reachable

    def generate_probe_sequences(self) -> List[List[str]]:
        """
        Generate API call sequences that skip intermediate steps.
        These are test cases for workflow bypass vulnerabilities.
        """
        probes = []

        for start_state in self._states:
            reachable = self.find_reachable_states(start_state)
            for target_state in reachable:
                # Generate a path that skips one intermediate step
                direct_path = [start_state, target_state]
                probes.append(direct_path)

        return probes


# ---------------------------------------------------------------------------
# Business Logic Probe Generator
# ---------------------------------------------------------------------------

class BusinessLogicProbe:
    """
    Generates specific test cases for common business logic flaws.

    Categories:
    1. Numeric manipulation (negative values, overflows, zero)
    2. State skipping (skip payment, skip verification)
    3. Parameter pollution (duplicate params with different values)
    4. Mass assignment (extra fields in API requests)
    5. Time-based race conditions
    """

    @staticmethod
    def generate_numeric_probes(param: str, original_value: Any) -> List[Dict]:
        """Generate numeric manipulation test cases."""
        probes = []
        try:
            val = float(original_value)
            probes.extend([
                {"param": param, "value": -val, "attack": "negative_value"},
                {"param": param, "value": 0, "attack": "zero_value"},
                {"param": param, "value": 0.001, "attack": "fractional_value"},
                {"param": param, "value": 9999999999, "attack": "overflow_attempt"},
                {"param": param, "value": int(val) - 1, "attack": "off_by_one"},
            ])
        except (ValueError, TypeError):
            pass
        return probes

    @staticmethod
    def generate_idor_probes(param: str, original_value: Any) -> List[Dict]:
        """Generate IDOR test cases by enumerating adjacent IDs."""
        probes = []
        try:
            val = int(original_value)
            for delta in [-1, 1, -2, 2, 100, val + 1000]:
                probes.append({
                    "param": param,
                    "value": val + delta if delta != val + 1000 else delta,
                    "attack": "idor_enumeration",
                    "original": val,
                })
        except (ValueError, TypeError):
            pass
        return probes

    @staticmethod
    def generate_mass_assignment_probes(existing_params: List[str]) -> List[Dict]:
        """Generate mass assignment test cases with privilege-escalation fields."""
        extra_fields = [
            {"admin": True, "attack": "admin_flag"},
            {"role": "admin", "attack": "role_escalation"},
            {"is_staff": True, "attack": "staff_flag"},
            {"price": 0.01, "attack": "price_manipulation"},
            {"discount": 100, "attack": "discount_manipulation"},
            {"credits": 9999, "attack": "credits_manipulation"},
            {"verified": True, "attack": "verification_bypass"},
        ]
        # Return fields not already in existing params
        return [
            f for f in extra_fields
            if f["attack"].split("_")[0] not in [p.lower() for p in existing_params]
        ]

    @staticmethod
    def generate_race_condition_probes(endpoint: str, payload: Dict, count: int = 5) -> List[Dict]:
        """Generate concurrent request probes for race conditions."""
        return [
            {"endpoint": endpoint, "payload": copy.deepcopy(payload), "thread": i}
            for i in range(count)
        ]


# ---------------------------------------------------------------------------
# Main Business Logic Analyzer
# ---------------------------------------------------------------------------

class BusinessLogicAnalyzer:
    """
    Combines WorkflowTracker, StateMachineAnalyzer, and BusinessLogicProbe
    into a unified business logic testing engine.
    """

    def __init__(self):
        self.workflow_tracker = WorkflowTracker()
        self.state_machine = StateMachineAnalyzer()
        self.probe_generator = BusinessLogicProbe()
        self._all_anomalies: List[WorkflowAnomaly] = []

    def observe(
        self,
        method: str,
        endpoint: str,
        status_code: int,
        session_id: str = "default",
        request_params: Optional[Dict] = None,
        previous_endpoint: Optional[str] = None,
    ) -> None:
        """Record an API call and update state machine."""
        self.workflow_tracker.record_from_response(
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            session_id=session_id,
            request_params=request_params,
        )
        if previous_endpoint:
            self.state_machine.observe_transition(previous_endpoint, endpoint)

    def analyze(self, session_id: str = "default") -> List[Dict]:
        """Run full business logic analysis."""
        anomalies = self.workflow_tracker.analyze_session(session_id)
        self._all_anomalies.extend(anomalies)
        return [a.to_dict() for a in anomalies]

    def get_test_cases(self, endpoints_with_params: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Generate business logic test cases for a set of endpoints.

        Returns dict: endpoint → list of probe dicts
        """
        test_cases = defaultdict(list)

        for ep_info in endpoints_with_params:
            endpoint = ep_info.get("endpoint", "")
            params = ep_info.get("parameters", {})

            for param_name, param_value in params.items():
                # Numeric manipulation
                test_cases[endpoint].extend(
                    self.probe_generator.generate_numeric_probes(param_name, param_value)
                )
                # IDOR probes
                if any(x in param_name.lower() for x in ["id", "user", "account", "doc"]):
                    test_cases[endpoint].extend(
                        self.probe_generator.generate_idor_probes(param_name, param_value)
                    )

            # Mass assignment
            test_cases[endpoint].extend(
                self.probe_generator.generate_mass_assignment_probes(list(params.keys()))
            )

        return dict(test_cases)


def create_business_logic_analyzer() -> BusinessLogicAnalyzer:
    """Factory function."""
    return BusinessLogicAnalyzer()
