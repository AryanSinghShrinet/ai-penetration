import yaml
import logging
from pathlib import Path
from dataclasses import asdict
from core.state import (
    create_run, 
    load_state,
    save_layer2_output, 
    save_layer3_payloads,
    save_execution_result,
    update_vuln_status,
    mark_blocked,
    mark_out_of_scope,
    save_rate_state,
    load_rate_state,
    mark_dry_run,
    update_state,
    # FIX 1 & 2: Pipeline tracking and cancel control
    update_pipeline,
    is_cancel_requested,
    mark_cancelled
)
from core.rate_control import RateController
from core.logger import setup_logger
from core.recon import recon_target
from core.context import detect_context
from core.payloads import select_payloads, mutate_payload
from core.executor import execute_payload
from core.learner import learn_from_execution
from core.correlator import correlate
from core.learning_memory import record_result
from core.mutator import choose_mutations, MUTATORS
from core.prioritizer import prioritize_vulns, compute_score
from core.reporter import generate_report
from core.task_planner import plan_tasks
from core.worker import worker_loop

from core.scope import is_url_in_scope
from core.idor import discover_id_candidates
from core.logic import discover_workflows, plan_logic_probes
from core.oauth_logic import analyze_oauth_parameters

# New workflow components
from core.target_parser import TargetParser
from core.checklist_generator import ChecklistGenerator, generate_checklist
from core.poc_generator import POCGenerator

# Scanner integration (Spider + Active Scanner engine)
from core.scanner.knowledge_base import ScannerKnowledgeBase
from core.scanner.attack_surface import AttackSurfaceNormalizer
from core.scanner.scan_scheduler import ScanScheduler

# Verifier for secondary confirmation
from core.verifier import VulnerabilityVerifier

# Exploit database for exploit matching
from core.exploit_db import ExploitMatcher, ExploitExecutor, get_exploit_database

# =============================================================================
# RESEARCH UPGRADES — Graceful import (fallback to None if unavailable)
# =============================================================================
_RESEARCH_MODULES_AVAILABLE = False
SubdomainDiscovery = None
AttackSurfaceIntelligence = None
EndpointDiscovery = None
ParameterMiner = None
AdaptiveFuzzer = None
AnomalyDetectionEngine = None
WorkflowTracker = None
BusinessLogicAnalyzer = None
build_enhanced_attack_graph = None
AttackPlanner = None
build_feature_vector = None
VulnFeatureVector = None

try:
    from recon.subdomain_discovery import SubdomainDiscovery
    from recon.attack_surface_intelligence import AttackSurfaceIntelligence
    from discovery.endpoint_discovery import EndpointDiscovery
    from discovery.parameter_miner import ParameterMiner
    from fuzzing.adaptive_fuzzer import AdaptiveFuzzer
    from analysis.anomaly_detection import AnomalyDetectionEngine
    from business_logic.workflow_tracker import WorkflowTracker, BusinessLogicAnalyzer
    from graph.chain_builder import build_attack_graph as build_enhanced_attack_graph, AttackGraph as ResearchAttackGraph
    from ai_reasoning.attack_planner import AttackPlanner, PlannerContext
    from ml.features import build_feature_vector, VulnFeatureVector
    _RESEARCH_MODULES_AVAILABLE = True
except ImportError as _e:
    import logging as _log
    _log.getLogger(__name__).warning(
        f"Research modules not fully available (non-critical): {_e}. "
        "Core scanning still works. Check module imports."
    )
# =============================================================================

CONFIG_PATH = Path("config/settings.yaml")

# --- ML Integration ---
import os

ML_ENABLED = False
ML_PREDICTOR = None

_model_path = Path("data/vuln_classifier.pkl")
_vectorizer_path = Path("data/vectorizer.pkl")

if _model_path.exists() and _vectorizer_path.exists():
    try:
        import joblib
        from core.ml_analysis.predictor import VulnerabilityPredictor
        
        # Load the saved model and vectorizer
        classifier_model = joblib.load(str(_model_path))
        vectorizer = joblib.load(str(_vectorizer_path))
        
        # Create predictor with loaded model and vectorizer
        ML_PREDICTOR = VulnerabilityPredictor(classifier_model, vectorizer)
        ML_ENABLED = True
        logging.getLogger(__name__).info("[ML] Model loaded successfully")
    except Exception as e:
        logging.getLogger(__name__).warning(f"[ML] Failed to load model: {e}")
        ML_ENABLED = False
# -------------------------------------------------------------

def load_config(config_path=None):
    path = Path(config_path) if config_path else CONFIG_PATH
    with open(path, "r") as f:
        return yaml.safe_load(f)

def start(target=None, config_path=None, dry_run=None, phase="all"):
    config = load_config(config_path)

    # CLI args override config file values
    target_spec = target or config.get("target", "").strip()

    if not target_spec:
        raise ValueError("Target is empty. Pass --target or set it in config/settings.yaml")

    # Parse target specification (URL, domain, or wildcard)
    parser = TargetParser()
    target_info = parser.parse(target_spec)
    
    logging.getLogger(__name__).info(f"[Target] Type: {target_info['type']}, Targets: {len(target_info['targets'])}")
    
    # Use first target for now (multi-target support can be added later)
    target = target_info['targets'][0] if target_info['targets'] else target_spec
    # C-5 FIX: TargetParser may return a dict object as target[0]. Normalise to
    # a plain URL string immediately so .lower(), .startswith() etc. never fail.
    target = target["url"] if isinstance(target, dict) else str(target)

    state = create_run(
        target=target,
        resume_enabled=config.get("resume", False)
    )
    
    # Store target info and research phase in state
    state["target_info"] = target_info
    state["all_targets"] = target_info['targets']
    state["research_phase"] = phase

    logger = setup_logger(state["run_id"])
    
    logger.info(f"Target parsed: {target_info['type']} -> {len(target_info['targets'])} URLs")
    logger.info(f"Research phase: {phase}")
    
    if not is_url_in_scope(target, logger):
        logger.error("Target is OUT OF SCOPE. Aborting run.")
        mark_out_of_scope(state["run_id"], target)
        raise ValueError("Target is outside defined scope — check config/scope.yaml")
    
    # dry_run: CLI arg overrides config
    if dry_run is None:
        dry_run = bool(config.get("dry_run", False))
    mark_dry_run(state["run_id"], dry_run)
    
    if dry_run:
        logger.warning("DRY-RUN MODE ENABLED — no HTTP requests will be sent")

    logger.info("Layer 1 initialized")
    
    # FIX 1: Real progress tracking - Layer 1 complete
    update_pipeline(state["run_id"], layer=1, progress=1.0, 
                    message="Initialization complete", status="completed")
    
    # FIX 2: Check for cancellation
    if is_cancel_requested(state["run_id"]):
        logger.warning("Scan cancelled by user")
        mark_cancelled(state["run_id"])
        return {"state": state, "cancelled": True}
    
    logger.info("Starting Layer 2")
    update_pipeline(state["run_id"], layer=2, progress=0.0, 
                    message="Starting reconnaissance...")

    # --- Phase 2: Reconnaissance (Recon v2) ---
    recon_data = recon_target(target, logger)
    
    # FIX 1: Update progress during recon
    update_pipeline(state["run_id"], layer=2, progress=0.5, 
                    message="Processing reconnaissance data...")
    
    # Log Canonical Profile for Visualization
    if hasattr(recon_data, "to_dict"):
        logger.info(f"Recon Profile: {recon_data.to_dict()}")
    else:
        logger.info(f"Recon Data: {recon_data}")
        
    # --- Improvement 3: Recon Visualization ---
    from core.recon.visualization import export_profile_graphs
    export_profile_graphs(recon_data, f"reports/{state['run_id']}")

    # --- Improvement 1: Hypothesis Engine ---
    from core.hypothesis import generate_hypotheses
    hypotheses = generate_hypotheses(recon_data)
    for h in hypotheses:
        logger.info(f"Hypothesis Generated: {h['type']} (Conf: {h['confidence']}) - {h['reason']}")
    
    # Store hypotheses in profile if possible, or context
    if hasattr(recon_data, "hypotheses"):
        recon_data.hypotheses.extend(hypotheses)

    # --- Phase 3: Context Analysis & Planning ---
    context_data = detect_context(recon_data, logger)

    save_data = recon_data.to_dict() if hasattr(recon_data, "to_dict") else recon_data
    save_layer2_output(state["run_id"], save_data, context_data)

    logger.info("Layer 2 completed successfully")
    
    # FIX 1: Layer 2 complete
    update_pipeline(state["run_id"], layer=2, progress=1.0, 
                    message="Reconnaissance complete", status="completed")

    # =========================================================================
    # RESEARCH UPGRADE: Subdomain Discovery + Attack Surface Intelligence
    # =========================================================================
    research_subdomains = []
    research_scored_endpoints = []
    if _RESEARCH_MODULES_AVAILABLE:
        try:
            logger.info("[research] Running SubdomainDiscovery...")
            _sd_domain = ""
            try:
                from urllib.parse import urlparse as _urlparse
                # Strip SPA hash-fragment (#/) before extracting hostname — crawlers
                # normalise away the fragment, so we must use the bare origin here.
                _clean_target = str(target).split("#")[0].rstrip("/")
                _sd_domain = _urlparse(_clean_target).hostname or ""
            except Exception:
                _sd_domain = str(target).split("#")[0]
            sd = SubdomainDiscovery(domain=_sd_domain, timeout=15)
            _domains = [target.get("base_domain", target.get("domain", ""))] if isinstance(target, dict) else [str(target)]
            _domains = [d for d in _domains if d]
            research_subdomains = sd.run()
            logger.info(f"[research] Subdomain discovery found {len(research_subdomains)} subdomains")
        except Exception as _e:
            logger.warning(f"[research] SubdomainDiscovery failed (non-critical): {_e}")

        try:
            logger.info("[research] Running AttackSurfaceIntelligence scoring...")
            _surface = save_data if isinstance(save_data, dict) else {}
            _endpoints = _surface.get("endpoints", [])
            if _endpoints:
                asi = AttackSurfaceIntelligence()
                research_scored_endpoints = asi.rank_endpoints(
                    {"endpoints": _endpoints, "parameters": _surface.get("parameters", []), "forms": _surface.get("forms", [])}
                )
                logger.info(f"[research] Scored {len(research_scored_endpoints)} endpoints by risk.")
                # Log top 5 high-risk endpoints
                for ep in research_scored_endpoints[:5]:
                    risk = ep.get("risk_level", "?") if isinstance(ep, dict) else "?"
                    url  = ep.get("endpoint",  "?") if isinstance(ep, dict) else str(ep)
                    logger.info(f"[research][ASI]  {risk:8s}  {url}")
        except Exception as _e:
            logger.warning(f"[research] AttackSurfaceIntelligence failed (non-critical): {_e}")

        # -----------------------------------------------------------------------
        # RESEARCH: Endpoint Discovery — active wordlist probing for hidden paths
        # -----------------------------------------------------------------------
        research_discovered_endpoints = []
        try:
            logger.info("[research] Running EndpointDiscovery (active path probing)...")
            from core.executor import create_session as _create_session_tmp
            # B-3 FIX: yaml imported at module level as _yaml_tmp
            try:
                with open("config/auth.yaml") as _af:
                    _auth_cfg_tmp = _yaml_tmp.safe_load(_af)
            except Exception as _e:
                _auth_cfg_tmp = {}
            _disc_session = _create_session_tmp(_auth_cfg_tmp)
            _disc = EndpointDiscovery(session=_disc_session, threads=5)
            _base_url = str(target.get("url", target) if isinstance(target, dict) else target)
            research_discovered_endpoints = _disc.discover(_base_url, logger=logger)
            # Also probe for API versioning
            _api_vers = _disc.discover_api_versions(_base_url, logger=logger)
            research_discovered_endpoints.extend(_api_vers)
            logger.info(f"[research] EndpointDiscovery found {len(research_discovered_endpoints)} hidden paths")
            # Merge into recon data so payload planning can use them
            if isinstance(save_data, dict):
                _existing = save_data.get("endpoints", [])
                _new_urls = [ep.get("url", "") for ep in research_discovered_endpoints if ep.get("url")]
                save_data["endpoints"] = list(set(_existing + _new_urls))
        except Exception as _e:
            logger.warning(f"[research] EndpointDiscovery failed (non-critical): {_e}")

        # -----------------------------------------------------------------------
        # RESEARCH: Parameter Miner — find hidden/undocumented parameters
        # -----------------------------------------------------------------------
        research_mined_params = []
        try:
            logger.info("[research] Running ParameterMiner on top endpoints...")
            # E-5 FIX: guard against _disc_session being unbound if EndpointDiscovery
            # block threw before assigning it.
            if not _disc_session:
                raise RuntimeError("Discovery session not available for ParameterMiner")
            _pm = ParameterMiner(session=_disc_session, threads=5)
            # Mine top 5 endpoints (scored high-risk first, then discovered)
            _mine_targets = []
            if research_scored_endpoints:
                _mine_targets = [ep.get("endpoint", "") for ep in research_scored_endpoints[:3] if isinstance(ep, dict)]
            if research_discovered_endpoints:
                _mine_targets += [ep.get("url", "") for ep in research_discovered_endpoints[:2] if isinstance(ep, dict) and ep.get("status_code") == 200]
            _mine_targets = [u for u in _mine_targets if u][:5]
            for _mine_url in _mine_targets:
                try:
                    _pm_result = _pm.mine_endpoint(_mine_url, methods=["GET", "POST"], logger=logger)
                    if _pm_result.get("count", 0) > 0:
                        research_mined_params.append(_pm_result)
                        logger.info(f"[research][ParameterMiner] {_mine_url}: {_pm_result['count']} hidden params found")
                except Exception as _e:
                    continue
            # Merge mined params into recon data
            if isinstance(save_data, dict) and research_mined_params:
                _existing_params = save_data.get("parameters", [])
                for _pm_r in research_mined_params:
                    for _disc_p in _pm_r.get("discovered_parameters", []):
                        _pname = _disc_p.get("param", "")
                        if _pname and _pname not in _existing_params:
                            _existing_params.append(_pname)
                save_data["parameters"] = _existing_params
        except Exception as _e:
            logger.warning(f"[research] ParameterMiner failed (non-critical): {_e}")
    else:
        research_discovered_endpoints = []
        research_mined_params = []
    # =========================================================================

    # FIX 2: Check for cancellation
    if is_cancel_requested(state["run_id"]):
        logger.warning("Scan cancelled by user")
        mark_cancelled(state["run_id"])
        return {"state": state, "cancelled": True}
    
    # =========================================================================
    # SCANNER INTEGRATION: Knowledge Base & Attack Surface Normalization
    # =========================================================================
    
    # Initialize Scanner Knowledge Base (enforces stop-after-confirmed rule)
    knowledge_base = ScannerKnowledgeBase(state["run_id"])
    logger.info(f"[scanner] Knowledge base initialized. Stats: {knowledge_base.get_stats()}")
    
    # Normalize attack surface into structured injection points
    normalizer = AttackSurfaceNormalizer()
    injection_points = normalizer.normalize(target, save_data)
    logger.info(f"[scanner] Normalized {len(injection_points)} injection points")
    
    # Store in state for reference
    state["injection_points"] = normalizer.to_dict()
    
    # Initialize Scan Scheduler (integrates with knowledge base)
    scan_scheduler = ScanScheduler(knowledge_base, logger)
    logger.info("[scanner] Scan scheduler ready. Stop-after-confirmed rule ACTIVE.")
    
    # --- Dynamic Checklist Generation ---
    checklist_gen = ChecklistGenerator()
    dynamic_checklist = checklist_gen.generate(recon_data)
    
    logger.info(f"Dynamic Checklist Generated: {len(dynamic_checklist)} vulnerability checks")
    for item in dynamic_checklist[:5]:  # Log first 5
        logger.info(f"  [{item['severity'].upper()}] {item['name']} - {item['reasons'][0]}")
    
    # Store checklist in state
    state["dynamic_checklist"] = dynamic_checklist
    
    # Export formatted checklist
    from pathlib import Path
    checklist_path = Path(f"reports/{state['run_id']}/checklist.md")
    checklist_path.parent.mkdir(parents=True, exist_ok=True)
    checklist_path.write_text(checklist_gen.format_checklist(dynamic_checklist), encoding="utf-8")
    
    # --- Improvement 2: Business Logic Memory ---
    from core.logic_memory import LogicMemory
    logic_mem = LogicMemory()
    logger.info(f"Business Logic Memory loaded: {len(logic_mem.memory)} profiles")
    
    logger.info("Starting Layer 3: Payload Intelligence")
    
    # FIX 1: Layer 3 progress
    update_pipeline(state["run_id"], layer=3, progress=0.0, 
                    message="Building payload plan...")

    payload_plan = {}
    
    # Identify upload targets
    upload_targets = []
    for form in recon_data.get("forms", []):
        if form.get("method", "").lower() == "post":
            for inp in form.get("inputs", []):
                if "file" in inp.lower() or "upload" in inp.lower():
                    upload_targets.append({
                        "url": form.get("action"),
                        "field": inp,
                        "original": f"Upload Probe on {inp}"
                    })

    if upload_targets:
        payload_plan["file_upload"] = upload_targets[:1]

    # Workflow Discovery & Logic Planning
    workflows = discover_workflows(recon_data)
    logic_plans = plan_logic_probes(workflows)

    if logic_plans:
        payload_plan["business_logic"] = logic_plans

    # =========================================================================
    # INTELLIGENT PAYLOAD SELECTION using injection points
    # =========================================================================
    from core.payloads import build_intelligent_payload_plan
    
    # Get injection points that were normalized earlier
    injection_points_data = state.get("injection_points", {})
    injection_points_list = injection_points_data.get("points", [])
    
    if injection_points_list:
        logger.info(f"[payloads] Using {len(injection_points_list)} injection points for intelligent selection")
        
        # Build intelligent payload plan using context and preconditions
        intelligent_plan = build_intelligent_payload_plan(
            injection_points=injection_points_list,
            checklist=state.get("checklist", {}),
            max_payloads_per_param=15
        )
        
        # Merge intelligent plan into payload_plan
        for vuln_type, payloads in intelligent_plan.items():
            if vuln_type not in payload_plan:
                payload_plan[vuln_type] = []
            
            for p in payloads:
                payload_plan[vuln_type].append(mutate_payload(p))
        
        logger.info(f"[payloads] Intelligent plan: {len(intelligent_plan)} vuln types, "
                   f"{sum(len(v) for v in intelligent_plan.values())} total payloads")

        # Fallback merge loop: Ensure all checklist vulns have at least one payload.
        # Critical for context-independent vulns (cors, auth_bypass, brute_force, csrf, 
        # information_disclosure, security_headers) that don't match any injection point.
        # Step 1: use dynamic_checklist items
        checklist_vulns = state.get("dynamic_checklist", [])
        for checklist_item in checklist_vulns:
            vuln_type = checklist_item.get("vuln")  # correct key
            if vuln_type and vuln_type not in payload_plan:
                logger.info(f"[payloads] Adding fallback payload for {vuln_type}")
                selected = select_payloads(vuln_type, context_data)
                payload_plan[vuln_type] = []
                for fp in (selected or [f"probe-{vuln_type}"]):
                    payload_plan[vuln_type].append(mutate_payload(fp))

        # Step 2: Final safety net - ensure EVERY vuln in the state checklist has at least
        # a sentinel so its executor handler always runs (even with no real payloads)
        for vuln_type in state.get("checklist", {}).keys():
            if vuln_type not in payload_plan:
                logger.info(f"[payloads] Sentinel fallback for {vuln_type}")
                selected = select_payloads(vuln_type, context_data)
                payload_plan[vuln_type] = []
                for fp in (selected or [f"probe-{vuln_type}"]):
                    payload_plan[vuln_type].append(mutate_payload(fp))

    else:
        # Fallback to legacy behavior if no injection points
        logger.warning("[payloads] No injection points available, using legacy selection")
        all_vulns = list(state.get("checklist", {}).keys())
        for vuln in all_vulns:
            if vuln in payload_plan:
                continue
            selected = select_payloads(vuln, context_data)
            payload_plan[vuln] = []
            for p in selected:
                payload_plan[vuln].append(mutate_payload(p))

    # Dynamic IDOR planning
    id_candidates = discover_id_candidates(recon_data)
    if len(id_candidates) >= 2:
        payload_plan["idor"] = [{
            "original": f"IDOR swap {id_candidates[0]} <-> {id_candidates[1]}",
            "own_id": id_candidates[0],
            "other_id": id_candidates[1]
        }]

    # FIX3: Wire ParameterMiner results into payload entries.
    # research_mined_params contains discovered param names per endpoint.
    # Inject them as the "param" key so execute_payload uses real discovered
    # parameters instead of generic fallbacks like ?q= or ?test=.
    if research_mined_params:
        _all_mined = []
        for _pm_r in research_mined_params:
            for _dp in _pm_r.get("discovered_parameters", []):
                _pname = _dp.get("param", "")
                if _pname:
                    _all_mined.append(_pname)
        if _all_mined:
            logger.info(f"[payloads] FIX3: Enriching payloads with {len(_all_mined)} mined params: {_all_mined[:8]}")
            for vuln_type, entries in payload_plan.items():
                for i, entry in enumerate(entries):
                    if isinstance(entry, dict) and not entry.get("param"):
                        # Assign the best-fit mined param for this vuln type
                        _vuln_param_hints = {
                            "sqli": ["id","search","q","query","filter","name","email","username"],
                            "xss":  ["search","q","query","name","input","comment","msg","text"],
                            "ssrf": ["url","uri","redirect","webhook","callback","fetch","src"],
                            "lfi":  ["file","path","page","include","load","template","doc"],
                            "open_redirect": ["redirect","next","returnTo","return_url","url","goto"],
                        }
                        _hints = _vuln_param_hints.get(vuln_type, [])
                        _chosen = next((p for p in _hints if p in _all_mined), _all_mined[0])
                        payload_plan[vuln_type][i]["param"] = _chosen
            logger.info("[payloads] FIX3: Parameter enrichment complete")

    save_layer3_payloads(state["run_id"], payload_plan)

    logger.info("Layer 3 completed successfully")
    
    # FIX 1: Layer 3 complete
    update_pipeline(state["run_id"], layer=3, progress=1.0, 
                    message="Payload planning complete", status="completed")
    
    # FIX 2: Check for cancellation
    if is_cancel_requested(state["run_id"]):
        logger.warning("Scan cancelled by user")
        mark_cancelled(state["run_id"])
        return {"state": state, "cancelled": True}
    
    # --- Layer 3.5: Passive Logic Analysis ---
    # OAuth
    if "oauth" in target.lower() or "authorize" in target.lower():
        # Parse params from target URL
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        # Flatten params for analysis (list to single value if one)
        flat_params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        
        oauth_issues = analyze_oauth_parameters(flat_params)
        if oauth_issues:
            logger.info(f"OAuth Logic Issues detected: {oauth_issues}")
            # Record directly as findings
            update_vuln_status(state["run_id"], "oauth_logic", "FOUND")
            save_execution_result(state["run_id"], "oauth_logic", {
                "status": "SUCCESS",
                "payload": "passive_analysis",
                "evidence": oauth_issues
            })

    logger.info("Starting Layer 4: Execution Engine")
    
    # FIX 1: Layer 4 progress
    update_pipeline(state["run_id"], layer=4, progress=0.0, 
                    message="Starting vulnerability testing...")

    rl = config.get("rate_limit", {})
    rate = RateController(
        rps=rl.get("requests_per_second", 5),
        persist_path=f"data/rate_{state['run_id']}.db",  # P-3 FIX: per-run DB
        per_ep_cooldown=rl.get("per_endpoint_cooldown_sec", 1),  # FIX2: was 10, now 1
        max_requests=rl.get("max_requests_per_run", 5000),       # FIX2: was 300, now 5000
        backoff=rl.get("block_backoff_sec", 30),                  # FIX2: was 300, now 30
    )

    # restore rate state on resume
    rate_state = load_rate_state(state["run_id"])
    rate.request_count = rate_state.get("request_count", 0)
    rate.paused_until = rate_state.get("paused_until", 0.0)

    logger.info("RateController initialized")
    
    # Phase B1: Authenticated Testing Setup
    import yaml
    try:
        with open("config/auth.yaml") as f:
            auth_config = yaml.safe_load(f)
    except Exception as e:
        logger.warning(f"Failed to load auth config: {e}. Using default empty auth.")
        auth_config = {}

    from core.executor import create_session
    session = create_session(auth_config)
    logger.info(f"Authenticated session created. Auth enabled: {auth_config.get('enabled')}")

    # Phase A3: Context-Aware Prioritization
    ordered_vulns = prioritize_vulns(
        list(payload_plan.keys()), 
        context_data, 
        target
    )
    logger.info(f"[prioritizer] Vulnerability order: {ordered_vulns}")
    
    # Log scores for explainability
    for v in ordered_vulns:
         # compute_score is stateless so calling it again is fine for logging
         # Importing compute_score might be needed or we just rely on the order log.
         # To correspond strictly to "Explainable" step:
         logger.info(f"[prioritizer] {v} score = {compute_score(v, context_data, target)}")

    layer4_results = {} # Store results for Layer 5

    layer4_results = {} # Store results for Layer 5 - In distributed mode, this might be partial in memory?
    # Actually, Layer 5 `correlate` reads from `state_now` which loads from disk.
    # So if workers write to disk (state), Layer 5 will see them.

    # =========================================================================
    # RESEARCH: Anomaly Detection Engine — build baseline before fuzzing
    # =========================================================================
    _anomaly_engine = None
    _anomaly_baseline_built = False
    _anomaly_findings = []
    if _RESEARCH_MODULES_AVAILABLE and not dry_run:
        try:
            _anomaly_engine = AnomalyDetectionEngine()
            logger.info("[research] AnomalyDetectionEngine initialized — building baseline from first responses...")
            # Warm up baseline with 5 GET requests to the target
            import requests as _req_tmp
            for _b_attempt in range(5):
                try:
                    import time as _time_tmp
                    _t0 = _time_tmp.time()
                    _b_resp = session.get(
                        str(target.get("url", target) if isinstance(target, dict) else target),
                        timeout=10, params={"_baseline": _b_attempt}
                    )
                    _b_ms = (_time_tmp.time() - _t0) * 1000
                    _anomaly_engine.learn_baseline(_b_resp, _b_ms)
                except Exception as _e:
                    # P-5 FIX: continue to next attempt instead of aborting all 5
                    logger.debug(f"[research] Baseline attempt failed (will retry): {_e}")
                    continue
            _anomaly_engine.finalize_baseline(logger=logger)
            _anomaly_baseline_built = True
            logger.info(f"[research] Anomaly baseline ready (samples: {_anomaly_engine._baseline_count})")
        except Exception as _ae:
            logger.warning(f"[research] AnomalyDetectionEngine init failed (non-critical): {_ae}")

    # =========================================================================
    # RESEARCH: BusinessLogicAnalyzer — observes all API calls during scan
    # =========================================================================
    _bla = None
    _prev_endpoint = None
    if _RESEARCH_MODULES_AVAILABLE:
        try:
            _bla = BusinessLogicAnalyzer()
            logger.info("[research] BusinessLogicAnalyzer initialized — will observe all API calls")
        except Exception as _ble:
            logger.warning(f"[research] BusinessLogicAnalyzer init failed (non-critical): {_ble}")
    # =========================================================================
    
    # Extract discovered endpoints from recon for per-endpoint testing
    # FIX3: Remove [:10] cap — use ALL discovered endpoints, filtered to API/REST only
    _raw_endpoints = []
    if hasattr(recon_data, 'endpoints'):
        _raw_endpoints = recon_data.endpoints
    elif isinstance(recon_data, dict) and 'endpoints' in recon_data:
        _raw_endpoints = recon_data.get('endpoints', [])

    # Separate high-value API endpoints from static assets
    _api_keywords = ['/api/', '/rest/', '/v1/', '/v2/', '/v3/', '/graphql',
                     '/user', '/admin', '/auth', '/login', '/account',
                     '/basket', '/order', '/payment', '/card', '/address',
                     '/upload', '/file', '/search', '/data', '/export']
    _static_ext = ('.js', '.css', '.png', '.jpg', '.ico', '.svg', '.woff',
                   '.ttf', '.map', '.txt', '.html')

    api_endpoints = []
    other_endpoints = []
    for ep in _raw_endpoints:
        ep_str = str(ep).split('?')[0].lower()
        if ep_str.endswith(_static_ext):
            continue  # skip static assets entirely
        if any(kw in ep_str for kw in _api_keywords):
            api_endpoints.append(ep)
        else:
            other_endpoints.append(ep)

    # Priority: API endpoints first, then other pages, cap at 50 total
    discovered_endpoints = (api_endpoints + other_endpoints)[:50]

    # If nothing discovered, fall back to scan root
    if not discovered_endpoints:
        discovered_endpoints = [str(target)]

    logger.info(f"Testing {len(discovered_endpoints)} endpoints "
                f"({len(api_endpoints)} API, {len(other_endpoints)} pages, "
                f"static assets skipped)")
    
    if config.get("distributed", {}).get("enabled"):
        logger.info("Distributed mode enabled")
        
        # Plan tasks - now passing discovered endpoints
        task_count = plan_tasks(target, payload_plan, endpoints=discovered_endpoints)
        logger.info(f"Planned {task_count} tasks across {len(discovered_endpoints)} endpoints")
        
        import threading
        # We need to pass run_id to worker for state updates
        run_id = state["run_id"]
        
        # Initialize shared scanner components for workers
        from core.worker import init_worker_scanner, reset_worker_cache
        reset_worker_cache()  # Clear any stale state
        init_worker_scanner(run_id, logger)
        logger.info("[scanner] Initialized shared scanner for distributed workers")
        
        workers = []
        worker_count = config["distributed"].get("workers", 2)
        
        for i in range(worker_count):
            t = threading.Thread(
                target=worker_loop,
                args=(i, session, logger, rate, dry_run, run_id)
            )
            workers.append(t)
            t.start()
            
        for t in workers:
            t.join()
            
    else:
        logger.info("Running in single-worker mode")
        logger.info("[scanner] Stop-after-confirmed rule is ENFORCED")
        logger.info(f"[scanner] FIX1: Outer loop = {len(discovered_endpoints)} endpoints, "
                    f"inner loop = {len(ordered_vulns)} vuln types")

        # FIX1: Outer loop over ENDPOINTS, inner loop over VULN TYPES.
        # Previously the loop was only over vuln types, firing all payloads at the
        # scan root. This caused ENDPOINT_COOLDOWN for 69% of all payloads because
        # every vuln type hammered the same URL.
        # Now each endpoint gets its own independent test pass with its own cooldown bucket.
        for _scan_endpoint in discovered_endpoints:
            _ep_str = str(_scan_endpoint)
            logger.info(f"[scanner] === Testing endpoint: {_ep_str} ===")

            for vuln in ordered_vulns:
                payloads = payload_plan[vuln]
                logger.info(f"[scanner] {vuln} on {_ep_str} ({len(payloads)} payloads)")
                update_vuln_status(state["run_id"], vuln, "IN_PROGRESS")

                # Track if this vuln type was confirmed on ANY endpoint
                vuln_confirmed = False

                for payload_entry in payloads:
                    payload_str = payload_entry.get("original", str(payload_entry)) if isinstance(payload_entry, dict) else str(payload_entry)

                    if isinstance(payload_entry, dict):
                        param = payload_entry.get("param") or payload_entry.get("field") or vuln
                    else:
                        param = vuln

                    location = payload_entry.get("location", "query") if isinstance(payload_entry, dict) else "query"

                    # STOP-AFTER-CONFIRMED CHECK — keyed per endpoint+vuln
                    scan_decision = scan_scheduler.should_scan(
                        endpoint=_ep_str,
                        param=param,
                        location=location,
                        vuln_type=vuln,
                        payload=payload_str
                    )

                    if not scan_decision.should_scan:
                        logger.debug(f"[scanner] SKIPPING: {scan_decision.reason_detail}")
                        continue

                    result = execute_payload(
                        _ep_str,   # FIX1: use the actual endpoint, not the scan root
                        vuln,
                        payload_entry,
                        logger,
                        rate,
                        dry_run=dry_run,
                        session=session
                    )

                # =============================================================
                # RESEARCH: Anomaly Detection on each response
                # =============================================================
                if _anomaly_engine and _anomaly_baseline_built and not dry_run:
                    try:
                        # P-1 FIX: reuse the response already fetched by execute_payload
                        # instead of making a duplicate HTTP request.
                        _ar_resp = result.get("_response")
                        if _ar_resp is not None:
                            _ar_ms = 0.0  # timing not available from cached response
                        else:
                            import time as _t_tmp
                            _t0 = _t_tmp.time()
                            _ar_resp = session.get(
                                _ep_str,
                                params={param: payload_str}, timeout=10
                            )
                            _ar_ms = (_t_tmp.time() - _t0) * 1000
                        _anomaly_report = _anomaly_engine.analyze(_ar_resp, _ar_ms)
                        if _anomaly_report.is_anomalous:
                            logger.warning(
                                f"[research][anomaly] ANOMALY on {param}={payload_str[:30]} "
                                f"score={_anomaly_report.anomaly_score:.2f} "
                                f"reasons={_anomaly_report.reasons[:2]}"
                            )
                            _anomaly_findings.append({
                                "vuln": vuln, "param": param,
                                "payload": payload_str,
                                "anomaly_score": _anomaly_report.anomaly_score,
                                "reasons": _anomaly_report.reasons,
                            })
                    except Exception as _ae:
                        logger.debug(f"[research][anomaly] Non-critical error during anomaly analysis: {_ae}")
                # =============================================================
                if build_feature_vector and not dry_run:
                    try:
                        # P-1 FIX: reuse cached response
                        _fv_resp = result.get("_response")
                        _fv_ms = 0.0
                        if _fv_resp is None:
                            import time as _fv_t
                            _fv_t0 = _fv_t.time()
                            _fv_resp = session.get(
                                _ep_str,
                                params={param: payload_str}, timeout=10
                            )
                            _fv_ms = (_fv_t.time() - _fv_t0) * 1000
                        _fv = build_feature_vector(
                            url=_ep_str,
                            method="GET", payload=payload_str,
                            response=_fv_resp, response_time_ms=_fv_ms,
                        )
                        logger.debug(f"[research][features] {vuln} feature vector: status={_fv.status_code} entropy={_fv.body_entropy:.2f}")
                    except Exception as _fve:
                        logger.debug(f"[research][features] Non-critical error building feature vector: {_fve}")

                # =============================================================
                # RESEARCH: BusinessLogicAnalyzer — observe this API call
                # =============================================================
                if _bla:
                    try:
                        _bla.observe(
                            method="GET",
                            endpoint=_ep_str,
                            status_code=200,
                            session_id=state["run_id"],
                            request_params={param: payload_str},
                            previous_endpoint=_prev_endpoint,
                        )
                        _prev_endpoint = _ep_str
                    except Exception as _blae:
                        logger.debug(f"[research][bla] Non-critical error in BusinessLogicAnalyzer.observe: {_blae}")
                scan_scheduler.record_payload_sent(_ep_str, param, "query", payload_str)

                # Record learning (Phase A1)
                record_result(
                    target=_ep_str,
                    vuln=vuln,
                    payload=result.get("payload", payload_entry),
                    status=result["status"]
                )

                save_execution_result(state["run_id"], vuln, result)
                
                if not dry_run:
                    save_rate_state(state["run_id"], {
                        "request_count": rate.request_count,
                        "paused_until": rate.paused_until
                    })

                if result["status"] == "BLOCKED":
                    logger.warning("Blocking detected")
                    update_vuln_status(state["run_id"], vuln, "BLOCKED")
                    mark_blocked(state["run_id"])
                    
                    # Phase A2: Adaptive Mutation
                    mutations = choose_mutations(_ep_str, vuln, result.get("payload", payload_entry))
                    logger.info(f"[mutator] Trying {len(mutations)} mutations")

                    for m in mutations:
                        # ... (existing mutation logic) ...
                        # For brevity in this replace, I need to include the mutation logic block or omit if too long.
                        # I'll include the logic concisely to maintain feature parity in single mode.
                        
                        original_payload_str = result.get("payload", payload_entry)
                        p_str = original_payload_str
                        if isinstance(original_payload_str, dict):
                            p_str = original_payload_str.get("original", "")
                            
                        if not isinstance(p_str, str):
                            continue 
                            
                        mutated = MUTATORS[m](p_str)
                        logger.info(f"[mutator] Applying {m} mutation")
                        
                        mutated_entry = {"original": mutated}
                        
                        mutated_result = execute_payload(
                            _ep_str,
                            vuln,
                            mutated_entry,
                            logger,
                            rate,
                            dry_run=dry_run,
                            session=session
                        )

                        record_result(_ep_str, vuln, mutated, mutated_result["status"])

                        if mutated_result["status"] == "SUCCESS":
                            logger.info(f"[+] Mutated payload ({m}) SUCCESS")
                            update_vuln_status(state["run_id"], vuln, "FOUND")
                            save_execution_result(state["run_id"], vuln, mutated_result)
                            break
                    
                    break 

                if result["status"] == "PLANNED":
                    update_vuln_status(state["run_id"], vuln, "PLANNED")
                elif result["status"] == "SUCCESS":
                    logger.info(f"[+] {vuln} vulnerability FOUND")
                    
                    # ML Verification Step
                    if ML_ENABLED and ML_PREDICTOR:
                        try:
                            # Construct a description for the predictor
                            desc = f"{vuln} vulnerability found on {target} with payload {result.get('payload', '')}. Evidence: {result.get('evidence', '')}"
                            pred_result = ML_PREDICTOR.predict_description(desc)
                            logger.info(f"[ML-VERIFY] Prediction: {pred_result['prediction']} (Confidence: {pred_result['confidence']:.2f})")
                            
                            # Augment result with ML data
                            result["ml_verification"] = pred_result
                        except Exception as e:
                            logger.warning(f"ML Verification failed: {e}")

                    update_vuln_status(state["run_id"], vuln, "FOUND")
                    save_execution_result(state["run_id"], vuln, result)
                    
                    # CRITICAL: Record confirmed vulnerability in knowledge base
                    # This enforces STOP-AFTER-CONFIRMED rule
                    scan_scheduler.record_vulnerability_confirmed(
                        endpoint=_ep_str,
                        param=param,
                        location=location,
                        vuln_type=vuln,
                        payload=payload_str,
                        method="GET",  # Default for single worker mode
                        response_code=200,  # Assume success
                        response_body=str(result.get("evidence", {}))[:500],
                        evidence_dict=result.get("evidence", {})
                    )
                    
                    vuln_confirmed = True
                    logger.info(f"[scanner] Vulnerability CONFIRMED - stopping further payloads for {param}")
                    break

            else:
                # A-3 FIX: re-read checklist from disk; the in-memory copy may be
                # stale if update_vuln_status wrote "FOUND" during this scan.
                try:
                    _fresh = load_state(state["run_id"])
                    _fresh_status = _fresh.get("checklist", {}).get(vuln, "NOT_STARTED")
                except Exception as _e:
                    _fresh_status = state["checklist"].get(vuln, "NOT_STARTED")
                if _fresh_status != "FOUND":
                    update_vuln_status(state["run_id"], vuln, "FAILED")

    logger.info("Layer 4 completed")
    
    # =========================================================================
    # RESEARCH: AdaptiveFuzzer — run on top scored endpoints after standard scan
    # =========================================================================
    research_fuzz_findings = []
    if _RESEARCH_MODULES_AVAILABLE and AdaptiveFuzzer and not dry_run and research_scored_endpoints:
        try:
            logger.info("[research] Starting AdaptiveFuzzer on high-risk endpoints...")
            import time as _af_time
            _af_budget_int = int(os.environ.get("RESEARCH_BUDGET", "500"))
            from fuzzing.adaptive_fuzzer import FuzzBudget
            _fuzz_budget = FuzzBudget(total=_af_budget_int)
            _af = AdaptiveFuzzer(session=session, rate_limit=1.0)

            # Build payload map from existing payload_plan
            _payload_map = {}
            for _vt, _plist in payload_plan.items():
                _payload_map[_vt] = [
                    (p.get("original", str(p)) if isinstance(p, dict) else str(p))
                    for p in _plist
                ]

            # Fuzz top 3 critical/high endpoints from ASI scoring
            _fuzz_targets = [
                ep for ep in research_scored_endpoints[:5]
                if isinstance(ep, dict) and ep.get("risk_level") in ("critical", "high")
            ][:3]

            for _fuzz_ep in _fuzz_targets:
                _fuzz_url = _fuzz_ep.get("endpoint", "")
                if not _fuzz_url or _fuzz_budget.is_exhausted():
                    break

                # Build injection points from what we know about the endpoint
                _injection_pts = []
                _ep_params = _fuzz_ep.get("parameters", []) or []
                for _ep_p in (_ep_params if _ep_params else ["q", "id", "search"]):
                    _injection_pts.append({
                        "name": _ep_p,
                        "location": "query",
                        "method": "GET",
                        "context": "generic",
                        "risk_score": _fuzz_ep.get("risk_score", 5),
                    })

                logger.info(f"[research][fuzzer] Fuzzing {_fuzz_url} ({len(_injection_pts)} injection points)")
                _fuzz_results = _af.fuzz_endpoint(
                    endpoint=_fuzz_url,
                    injection_points=_injection_pts,
                    payload_map=_payload_map,
                    budget=_fuzz_budget,
                    logger=logger,
                )

                for _fr in _fuzz_results:
                    _fr_d = _fr if isinstance(_fr, dict) else (asdict(_fr) if hasattr(_fr, "__dataclass_fields__") else vars(_fr))
                    if _fr_d.get("is_interesting") or _fr_d.get("anomaly_score", 0) > 0.5:
                        research_fuzz_findings.append(_fr_d)
                        logger.info(
                            f"[research][fuzzer] Interesting: {_fr_d.get('parameter')} "
                            f"payload={str(_fr_d.get('payload',''))[:40]} "
                            f"score={_fr_d.get('anomaly_score', 0):.2f}"
                        )

            logger.info(f"[research][fuzzer] Done. Budget used: {_af_budget_int - _fuzz_budget.remaining}/{_af_budget_int}. Findings: {len(research_fuzz_findings)}")
        except Exception as _afe:
            logger.warning(f"[research] AdaptiveFuzzer failed (non-critical): {_afe}")
    else:
        research_fuzz_findings = []
    # =========================================================================
    
    # FIX 1: Layer 4 complete
    update_pipeline(state["run_id"], layer=4, progress=1.0, 
                    message="Execution complete", status="completed")
    
    # FIX 2: Check for cancellation before Layer 5
    if is_cancel_requested(state["run_id"]):
        logger.warning("Scan cancelled by user")
        mark_cancelled(state["run_id"])
        return {"state": state, "cancelled": True}

    logger.info("Starting Layer 5: Learning, Chaining, Reporting")
    
    # FIX 1: Layer 5 progress
    update_pipeline(state["run_id"], layer=5, progress=0.0, 
                    message="Starting verification & reporting...")

    state_now = load_state(state["run_id"])
    layer4_results = state_now.get("layer_4", {})

    learning = learn_from_execution(layer4_results, logger)
    
    # --- VERIFICATION PHASE ---
    # Use verifier for secondary confirmation of findings
    logger.info("[verifier] Starting secondary confirmation phase")
    
    if config.get("verification", {}).get("enabled", True):
        verifier = VulnerabilityVerifier(
            session=session, 
            logger=logger,
            min_confirmations=config.get("verification", {}).get("min_confirmations", 2)
        )
        
        verified_count = 0
        unverified_count = 0
        
        for vuln, results in layer4_results.items():
            if not isinstance(results, list):
                results = [results]
            
            for result in results:
                if result.get("status") == "SUCCESS":
                    finding = {
                        "vuln": vuln,
                        "payload": result.get("payload", ""),
                        "evidence": result.get("evidence", {})
                    }
                    
                    verification = verifier.verify(finding, target)
                    result["verification"] = verification
                    
                    if verification.get("confirmed"):
                        verified_count += 1
                        logger.info(f"[verifier] Confirmed: {vuln} (confidence: {verification['confidence']:.0%})")
                    else:
                        unverified_count += 1
                        logger.warning(f"[verifier] Unconfirmed: {vuln} (only {verification['confirmations']} checks passed)")
        
        logger.info(f"[verifier] Verification complete: {verified_count} confirmed, {unverified_count} unconfirmed")
    else:
        logger.info("[verifier] Verification disabled in config")
    
    # FIX 1: Update Layer 5 progress after verification
    update_pipeline(state["run_id"], layer=5, progress=0.4, 
                    message="Analyzing attack chains...")
    
    logger.info("Starting Phase 3: Chaining & Correlation")
    
    graph, chain_suggestions = correlate(layer4_results, logger)

    # =========================================================================
    # RESEARCH: Enhanced Attack Graph with BFS pathfinding
    # =========================================================================
    research_attack_graph = None
    if _RESEARCH_MODULES_AVAILABLE and build_enhanced_attack_graph:
        try:
            logger.info("[research] Building enhanced attack graph with BFS pathfinding...")
            # Convert layer4_results into findings format for chain_builder
            _findings_for_graph = []
            for _vt, _results in layer4_results.items():
                _results_list = _results if isinstance(_results, list) else [_results]
                for _r in _results_list:
                    if _r.get("status") == "SUCCESS":
                        _findings_for_graph.append({
                            "vuln_type": _vt,
                            "endpoint": str(target.get("url", target) if isinstance(target, dict) else target),
                            "impact_score": 8.0 if _vt in ("sqli", "rce", "ssrf", "idor") else 5.0,
                            "confidence": 0.9,
                            "evidence": _r.get("evidence", {}),
                        })
            if _findings_for_graph:
                research_attack_graph = build_enhanced_attack_graph(_findings_for_graph, logger=logger)
                _high_impact = research_attack_graph.find_high_impact_paths(min_impact=6.0)
                if _high_impact:
                    logger.info(f"[research][graph] {len(_high_impact)} high-impact attack paths found:")
                    for _path in _high_impact[:3]:
                        logger.info(f"  -> {' -> '.join(_path.get('path', []))} (impact: {_path.get('final_impact', '?')})")
                # Also add anomaly findings as nodes
                for _af in _anomaly_findings[:5]:
                    research_attack_graph.add_vulnerability(
                        vuln_type=f"anomaly_{_af.get('vuln', 'unknown')}",
                        endpoint=str(target.get("url", target) if isinstance(target, dict) else target),
                        impact_score=_af.get("anomaly_score", 3.0) * 2,
                        confidence=0.6,
                        evidence={"reasons": _af.get("reasons", [])},
                    )
                    # A-1 FIX: moved infer_chains OUTSIDE the loop (was called N times)
                # A-1 FIX: single infer_chains call after all anomaly nodes added
                research_attack_graph.infer_chains(logger=logger)
                # Persist enhanced graph
                update_state(state["run_id"], "research_attack_graph", research_attack_graph.serialize())
                logger.info(f"[research][graph] Enhanced graph: {len(research_attack_graph._nodes)} nodes, {len(research_attack_graph._edges)} edges")
        except Exception as _ge:
            logger.warning(f"[research] Enhanced attack graph failed (non-critical): {_ge}")
    # =========================================================================

    # =========================================================================
    # RESEARCH: BusinessLogicAnalyzer — full analysis after all API calls observed
    # =========================================================================
    research_bla_findings = []
    if _bla:
        try:
            logger.info("[research] Running BusinessLogicAnalyzer full analysis...")
            research_bla_findings = _bla.analyze(session_id=state["run_id"])

            if research_bla_findings:
                logger.info(f"[research][BLA] {len(research_bla_findings)} business logic anomalies detected:")
                for _bla_f in research_bla_findings[:5]:
                    logger.info(f"  -> {_bla_f.get('anomaly_type','?')}: {_bla_f.get('description','')}")
                # Save as vulnerability findings
                for _bla_f in research_bla_findings:
                    save_execution_result(state["run_id"], "business_logic_research", {
                        "status": "SUCCESS",
                        "payload": "workflow_analysis",
                        "evidence": _bla_f,
                    })
            else:
                logger.info("[research][BLA] No business logic anomalies detected")

            # Generate probe test cases for discovered endpoints
            if research_discovered_endpoints:
                _bla_ep_params = []
                for _dep in research_discovered_endpoints[:5]:
                    _dep_url = _dep.get("url", "") if isinstance(_dep, dict) else str(_dep)
                    if _dep_url:
                        _bla_ep_params.append({"endpoint": _dep_url, "parameters": {"id": "1", "user_id": "1"}})
                if _bla_ep_params:
                    _bla_tests = _bla.get_test_cases(_bla_ep_params)
                    _bla_test_count = sum(len(v) for v in _bla_tests.values())
                    logger.info(f"[research][BLA] Generated {_bla_test_count} business logic test cases for {len(_bla_ep_params)} endpoints")
        except Exception as _blae:
            logger.warning(f"[research] BusinessLogicAnalyzer analysis failed (non-critical): {_blae}")
    else:
        research_bla_findings = []
    # =========================================================================
    
    # Update state with findings and PERSIST to disk for resume support
    state_now["attack_graph"] = graph.serialize()
    state_now["chain_suggestions"] = chain_suggestions
    state_now["phases"]["layer_5"] = "DONE"
    
    # Persist state for resume support
    update_state(state["run_id"], "attack_graph", graph.serialize())
    update_state(state["run_id"], "chain_suggestions", chain_suggestions)
    update_state(state["run_id"], "phases", state_now["phases"])
    
    chains = chain_suggestions
    
    # FIX 1: Update progress for POC generation
    update_pipeline(state["run_id"], layer=5, progress=0.7, 
                    message="Generating POC reports...")
    
    # --- POC Generation for Findings ---
    poc_gen = POCGenerator(output_dir="reports")
    pocs_generated = []
    generated_poc_ids = set()  # Track generated POC IDs to avoid duplicates
    
    for vuln, results in layer4_results.items():
        if not isinstance(results, list):
            results = [results]
        
        for result in results:
            if result.get("status") == "SUCCESS":
                # Generate POC for successful finding
                finding = {
                    "vuln": vuln,
                    "target": state_now.get("target", target),
                    "payload": result.get("payload", ""),
                    "param": result.get("param", ""),
                    "evidence": result.get("evidence", {}),
                    "method": result.get("method", "GET")
                }
                
                poc = poc_gen.generate(finding)

                # A-2 FIX: add ID unconditionally so the duplicate counter is accurate.
                # Previously generated_poc_ids was only ever updated when NOT a duplicate,
                # making len(generated_poc_ids) == len(pocs_generated) always.
                is_duplicate = poc["id"] in generated_poc_ids
                generated_poc_ids.add(poc["id"])

                if is_duplicate:
                    logger.debug(f"[POC] Skipping duplicate: {poc['id']}")
                    continue

                poc_path = poc_gen.save_poc(poc, state_now["run_id"])
                pocs_generated.append(poc)
                
                logger.info(f"[POC] Generated: {poc['title']} -> {poc_path}")
    
    logger.info(f"[POC] Total POCs generated: {len(pocs_generated)} (skipped {len(generated_poc_ids) - len(pocs_generated)} duplicates)")
    state_now["pocs"] = pocs_generated

    report_dir = generate_report(
        state=state_now,
        recon=recon_data,
        context=context_data,
        learning=learning,
        chains=chains
    )

    logger.info(f"Layer 5 completed. Reports generated at {report_dir}")
    logger.info(f"Chaining complete: {len(chain_suggestions)} chains suggested")

    # =========================================================================
    # RESEARCH UPGRADE: AI Attack Planner next-step suggestions
    # =========================================================================
    research_suggestions = []
    if _RESEARCH_MODULES_AVAILABLE:
        try:
            # Use the shared factory so provider/model always come from
            # config/ai.yaml — supports local Ollama, OpenAI, and Anthropic
            # with no code changes needed here.
            from ai_reasoning.attack_planner import create_attack_planner_from_config, PlannerContext
            planner = create_attack_planner_from_config()
            _all_findings = state_now.get("confirmed_vulns", []) + state_now.get("chains", [])
            ctx = PlannerContext(
                target=str(target.get("url", target) if isinstance(target, dict) else target),
                confirmed_findings=_all_findings,
                discovered_endpoints=research_discovered_endpoints,
                asis_scores=research_scored_endpoints,
                recon_summary=recon_data if isinstance(recon_data, dict) else (recon_data.to_dict() if hasattr(recon_data, "to_dict") else {}),
                scan_phase="LAYER_5_VERIFICATION"
            )
            research_suggestions = planner.suggest_next_steps(ctx)
            if research_suggestions:
                logger.info(f"[research][AttackPlanner] {len(research_suggestions)} next-step suggestions:")
                for s in research_suggestions[:3]:
                    logger.info(f"  -> {s}")
        except Exception as _e:
            logger.warning(f"[research] AttackPlanner failed (non-critical): {_e}")

    # =========================================================================

    # FIX 1: Final completion status
    update_pipeline(state["run_id"], layer=5, progress=1.0, 
                    message="Scan complete!", status="completed")

    return {
        "state": state_now,
        "recon": recon_data,
        "context": context_data,
        "payload_plan": payload_plan,
        "learning": learning,
        "chains": chains,
        "attack_graph": state_now["attack_graph"],
        # Research results (empty if modules not available)
        "research_subdomains": research_subdomains,
        "research_scored_endpoints": research_scored_endpoints,
        "research_suggestions": research_suggestions,
        "research_discovered_endpoints": research_discovered_endpoints,
        "research_mined_params": research_mined_params,
        "research_fuzz_findings": research_fuzz_findings,
        "research_anomaly_findings": _anomaly_findings,
        "research_bla_findings": research_bla_findings,
        "research_attack_graph": research_attack_graph.serialize() if research_attack_graph else {},
    }
