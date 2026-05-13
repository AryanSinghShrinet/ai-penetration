from core.recon.passive import analyze_passive
from core.recon.behavioral import profile_behavior
from core.recon.graph import build_graphs
from core.recon.trust import map_trust_boundaries
from core.recon.scoring import calculate_risk_scores
from core.recon.profile import ReconProfile
from core.recon.crawler import Crawler
from core.scope import is_url_in_scope
import requests
import urllib3

# Suppress SSL warnings for security testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def recon_target(target, logger):
    """
    Main entry point for Recon v2.
    Orchestrates all intelligence layers and builds a ReconProfile.
    """
    logger.info("=== Recon v2 Phase Started (Advanced Intelligence) ===")
    
    # Initialize Canonical Profile
    profile = ReconProfile(target)
    
    # Create session for recon with SSL verification disabled for security testing
    session = requests.Session()
    session.verify = False  # Disable SSL verification for HTTPS targets
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    # Layer 1: Passive
    # analyze_passive returns a dict (legacy structure) and response object
    passive_data, response = analyze_passive(target, logger, session=session)
    
    # Populate profile from passive data
    profile.status_code = passive_data.get("status_code")
    profile.headers = passive_data.get("headers", {})
    profile.server = passive_data.get("server", "")
    profile.content_type = passive_data.get("content_type", "")
    profile.endpoints = passive_data.get("endpoints", [])
    profile.parameters = passive_data.get("parameters", [])
    profile.forms = passive_data.get("forms", [])
    profile.cookies = passive_data.get("cookies", [])
    profile.technologies = passive_data.get("technologies", [])
    profile.hidden_elements = passive_data.get("hidden_elements", [])
    profile.comments = passive_data.get("comments", [])
    
    # NEW: Store passive security findings
    profile.passive_findings = passive_data.get("passive_findings", {})
    
    # =========================================================================
    # Layer 1.5: Web Crawling (with JS extraction)
    # =========================================================================
    logger.info("  [1.5/6] Running Web Crawler with JS extraction...")
    
    try:
        # Create scope checker function
        def scope_checker(url, log):
            return is_url_in_scope(url, log)
        
        crawler = Crawler(
            base_url=target,
            max_depth=3,
            max_pages=50  # Conservative limit to avoid scan storms
        )
        
        crawl_result = crawler.crawl(
            session=session,
            logger=logger,
            scope_checker=scope_checker
        )
        
        # Merge crawler discoveries into profile
        crawled_endpoints = crawl_result.get("endpoints", [])
        js_endpoints = crawl_result.get("js_endpoints", [])
        crawled_params = crawl_result.get("parameters", [])
        crawled_forms = crawl_result.get("forms", [])
        
        # NEW: Get endpoint details with HTTP methods
        endpoint_methods = crawl_result.get("endpoint_methods", {})
        endpoint_details = crawl_result.get("endpoint_details", [])
        
        # Deduplicate and merge
        existing_endpoints = set(profile.endpoints)
        for ep in crawled_endpoints + js_endpoints:
            if ep not in existing_endpoints:
                profile.endpoints.append(ep)
                existing_endpoints.add(ep)
        
        for param in crawled_params:
            if param not in profile.parameters:
                profile.parameters.append(param)
        
        for form in crawled_forms:
            if form not in profile.forms:
                profile.forms.append(form)
        
        # NEW: Store endpoint methods for exploitation
        profile.endpoint_methods = endpoint_methods
        profile.endpoint_details = endpoint_details
        
        methods_discovered = crawl_result.get('stats', {}).get('methods_discovered', 0)
        logger.info(f"  [crawler] Discovered: {len(crawled_endpoints)} pages, "
                   f"{len(js_endpoints)} JS endpoints, "
                   f"{methods_discovered} methods discovered, "
                   f"{crawl_result.get('stats', {}).get('duplicates_skipped', 0)} duplicates skipped")
        
    except Exception as e:
        logger.warning(f"  [crawler] Crawling failed: {e}")
    
    # Layer 2: Behavioral
    behavior_profile = profile_behavior(target, response, logger)
    # Store behavior in profile (maybe add a field or put in hypotheses/metrics)
    # For now, let's add it to a custom attribute or just keep it in hypotheses logic
    if behavior_profile.get("auth_enforced"):
         profile.add_hypothesis("auth_bypass", "low", "Auth differentiation detected")
    
    # Layer 3 & 4: Graphs
    # build_graphs expects dict, profile works due to __getitem__
    entity_graph, workflow_graph = build_graphs(profile, logger)
    profile.entities = entity_graph
    profile.workflows = workflow_graph
    
    # Layer 5: Trust
    trust_boundaries = map_trust_boundaries(profile, logger)
    profile.trust_boundaries = trust_boundaries
    
    # Layer 6: Scoring
    ranked_targets = calculate_risk_scores(profile, logger)
    profile.risk_scores = ranked_targets
    
    logger.info("=== Recon v2 Phase Completed ===")
    
    # Summary Logging
    logger.info(f"Endpoints: {len(profile.endpoints)} | Entities: {len(profile.entities)}")
    logger.info(f"Risk High Targets: {len([t for t in profile.risk_scores if t['risk_score'] > 5])}")
    
    return profile
