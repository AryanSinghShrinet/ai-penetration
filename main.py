"""
AI Penetration Research Tool — Main Entry Point (Research Edition)
=================================================================
New CLI flags: --phase, --budget, --threads, --verbose
Old flags preserved: --target, --config, --dry-run

Usage examples:
  python main.py --target https://example.com --dry-run
  python main.py --target https://example.com --phase recon --dry-run --verbose
  python main.py --target https://example.com --phase fuzz --budget 500 --threads 4
  python main.py --target https://example.com --phase all --verbose
  python main.py --target https://example.com --legacy   (runs old main_old.py behaviour)
"""

import argparse
import sys
import os
import io
from dotenv import load_dotenv

load_dotenv()

# Fix Windows CP1252 UnicodeEncodeError (e.g. → arrow character)
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


_MODULE_DOC = __doc__  # B-6 FIX: capture before any def shadows __doc__
def parse_args():
    parser = argparse.ArgumentParser(
        description="AI Penetration Research Tool — Research Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_MODULE_DOC
    )

    # Core args (backward compatible with old main.py)
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL or domain (e.g. https://example.com)"
    )
    parser.add_argument(
        "--config", "-c",
        default="config/settings.yaml",
        help="Path to config YAML file (default: config/settings.yaml)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Dry-run mode: no active requests sent"
    )

    # New research args
    parser.add_argument(
        "--phase",
        choices=["all", "recon", "fuzz", "chain", "report"],
        default="all",
        help="Execution phase to run (default: all)"
    )
    parser.add_argument(
        "--budget",
        type=int,
        default=10000,
        help="Fuzzing request budget (default: 10000)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=4,
        help="Number of worker threads (default: 4)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Verbose output"
    )

    # Rollback / backward compat
    parser.add_argument(
        "--legacy",
        action="store_true",
        default=False,
        help="Use legacy main_old.py entry point (for backward compatibility)"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    # Fallback to legacy entry point if requested
    if args.legacy:
        print("[main] --legacy flag set: delegating to main_old.py")
        from main_old import main as legacy_main
        sys.exit(legacy_main())

    # --- Banner ---
    print("=" * 60)
    print("  AI Penetration Research Tool  [Research Edition]")
    print(f"  Target : {args.target}")
    print(f"  Phase  : {args.phase}")
    print(f"  Budget : {args.budget} requests")
    print(f"  Threads: {args.threads}")
    print(f"  Dry-run: {args.dry_run}")
    print("=" * 60)

    # Set env vars so orchestrator and workers can read them
    os.environ["RESEARCH_PHASE"] = args.phase
    os.environ["RESEARCH_BUDGET"] = str(args.budget)
    os.environ["RESEARCH_THREADS"] = str(args.threads)
    os.environ["RESEARCH_VERBOSE"] = "1" if args.verbose else "0"

    # Import orchestrator (works whether research modules are available or not)
    try:
        from core.orchestrator import start
    except ImportError as e:
        print(f"[ERROR] Could not import core.orchestrator: {e}")
        sys.exit(1)

    # Run
    result = start(
        target=args.target,
        config_path=args.config,
        dry_run=args.dry_run,
        phase=args.phase,
    )

    if result and result.get("cancelled"):
        print("\n[main] Scan was cancelled by user.")
        sys.exit(0)

    # Print research extras if verbose
    if args.verbose and result:
        subs = result.get("research_subdomains", [])
        if subs:
            print(f"\n[research] Subdomains discovered: {len(subs)}")
            for s in subs[:10]:
                print(f"  {s}")

        disc_eps = result.get("research_discovered_endpoints", [])
        if disc_eps:
            print(f"\n[research] Hidden endpoints found: {len(disc_eps)}")
            for ep in disc_eps[:10]:
                url = ep.get("url", ep) if isinstance(ep, dict) else str(ep)
                status = ep.get("status_code", "?") if isinstance(ep, dict) else "?"
                print(f"  [{status}] {url}")

        mined = result.get("research_mined_params", [])
        if mined:
            total_params = sum(r.get("count", 0) for r in mined)
            print(f"\n[research] Hidden parameters found: {total_params} across {len(mined)} endpoints")
            for pm_r in mined[:5]:
                print(f"  {pm_r.get('endpoint','')} -> {pm_r.get('count',0)} params")

        scored = result.get("research_scored_endpoints", [])
        if scored:
            print(f"\n[research] High-risk endpoints (ASI scored):")
            for ep in scored[:5]:
                print(f"  [{ep.get('risk_level','?'):8s}] {ep.get('endpoint','?')}")

        anomalies = result.get("research_anomaly_findings", [])
        if anomalies:
            print(f"\n[research] Anomaly detection findings: {len(anomalies)}")
            for a in anomalies[:5]:
                print(f"  {a.get('vuln','?')} param={a.get('param','?')} score={a.get('anomaly_score',0):.2f}")

        fuzz = result.get("research_fuzz_findings", [])
        if fuzz:
            print(f"\n[research] Adaptive fuzzer findings: {len(fuzz)}")
            for f in fuzz[:5]:
                print(f"  param={f.get('parameter','?')} payload={str(f.get('payload',''))[:40]}")

        bla = result.get("research_bla_findings", [])
        if bla:
            print(f"\n[research] Business logic anomalies: {len(bla)}")
            for b in bla[:5]:
                desc = b.get('description', '').replace('\u2192', '->')
                print(f"  {b.get('anomaly_type','?')}: {desc}")

        suggestions = result.get("research_suggestions", [])
        if suggestions:
            print(f"\n[research] AttackPlanner next steps:")
            for s in suggestions[:5]:
                print(f"  -> {s}")

    print("\n[main] Done.")


if __name__ == "__main__":
    main()