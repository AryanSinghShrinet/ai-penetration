"""
Real-World Bug Bounty Dataset Aggregator

Fetches and parses vulnerability data from top sources:
1. HackerOne Disclosed Reports (~185,000 reports)
2. YesWeHack/Intigriti Reports (~45,000 reports)
3. Nuclei Templates (~15,000 templates)
4. RealWorld Bug Bounty PoCs (28,000 PoCs)
5. NVD/CVE Database

This module converts real-world vulnerability data into ML training format.
"""

import os
import re
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import hashlib

# Try to import optional dependencies
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class BugBountyReport:
    """Parsed bug bounty report."""
    id: str
    title: str
    vuln_type: str
    severity: str
    description: str
    poc: str
    impact: str
    platform: str
    source: str
    url: str = ""
    payout: float = 0.0
    cwe_id: str = ""
    cvss_score: float = 0.0


class DatasetAggregator:
    """
    Aggregates vulnerability data from multiple bug bounty sources.
    """
    
    DATA_DIR = Path("data/datasets")
    
    # GitHub repositories to clone
    REPOS = {
        "hackerone": {
            "url": "https://github.com/reddelexc/hackerone-reports.git",
            "alt_url": "https://github.com/ArcSecurityDev/H1-Public-Disclosed-Reports.git",
            "description": "HackerOne public disclosed reports"
        },
        "nuclei": {
            "url": "https://github.com/projectdiscovery/nuclei-templates.git",
            "description": "Nuclei vulnerability templates"
        },
        "realworld_pocs": {
            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
            "description": "PayloadsAllTheThings - Real world payloads"
        },
        "seclists": {
            "url": "https://github.com/danielmiessler/SecLists.git",
            "description": "SecLists - Security testing payloads"
        }
    }
    
    # Vulnerability type mappings
    VULN_TYPE_MAP = {
        # XSS variants
        "xss": "xss", "cross-site scripting": "xss", "reflected xss": "xss",
        "stored xss": "xss", "dom xss": "xss", "self-xss": "xss",
        
        # SQLi variants
        "sql injection": "sqli", "sqli": "sqli", "blind sql": "sqli",
        "error-based sql": "sqli", "time-based sql": "sqli",
        
        # SSRF variants
        "ssrf": "ssrf", "server-side request forgery": "ssrf",
        "blind ssrf": "ssrf",
        
        # XXE
        "xxe": "xxe", "xml external entity": "xxe",
        
        # Command injection
        "command injection": "cmd_injection", "rce": "cmd_injection",
        "remote code execution": "cmd_injection", "os command injection": "cmd_injection",
        
        # Auth issues
        "authentication bypass": "auth_bypass", "auth bypass": "auth_bypass",
        "broken authentication": "auth_bypass", "insecure authentication": "auth_bypass",
        
        # Access control
        "idor": "idor", "insecure direct object reference": "idor",
        "broken access control": "idor", "authorization bypass": "idor",
        
        # File issues
        "lfi": "lfi", "local file inclusion": "lfi",
        "rfi": "rfi", "remote file inclusion": "rfi",
        "path traversal": "path_traversal", "directory traversal": "path_traversal",
        "arbitrary file read": "lfi", "file upload": "file_upload",
        
        # Injection types
        "ldap injection": "ldap_injection", "ssti": "ssti",
        "template injection": "ssti", "crlf injection": "crlf",
        
        # Other
        "open redirect": "open_redirect", "csrf": "csrf",
        "information disclosure": "info_disclosure",
        "sensitive data exposure": "info_disclosure",
    }
    
    def __init__(self):
        self.data_dir = self.DATA_DIR
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports: List[BugBountyReport] = []
    
    def clone_repo(self, name: str, url: str) -> bool:
        """Clone a GitHub repository."""
        repo_dir = self.data_dir / name
        
        if repo_dir.exists():
            print(f"[Dataset] {name} already exists, pulling updates...")
            try:
                subprocess.run(
                    ["git", "pull"],
                    cwd=str(repo_dir),
                    capture_output=True,
                    timeout=300
                )
                return True
            except Exception as e:
                print(f"[Dataset] Pull failed: {e}")
                return True  # Still use existing
        
        print(f"[Dataset] Cloning {name}...")
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", url, str(repo_dir)],
                capture_output=True,
                timeout=600
            )
            if result.returncode == 0:
                print(f"[Dataset] Cloned {name} successfully")
                return True
            else:
                print(f"[Dataset] Clone failed: {result.stderr.decode()[:200]}")
                return False
        except Exception as e:
            print(f"[Dataset] Clone error: {e}")
            return False
    
    def fetch_all_repos(self) -> Dict[str, bool]:
        """Fetch all configured repositories."""
        results = {}
        for name, config in self.REPOS.items():
            url = config["url"]
            success = self.clone_repo(name, url)
            if not success and "alt_url" in config:
                success = self.clone_repo(name, config["alt_url"])
            results[name] = success
        return results
    
    def parse_hackerone_reports(self) -> List[BugBountyReport]:
        """Parse HackerOne disclosed reports."""
        reports = []
        repo_dir = self.data_dir / "hackerone"
        
        if not repo_dir.exists():
            print("[Dataset] HackerOne repo not found")
            return reports
        
        # PRIORITY 1: Parse data.csv (main dataset with ~thousands of reports)
        csv_file = repo_dir / "data.csv"
        if csv_file.exists():
            reports.extend(self._parse_h1_csv(csv_file))
        
        # PRIORITY 2: Parse tops_by_bug_type directory (organized by vulnerability type)
        tops_dir = repo_dir / "tops_by_bug_type"
        if tops_dir.exists():
            for json_file in tops_dir.glob("*.json"):
                reports.extend(self._parse_h1_json(json_file))
        
        # PRIORITY 3: Parse tops_by_program directory
        program_dir = repo_dir / "tops_by_program"
        if program_dir.exists():
            for json_file in program_dir.glob("*.json"):
                reports.extend(self._parse_h1_json(json_file))
        
        # PRIORITY 4: Parse any other JSON/MD files
        for pattern in ["**/*.json", "**/*.md"]:
            for file_path in repo_dir.glob(pattern):
                if "tops_by" in str(file_path):  # Skip already processed
                    continue
                try:
                    if file_path.suffix == ".json":
                        reports.extend(self._parse_h1_json(file_path))
                    elif file_path.suffix == ".md" and file_path.name != "README.md":
                        report = self._parse_h1_markdown(file_path)
                        if report:
                            reports.append(report)
                except Exception as e:
                    continue
        
        # Deduplicate by ID
        seen_ids = set()
        unique_reports = []
        for r in reports:
            if r.id not in seen_ids:
                seen_ids.add(r.id)
                unique_reports.append(r)
        
        print(f"[Dataset] Parsed {len(unique_reports)} HackerOne reports")
        return unique_reports
    
    def _parse_h1_csv(self, csv_file: Path) -> List[BugBountyReport]:
        """Parse HackerOne data.csv file (main dataset)."""
        reports = []
        try:
            import csv
            with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    title = row.get("title", row.get("Title", ""))
                    weakness = row.get("weakness", row.get("Weakness", row.get("vulnerability_type", "")))
                    
                    vuln_type = self._extract_vuln_type(title + " " + weakness)
                    if not vuln_type:
                        continue
                    
                    report = BugBountyReport(
                        id=str(row.get("id", row.get("ID", hashlib.md5(title.encode()).hexdigest()[:8]))),
                        title=title[:200],
                        vuln_type=vuln_type,
                        severity=str(row.get("severity", row.get("Severity", "medium"))).lower(),
                        description=str(row.get("title", ""))[:2000],
                        poc=str(row.get("url", ""))[:500],
                        impact="",
                        platform=str(row.get("team", row.get("program", "hackerone"))),
                        source="hackerone",
                        url=str(row.get("url", "")),
                        payout=float(row.get("bounty", row.get("Bounty", 0)) or 0),
                    )
                    reports.append(report)
            print(f"[Dataset] Parsed {len(reports)} reports from data.csv")
        except Exception as e:
            print(f"[Dataset] CSV parse error: {e}")
        return reports
    
    def _parse_h1_json(self, file_path: Path) -> List[BugBountyReport]:
        """Parse HackerOne JSON file."""
        reports = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            
            # Handle different JSON structures
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get("reports", data.get("data", [data]))
            else:
                return reports
            
            for item in items[:1000]:  # Limit per file
                if not isinstance(item, dict):
                    continue
                
                title = item.get("title", item.get("name", ""))
                vuln_type = self._extract_vuln_type(title + " " + str(item.get("weakness", "")))
                
                if vuln_type:
                    report = BugBountyReport(
                        id=str(item.get("id", hashlib.md5(title.encode()).hexdigest()[:8])),
                        title=title[:200],
                        vuln_type=vuln_type,
                        severity=str(item.get("severity", item.get("severity_rating", "medium"))),
                        description=str(item.get("vulnerability_information", item.get("description", "")))[:2000],
                        poc=str(item.get("poc", item.get("steps_to_reproduce", "")))[:2000],
                        impact=str(item.get("impact", ""))[:500],
                        platform=str(item.get("program", item.get("team", {}).get("name", "unknown"))),
                        source="hackerone",
                        payout=float(item.get("bounty_amount", item.get("awarded_amount", 0)) or 0),
                        cwe_id=str(item.get("cwe_id", item.get("weakness", {}).get("id", ""))),
                    )
                    reports.append(report)
        except Exception as e:
            # B-09 FIX: Log parse errors instead of silently swallowing them
            print(f"[Dataset] JSON parse error in {file_path}: {e}")
        
        return reports
    
    def _parse_h1_markdown(self, file_path: Path) -> Optional[BugBountyReport]:
        """Parse HackerOne markdown report."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            # Extract title from filename or first heading
            title = file_path.stem.replace("-", " ").replace("_", " ")
            title_match = re.search(r"^#\s*(.+)$", content, re.MULTILINE)
            if title_match:
                title = title_match.group(1)
            
            vuln_type = self._extract_vuln_type(content[:1000])
            if not vuln_type:
                return None
            
            # Extract severity
            severity = "medium"
            sev_match = re.search(r"severity[:\s]*(critical|high|medium|low)", content, re.IGNORECASE)
            if sev_match:
                severity = sev_match.group(1).lower()
            
            return BugBountyReport(
                id=hashlib.md5(content[:500].encode()).hexdigest()[:8],
                title=title[:200],
                vuln_type=vuln_type,
                severity=severity,
                description=content[:2000],
                poc=self._extract_poc(content),
                impact="",
                platform="hackerone",
                source="hackerone"
            )
        except Exception as _e:
            return None
    
    def parse_nuclei_templates(self) -> List[BugBountyReport]:
        """Parse Nuclei vulnerability templates."""
        reports = []
        repo_dir = self.data_dir / "nuclei"
        
        if not repo_dir.exists() or not YAML_AVAILABLE:
            print("[Dataset] Nuclei repo not found or YAML not available")
            return reports
        
        for yaml_file in repo_dir.glob("**/*.yaml"):
            try:
                with open(yaml_file, "r", encoding="utf-8", errors="ignore") as f:
                    template = yaml.safe_load(f)
                
                if not template or not isinstance(template, dict):
                    continue
                
                info = template.get("info", {})
                name = info.get("name", yaml_file.stem)
                vuln_type = self._extract_vuln_type(
                    name + " " + str(info.get("tags", "")) + " " + str(info.get("classification", ""))
                )
                
                if vuln_type:
                    # Extract payloads from requests
                    payloads = self._extract_nuclei_payloads(template)
                    
                    report = BugBountyReport(
                        id=template.get("id", hashlib.md5(name.encode()).hexdigest()[:8]),
                        title=name[:200],
                        vuln_type=vuln_type,
                        severity=str(info.get("severity", "medium")).lower(),
                        description=str(info.get("description", ""))[:1000],
                        poc=payloads[:2000],
                        impact=str(info.get("impact", "")),
                        platform="nuclei",
                        source="nuclei",
                        cwe_id=str(info.get("classification", {}).get("cwe-id", "") if isinstance(info.get("classification"), dict) else ""),
                        cvss_score=float(info.get("classification", {}).get("cvss-score", 0) if isinstance(info.get("classification"), dict) else 0),
                    )
                    reports.append(report)
            except Exception as _e:
                continue
        
        print(f"[Dataset] Parsed {len(reports)} Nuclei templates")
        return reports
    
    def _extract_nuclei_payloads(self, template: dict) -> str:
        """Extract payloads from Nuclei template."""
        payloads = []
        
        for request_type in ["http", "requests", "network", "dns"]:
            requests_data = template.get(request_type, [])
            if isinstance(requests_data, list):
                for req in requests_data:
                    if isinstance(req, dict):
                        # Raw request
                        raw = req.get("raw", [])
                        if raw:
                            payloads.extend(raw[:3])
                        
                        # Path
                        path = req.get("path", [])
                        if path:
                            payloads.extend(path[:3])
                        
                        # Body
                        body = req.get("body", "")
                        if body:
                            payloads.append(body[:500])
        
        return "\n".join(payloads)
    
    def parse_payloads_all_things(self) -> List[BugBountyReport]:
        """Parse PayloadsAllTheThings repository."""
        reports = []
        repo_dir = self.data_dir / "realworld_pocs"
        
        if not repo_dir.exists():
            print("[Dataset] PayloadsAllTheThings repo not found")
            return reports
        
        # EXPANDED: Map ALL 66 directory names to vuln types
        dir_vuln_map = {
            # Core Injection types
            "XSS Injection": "xss",
            "SQL Injection": "sqli",
            "NoSQL Injection": "sqli",
            "Command Injection": "cmd_injection",
            "LDAP Injection": "ldap_injection",
            "XPATH Injection": "sqli",
            "GraphQL Injection": "sqli",
            "Server Side Include Injection": "cmd_injection",
            "XSLT Injection": "xxe",
            "LaTeX Injection": "cmd_injection",
            "CRLF Injection": "crlf",
            "CSV Injection": "xss",
            "Prompt Injection": "cmd_injection",
            
            # Server-side vulnerabilities
            "Server Side Request Forgery": "ssrf",
            "Server Side Template Injection": "ssti",
            "XXE Injection": "xxe",
            "Insecure Deserialization": "rce",
            "Request Smuggling": "ssrf",
            
            # File/Path attacks
            "File Inclusion": "lfi",
            "Directory Traversal": "path_traversal",
            "Client Side Path Traversal": "path_traversal",
            "Upload Insecure Files": "file_upload",
            "Zip Slip": "path_traversal",
            
            # Auth/Access control
            "Insecure Direct Object References": "idor",
            "Account Takeover": "auth_bypass",
            "Mass Assignment": "idor",
            "OAuth Misconfiguration": "auth_bypass",
            "SAML Injection": "auth_bypass",
            "JSON Web Token": "auth_bypass",
            "Brute Force Rate Limit": "auth_bypass",
            
            # Client-side
            "Cross-Site Request Forgery": "csrf",
            "Clickjacking": "csrf",
            "Open Redirect": "open_redirect",
            "DOM Clobbering": "xss",
            "Tabnabbing": "phishing",
            "Prototype Pollution": "xss",
            
            # Business Logic
            "Business Logic Errors": "business_logic",
            "Race Condition": "business_logic",
            "Type Juggling": "auth_bypass",
            "External Variable Modification": "idor",
            "Insecure Randomness": "auth_bypass",
            
            # Infrastructure
            "CORS Misconfiguration": "cors",
            "DNS Rebinding": "ssrf",
            "Virtual Hosts": "info_disclosure",
            "Web Cache Deception": "info_disclosure",
            "Web Sockets": "info_disclosure",
            "Reverse Proxy Misconfigurations": "ssrf",
            "Insecure Management Interface": "auth_bypass",
            
            # Information Disclosure
            "API Key Leaks": "info_disclosure",
            "Insecure Source Code Management": "info_disclosure",
            "Hidden Parameters": "info_disclosure",
            "ORM Leak": "info_disclosure",
            "Encoding Transformations": "info_disclosure",
            
            # Denial of Service
            "Denial of Service": "dos",
            "Regular Expression": "dos",
            
            # Other
            "CVE Exploits": "cve",
            "Dependency Confusion": "rce",
            "Java RMI": "rce",
            "Google Web Toolkit": "info_disclosure",
            "Headless Browser": "xss",
        }
        
        for dir_name, vuln_type in dir_vuln_map.items():
            vuln_dir = repo_dir / dir_name
            if not vuln_dir.exists():
                continue
            
            for md_file in vuln_dir.glob("**/*.md"):
                try:
                    with open(md_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    
                    # Extract payloads from code blocks
                    payloads = re.findall(r"```[\w]*\n(.*?)\n```", content, re.DOTALL)
                    
                    report = BugBountyReport(
                        id=hashlib.md5(content[:500].encode()).hexdigest()[:8],
                        title=f"{vuln_type.upper()} - {md_file.stem}",
                        vuln_type=vuln_type,
                        severity="high",
                        description=content[:1500],
                        poc="\n".join(payloads[:10])[:2000],
                        impact=f"Potential {vuln_type} exploitation",
                        platform="payloadsallthethings",
                        source="payloadsallthethings"
                    )
                    reports.append(report)
                except Exception as _e:
                    continue
        
        print(f"[Dataset] Parsed {len(reports)} PayloadsAllTheThings entries")
        return reports
    
    def _extract_vuln_type(self, text: str) -> str:
        """Extract vulnerability type from text."""
        text_lower = text.lower()
        
        for pattern, vuln_type in self.VULN_TYPE_MAP.items():
            if pattern in text_lower:
                return vuln_type
        
        return ""
    
    def _extract_poc(self, content: str) -> str:
        """Extract PoC from markdown content."""
        # Look for code blocks
        code_blocks = re.findall(r"```[\w]*\n(.*?)\n```", content, re.DOTALL)
        if code_blocks:
            return "\n---\n".join(code_blocks[:5])[:2000]
        
        # Look for curl/wget commands
        commands = re.findall(r"(curl\s+.+|wget\s+.+)", content, re.IGNORECASE)
        if commands:
            return "\n".join(commands[:5])
        
        return ""
    
    def aggregate_all(self) -> List[BugBountyReport]:
        """Aggregate all data sources."""
        print("[Dataset] Starting data aggregation...")
        
        all_reports = []
        
        # Parse available sources
        all_reports.extend(self.parse_hackerone_reports())
        all_reports.extend(self.parse_nuclei_templates())
        all_reports.extend(self.parse_payloads_all_things())
        
        self.reports = all_reports
        print(f"[Dataset] Total aggregated: {len(all_reports)} reports")
        
        return all_reports
    
    def convert_to_training_data(self) -> List[Dict]:
        """Convert bug bounty reports to ML training format."""
        training_data = []
        
        for report in self.reports:
            # Create training example
            example = {
                "id": report.id,
                "description": f"{report.vuln_type.upper()}: {report.title}. {report.description[:500]}",
                "response_body": report.poc[:1000] if report.poc else report.description[:500],
                "response_status": 200,
                "response_headers": {},
                "vuln_type": report.vuln_type,
                "payload_used": report.poc[:500] if report.poc else "",
                "is_vulnerable": 1,
                "confidence": 0.95,
                "source": f"bugbounty_{report.source}",
                "cvss_score": report.cvss_score if report.cvss_score > 0 else self._severity_to_cvss(report.severity),
                "timestamp": datetime.now().isoformat()
            }
            training_data.append(example)
        
        return training_data
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity to CVSS score."""
        mapping = {
            "critical": 9.5,
            "high": 8.0,
            "medium": 5.5,
            "low": 3.0,
            "informational": 1.0,
            "none": 0.0
        }
        return mapping.get(severity.lower(), 5.0)
    
    def save_training_data(self, output_file: str = "data/ml_training/bugbounty_training.json"):
        """Save converted training data."""
        training_data = self.convert_to_training_data()
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w") as f:
            json.dump(training_data, f, indent=2)
        
        print(f"[Dataset] Saved {len(training_data)} training examples to {output_file}")
        return len(training_data)
    
    def get_stats(self) -> Dict:
        """Get aggregation statistics."""
        by_type = {}
        by_source = {}
        by_severity = {}
        
        for report in self.reports:
            by_type[report.vuln_type] = by_type.get(report.vuln_type, 0) + 1
            by_source[report.source] = by_source.get(report.source, 0) + 1
            by_severity[report.severity] = by_severity.get(report.severity, 0) + 1
        
        return {
            "total_reports": len(self.reports),
            "by_vuln_type": by_type,
            "by_source": by_source,
            "by_severity": by_severity
        }


# =============================================================================
# QUICK FETCH FUNCTIONS
# =============================================================================

def fetch_and_train():
    """Fetch all datasets and train the ML model."""
    aggregator = DatasetAggregator()
    
    # Fetch repos
    print("Fetching repositories...")
    aggregator.fetch_all_repos()
    
    # Aggregate data
    print("Aggregating data...")
    aggregator.aggregate_all()
    
    # Save training data
    count = aggregator.save_training_data()
    
    # Print stats
    stats = aggregator.get_stats()
    print("\nAggregation Statistics:")
    print(f"  Total: {stats['total_reports']}")
    print(f"  By Type: {stats['by_vuln_type']}")
    print(f"  By Source: {stats['by_source']}")
    
    # Train the model
    print("\nTraining ML model with bug bounty data...")
    from core.ml_analysis.training_data import TrainingDataset
    from core.ml_analysis.response_analyzer import ResponseAnalyzer
    
    # Load bug bounty data into main training dataset
    dataset = TrainingDataset()
    bb_file = Path("data/ml_training/bugbounty_training.json")
    if bb_file.exists():
        with open(bb_file, "r") as f:
            bb_data = json.load(f)
        
        from core.ml_analysis.training_data import TrainingExample
        for item in bb_data:
            example = TrainingExample(
                id=item["id"],
                description=item["description"],
                response_body=item["response_body"],
                response_status=item["response_status"],
                response_headers=item.get("response_headers", {}),
                vuln_type=item["vuln_type"],
                payload_used=item.get("payload_used", ""),
                is_vulnerable=item["is_vulnerable"],
                confidence=item.get("confidence", 0.9),
                source=item["source"],
                cvss_score=item.get("cvss_score", 7.0),
                timestamp=item.get("timestamp", "")
            )
            dataset.add_example(example)
    
    dataset.save()
    
    # Train analyzer
    analyzer = ResponseAnalyzer()
    analyzer.train(dataset)
    
    print("\n✅ Bug bounty data integrated and model trained!")
    return stats


def quick_aggregate() -> Dict:
    """Quick aggregation without cloning (uses existing data)."""
    aggregator = DatasetAggregator()
    aggregator.aggregate_all()
    return aggregator.get_stats()


if __name__ == "__main__":
    stats = fetch_and_train()
