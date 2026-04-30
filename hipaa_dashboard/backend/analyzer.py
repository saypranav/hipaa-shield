import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CONTROLS_PATH = ROOT / "out" / "controls.jsonl"

# Mapping keywords to HIPAA Control IDs
KEYWORD_MAPPING = {
    "hsts": ["164.312-e-1", "164.312-e-2-ii"],
    "strict-transport-security": ["164.312-e-1", "164.312-e-2-ii"],
    "manager/html": ["164.312-a-1"],
    "host-manager": ["164.312-a-1"],
    "apache tomcat": ["164.308-a-1-ii-A"],
    "default jsp": ["164.308-a-1-ii-A"],
    "secret": ["164.308-a-1-ii-B", "164.312-a-1"],
    "password": ["164.308-a-5-ii-D"],
    "locked user": ["164.308-a-5-ii-C"],
    "authenticate": ["164.308-a-5-ii-C"],
    "failed login": ["164.308-a-5-ii-C"],
    "access denied": ["164.312-a-1"],
    "mysqlsyntaxerrorexception": ["164.308-a-1-ii-A"],
    "database error": ["164.308-a-1-ii-A"],
}

class HIPAAAnalyzer:
    def __init__(self):
        self.controls = self._load_controls()

    def _load_controls(self):
        controls = {}
        if not CONTROLS_PATH.exists():
            return {}
        with open(CONTROLS_PATH, 'r') as f:
            for line in f:
                data = json.loads(line)
                controls[data['chunk_id']] = data
        return controls

    def analyze_logs(self, logs):
        findings = []
        seen_controls = set()
        
        # Combine logs but also handle line-by-line for JSON parsing (trufflehog)
        log_text = "".join(logs).lower()
        
        # Check for JSON trufflehog findings
        for line in logs:
            try:
                if '"{' in line or line.startswith('{'):
                    data = json.loads(line)
                    # If it's a trufflehog finding
                    if "DetectorName" in data or "Raw" in data:
                        cid = "164.312-a-1" # Access Control
                        if cid in self.controls and cid not in seen_controls:
                            control = self.controls[cid]
                            findings.append({
                                "keyword": f"Secret Found: {data.get('DetectorName', 'Unknown')}",
                                "control_id": cid,
                                "citation": control.get("citation"),
                                "title": "Exposed Credentials Found",
                                "description": f"TruffleHog detected an exposed secret ({data.get('DetectorName')}) in {data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file')}. This is a critical violation of Access Control standards."
                            })
                            seen_controls.add(cid)
            except:
                continue

        # Check for JSON semgrep findings
        for line in logs:
            try:
                if '{"results":' in line or line.startswith('{"results":'):
                    data = json.loads(line)
                    for result in data.get("results", []):
                        check_id = result.get("check_id", "").lower()
                        # Map SQLi or XSS to HIPAA
                        if "sql" in check_id or "xss" in check_id or "injection" in check_id:
                            cid = "164.312-c-1" # Integrity
                            if cid in self.controls and cid not in seen_controls:
                                control = self.controls[cid]
                                findings.append({
                                    "keyword": f"SAST: {result.get('extra', {}).get('message')}",
                                    "control_id": cid,
                                    "citation": control.get("citation"),
                                    "title": "Code-Level Vulnerability Detected",
                                    "description": f"Semgrep identified a high-risk pattern ({check_id}) in {result.get('path')}. This violates HIPAA Integrity standards by allowing potential unauthorized modification of ePHI."
                                })
                                seen_controls.add(cid)
            except:
                continue

        for keyword, control_ids in KEYWORD_MAPPING.items():
            if keyword in log_text:
                for cid in control_ids:
                    if cid in self.controls and cid not in seen_controls:
                        control = self.controls[cid]
                        findings.append({
                            "keyword": keyword,
                            "control_id": cid,
                            "citation": control.get("citation"),
                            "title": control.get("implementation_spec_title") or control.get("section_title"),
                            "description": control.get("text_raw")
                        })
                        seen_controls.add(cid)
        return findings

analyzer = HIPAAAnalyzer()
