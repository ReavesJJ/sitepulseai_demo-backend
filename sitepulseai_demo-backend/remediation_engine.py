
from remediation_engine import REMEDIATION_RULES
from datetime import datetime

def generate_remediation(vuln_id: str, site_url: str, evidence: dict):
    rule = REMEDIATION_RULES.get(vuln_id)

    if not rule:
        return {
            "vuln_id": vuln_id,
            "site": site_url,
            "status": "no_rule_defined",
            "generated_at": datetime.utcnow().isoformat()
        }

    remediation = {
        "vuln_id": vuln_id,
        "site": site_url,
        "severity": rule["severity"],
        "title": rule["title"],
        "summary": rule["summary"],
        "fix_type": rule["fix_type"],
        "steps": rule["steps"],
        "automation_possible": rule["automation_possible"],
        "evidence": evidence,
        "status": "pending",
        "generated_at": datetime.utcnow().isoformat()
    }

    return remediation

