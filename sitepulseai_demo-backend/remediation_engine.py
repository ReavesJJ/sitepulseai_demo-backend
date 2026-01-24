# remediation_engine.py
from datetime import datetime
from remediation_rules import REMEDIATION_RULES
from remediation_store import save_remediation


def generate_remediation(vuln_id: str, site_url: str, evidence: dict):
    rule = REMEDIATION_RULES.get(vuln_id)

    if not rule:
        remediation = {
            "vuln_id": vuln_id,
            "site": site_url,
            "status": "no_rule_defined",
            "generated_at": datetime.utcnow().isoformat()
        }
        save_remediation(remediation)
        return remediation

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

    remediation_id = save_remediation(remediation)
    remediation["remediation_id"] = remediation_id

    return remediation
