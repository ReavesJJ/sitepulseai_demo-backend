# autofix_engine.py
from datetime import datetime
from autofix_ssl import fix_expired_ssl, fix_weak_ssl_protocols
from autofix_headers import fix_missing_security_headers


def execute_remediation(remediation: dict):
    """
    Route remediation to the correct auto-fix module based on vuln_id.
    """
    vuln_id = remediation.get("vuln_id")
    site_url = remediation.get("site")

    if vuln_id == "ssl_expired":
        fix_result = fix_expired_ssl(site_url)

    elif vuln_id == "ssl_weak_protocols":
        fix_result = fix_weak_ssl_protocols(site_url)

    elif vuln_id == "missing_security_headers":
        fix_result = fix_missing_security_headers(site_url)

    else:
        fix_result = {
            "fix_type": "unsupported",
            "status": "not_executed",
            "message": f"No auto-fix module for vuln_id: {vuln_id}",
            "attempted_at": datetime.utcnow().isoformat()
        }

    return {
        "remediation_id": remediation.get("remediation_id"),
        "vuln_id": vuln_id,
        "site": site_url,
        "status": fix_result["status"],
        "fix_result": fix_result,
        "executed_at": datetime.utcnow().isoformat()
    }
