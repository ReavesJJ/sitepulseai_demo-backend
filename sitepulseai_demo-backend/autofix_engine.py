# autofix_engine.py
# autofix_engine.py
from datetime import datetime
from autofix_ssl import fix_expired_ssl, fix_weak_ssl_protocols
from autofix_headers import fix_missing_security_headers
from remediation_store import add_remediation  # Track executed fixes

def execute_remediation(remediation: dict):
    """
    Route remediation to the correct auto-fix module based on vuln_id.
    Each fix is automatically added to the remediation store.
    """
    vuln_id = remediation.get("vuln_id")
    site_url = remediation.get("site")
    
    # Default fix result
    fix_result = {
        "fix_type": "unsupported",
        "status": "not_executed",
        "message": f"No auto-fix module for vuln_id: {vuln_id}",
        "attempted_at": datetime.utcnow().isoformat()
    }

    # -------------------------------
    # SSL fixes
    # -------------------------------
    if vuln_id == "ssl_expired":
        fix_result = fix_expired_ssl(site_url)

    elif vuln_id == "ssl_weak_protocols":
        fix_result = fix_weak_ssl_protocols(site_url)

    # -------------------------------
    # Security headers
    # -------------------------------
    elif vuln_id == "missing_security_headers":
        fix_result = fix_missing_security_headers(site_url)

    # -------------------------------
    # Build remediation record
    # -------------------------------
    remediation_record = {
        "remediation_id": remediation.get("remediation_id"),
        "vuln_id": vuln_id,
        "site": site_url,
        "status": fix_result.get("status"),
        "fix_result": fix_result,
        "executed_at": datetime.utcnow().isoformat()
    }

    # -------------------------------
    # Save to store (Auto-Fix All tracking)
    # -------------------------------
    add_remediation(remediation_record)

    return remediation_record
