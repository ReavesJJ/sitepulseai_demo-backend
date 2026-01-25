# ssl_automation.py

from typing import Dict, Any

from ssl_utils import get_ssl_certificate
from ssl_state import update_ssl_state, can_attempt_repair
from ssl_policy import evaluate_ssl_policy
from certbot_adapter import attempt_ssl_repair


def run_ssl_automation(domain: str) -> Dict[str, Any]:
    """
    Main SSL automation pipeline:
    - Fetch SSL certificate info
    - Evaluate policy compliance
    - Attempt repair if needed
    - Persist updated SSL state
    """

    result = {
        "domain": domain,
        "ssl_valid": False,
        "expires_in_days": None,
        "issuer": None,
        "policy_compliant": False,
        "repair_attempted": False,
        "repair_success": False,
        "error": None,
    }

    try:
        # 1. Fetch SSL certificate info
        cert_info = get_ssl_certificate(domain)

        if not cert_info:
            result["error"] = "Unable to fetch SSL certificate"
            update_ssl_state(domain, result)
            return result

        result["ssl_valid"] = cert_info.get("valid", False)
        result["expires_in_days"] = cert_info.get("expires_in_days")
        result["issuer"] = cert_info.get("issuer")

        # 2. Evaluate SSL policy compliance
        policy_result = evaluate_ssl_policy(cert_info)
        result["policy_compliant"] = policy_result.get("compliant", False)

        # 3. Attempt repair if needed
        if not result["policy_compliant"] and can_attempt_repair(domain):
            result["repair_attempted"] = True

            repair_result = attempt_ssl_repair(domain)

            result["repair_success"] = repair_result.get("success", False)

            # Re-fetch cert after repair attempt
            if result["repair_success"]:
                cert_info = get_ssl_certificate(domain)
                result["ssl_valid"] = cert_info.get("valid", False)
                result["expires_in_days"] = cert_info.get("expires_in_days")
                result["issuer"] = cert_info.get("issuer")

                policy_result = evaluate_ssl_policy(cert_info)
                result["policy_compliant"] = policy_result.get("compliant", False)

        # 4. Persist final SSL state
        update_ssl_state(domain, result)

        return result

    except Exception as e:
        result["error"] = str(e)
        update_ssl_state(domain, result)
        return result
