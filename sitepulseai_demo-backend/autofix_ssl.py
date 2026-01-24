# autofix_ssl.py
from datetime import datetime
from urllib.parse import urlparse
from certbot_adapter import certbot_dry_run, certbot_live_renew


ENABLE_LIVE_SSL_RENEWAL = False   # 🔒 SAFETY SWITCH


def extract_domain(site_url: str) -> str:
    parsed = urlparse(site_url)
    return parsed.netloc or parsed.path


def fix_expired_ssl(site_url: str):
    domain = extract_domain(site_url)

    dry_run_result = certbot_dry_run(domain)

    if ENABLE_LIVE_SSL_RENEWAL and dry_run_result.get("status") == "success":
        live_result = certbot_live_renew(domain)
    else:
        live_result = {
            "mode": "live",
            "status": "skipped",
            "reason": "Live SSL renewal disabled or dry-run failed",
            "executed_at": datetime.utcnow().isoformat()
        }

    return {
        "fix_type": "ssl_renew",
        "site": site_url,
        "domain": domain,
        "status": live_result.get("status", "dry_run_only"),
        "dry_run": dry_run_result,
        "live_run": live_result,
        "executed_at": datetime.utcnow().isoformat()
    }


def fix_weak_ssl_protocols(site_url: str):
    domain = extract_domain(site_url)

    return {
        "fix_type": "ssl_protocols",
        "site": site_url,
        "domain": domain,
        "status": "not_implemented",
        "message": "Protocol hardening requires server-level config access",
        "executed_at": datetime.utcnow().isoformat()
    }
