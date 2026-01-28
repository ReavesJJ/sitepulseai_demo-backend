from ssl_automation import check_ssl_state
from vulnerabilities_checker import scan_headers
from uptime import check_uptime


def run_full_scan(domain: str):
    results = {"domain": domain}

    print("🔐 Running SSL scan...")
    results["ssl_status"] = check_ssl_state(domain)
    print("✅ SSL scan complete.")

    print("🌐 Running uptime check...")
    results["uptime"] = check_uptime(domain)
    print("✅ Uptime check complete.")

    print("🛡️ Running vulnerability scan...")
    results["vulnerabilities"] = scan_headers(domain)
    print("✅ Vulnerability scan complete.")

    return results
