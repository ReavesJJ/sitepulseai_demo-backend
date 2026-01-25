from ssl_automation import get_ssl_status
from vulnerability_checker import scan_vulnerabilities
from uptime import check_uptime




def run_full_scan(domain: str):
    results = {"domain": domain}

    print("🔐 Running SSL scan...")
    results["ssl_status"] = get_ssl_status(domain)
    print("✅ SSL scan complete.")

    print("🌐 Running uptime check...")
    results["uptime"] = check_uptime(domain)
    print("✅ Uptime check complete.")

    print("🛡️ Running vulnerability scan...")
    results["vulnerabilities"] = scan_vulnerabilities(domain)
    print("✅ Vulnerability scan complete.")

    return results
