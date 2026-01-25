from ssl_automation import get_ssl_status
import time
import requests
def run_full_scan(domain: str):
    results = {"domain": domain}

    try:
        print("🔐 Running SSL scan...")
        results["ssl_status"] = get_ssl_status(domain)
        print("✅ SSL scan complete.")
    except Exception as e:
        print("❌ SSL scan failed:", e)
        raise Exception(f"SSL scan failed: {e}")

    try:
        print("🌐 Running uptime check...")
        results["uptime"] = check_uptime(domain)
        print("✅ Uptime check complete.")
    except Exception as e:
        print("❌ Uptime check failed:", e)
        raise Exception(f"Uptime check failed: {e}")

    try:
        print("🛡️ Running vulnerability scan...")
        results["vulnerabilities"] = scan_vulnerabilities(domain)
        print("✅ Vulnerability scan complete.")
    except Exception as e:
        print("❌ Vulnerability scan failed:", e)
        raise Exception(f"Vulnerability scan failed: {e}")

    return results
