from ssl_automation import get_ssl_status
import time
import requests

def check_uptime(domain: str):
    start = time.time()
    try:
        r = requests.get(f"https://{domain}", timeout=10)
        elapsed = int((time.time() - start) * 1000)

        return {
            "status": "up" if r.status_code == 200 else "down",
            "status_code": r.status_code,
            "response_time_ms": elapsed
        }

    except Exception as e:
        return {
            "status": "down",
            "error": str(e),
            "response_time_ms": None
        }

def scan_vulnerabilities(domain: str):
    from vulnerability_checker import run_vulnerability_scan

    try:
        return run_vulnerability_scan(domain)
    except Exception as e:
        print("VULN SCAN ERROR:", e)
        return []

def run_full_scan(domain: str):
    ssl_status = get_ssl_status(domain)
    uptime = check_uptime(domain)
    vulns = scan_vulnerabilities(domain)

    return {
        "domain": domain,
        "ssl_status": ssl_status,
        "uptime": uptime,
        "vulnerabilities": vulns
    }
