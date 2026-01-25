from ssl_automation import check_ssl
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
    findings = []

    # Placeholder logic (real scanner comes later)
    if domain.startswith("http://"):
        findings.append({
            "type": "Insecure Protocol",
            "severity": "high",
            "description": "Site is not using HTTPS"
        })

    return findings


def run_full_scan(domain: str):
    ssl_status = check_ssl(domain)
    uptime = check_uptime(domain)
    vulns = scan_vulnerabilities(domain)

    baseline = {
        "domain": domain,
        "ssl_status": ssl_status,
        "uptime": uptime,
        "vulnerabilities": vulns
    }

    return baseline
