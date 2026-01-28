# sitepulseai_demo-backend/vulnerabilities.py

def scan_headers(domain: str):
    # your existing scanning logic here
    return {
        "findings": [
            {"type": "X-Frame-Options missing", "severity": "Medium"},
            {"type": "Content-Security-Policy missing", "severity": "High"}
        ]
    }
