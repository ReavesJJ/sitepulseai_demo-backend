REMEDIATION_RULES = {
    "ssl_expired": {
        "severity": "critical",
        "title": "Expired SSL Certificate",
        "fix_type": "manual",
        "summary": "The SSL certificate has expired and must be renewed immediately.",
        "steps": [
            "Log into your domain registrar or certificate provider.",
            "Renew or reissue the SSL certificate.",
            "Install the renewed certificate on your web server.",
            "Restart the web server to apply changes.",
            "Verify the certificate chain and expiry date."
        ],
        "automation_possible": False
    },

    "ssl_weak_protocols": {
        "severity": "high",
        "title": "Weak SSL/TLS Protocols Enabled",
        "fix_type": "config",
        "summary": "The server supports deprecated or insecure SSL/TLS protocols.",
        "steps": [
            "Disable TLS 1.0 and TLS 1.1 in server configuration.",
            "Enable TLS 1.2 and TLS 1.3 only.",
            "Update OpenSSL or server crypto libraries if outdated.",
            "Restart the web server.",
            "Re-run SSL scan to confirm remediation."
        ],
        "automation_possible": True
    },

    "missing_security_headers": {
        "severity": "medium",
        "title": "Missing HTTP Security Headers",
        "fix_type": "config",
        "summary": "Important security headers are not present in HTTP responses.",
        "steps": [
            "Add Content-Security-Policy header.",
            "Add X-Frame-Options header.",
            "Add X-Content-Type-Options header.",
            "Add Strict-Transport-Security header.",
            "Restart the web server.",
            "Validate headers using curl or browser dev tools."
        ],
        "automation_possible": True
    },

    "outdated_server_software": {
        "severity": "high",
        "title": "Outdated Server Software Detected",
        "fix_type": "patch",
        "summary": "The server is running outdated or vulnerable software.",
        "steps": [
            "Identify the outdated service and version.",
            "Review vendor security advisories.",
            "Update to the latest stable version.",
            "Restart the affected service.",
            "Re-run vulnerability scan."
        ],
        "automation_possible": True
    }
}