import json
import os
from fastapi import HTTPException
from urllib.parse import urlparse

LICENSE_FOLDER = "licenses"


def normalize_domain(url: str):
    try:
        parsed = urlparse(url)

        if parsed.netloc:
            domain = parsed.netloc.lower()
        else:
            domain = parsed.path.lower()

        domain = domain.replace("www.", "")
        return domain

    except Exception:
        return url.lower()


def load_license(client_id):

    license_file = os.path.join(LICENSE_FOLDER, f"{client_id}.json")

    if not os.path.exists(license_file):
        raise HTTPException(status_code=403, detail="License not found.")

    with open(license_file, "r") as f:
        return json.load(f)


def validate_domain(client_id, requested_domain):

    license_data = load_license(client_id)

    allowed_domains = license_data.get("domains", [])

    normalized_requested = normalize_domain(requested_domain)

    normalized_allowed = [normalize_domain(d) for d in allowed_domains]

    if normalized_requested not in normalized_allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Domain '{requested_domain}' not allowed under this license."
        )

    return True


def check_feature_access(client_id, feature):

    license_data = load_license(client_id)

    tier = license_data.get("tier")

    tier_permissions = {

        "tier_1": [
            "ssl",
            "uptime",
            "seo",
            "latency",
            "traffic",
            "vulnerabilities"
        ]
    }

    allowed = tier_permissions.get(tier, [])

    if feature not in allowed:

        raise HTTPException(
            status_code=403,
            detail=f"Feature '{feature}' not permitted under {tier} license."
        )

    return True