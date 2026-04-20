# license_enforcer.py
# License_enforcer.py

import os
import json
import hashlib
import uuid
from datetime import datetime
from typing import List
from urllib.parse import urlparse
from fastapi import HTTPException

# -------------------------------
# Configuration
# -------------------------------
LICENSE_FOLDER = "licenses"
SECRET_KEY = "CHANGE_THIS_TO_LONG_RANDOM_SECRET"

# -------------------------------
# Utility Functions
# -------------------------------

def normalize_domain(url: str) -> str:
    """
    Normalize URLs for domain comparison (removes www., lowercase)
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path
        return domain.lower().replace("www.", "")
    except Exception:
        return url.lower()


def generate_client_id(tier: str) -> str:
    """
    Generate a unique client ID per license
    """
    random_part = uuid.uuid4().hex[:8].upper()
    return f"SPA-{tier.upper()}-{random_part}"


# -------------------------------
# FIX #1: Canonical domain sorting (signature stability)
# -------------------------------

def _canonical_domains(domains: List[str]) -> str:
    """
    Ensures consistent domain ordering for signature generation
    """
    return ",".join(sorted([d.lower().strip() for d in domains]))


def _generate_signature(client_id: str, tier: str, domains: List[str], expiration_date: str) -> str:
    """
    Generate a SHA256 signature to verify license authenticity
    """
    payload = (
        f"{client_id}"
        f"{tier}"
        f"{_canonical_domains(domains)}"
        f"{expiration_date}"
        f"{SECRET_KEY}"
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _save_license(client_id: str, license_data: dict):
    os.makedirs(LICENSE_FOLDER, exist_ok=True)
    path = os.path.join(LICENSE_FOLDER, f"{client_id}.json")

    with open(path, "w") as f:
        json.dump(license_data, f, indent=4)


def _load_license(client_id: str) -> dict:
    path = os.path.join(LICENSE_FOLDER, f"{client_id}.json")

    if not os.path.exists(path):
        raise HTTPException(status_code=403, detail="License not found.")

    with open(path, "r") as f:
        return json.load(f)


# -------------------------------
# Public License Functions
# -------------------------------

def create_license(tier: str, domains: List[str], expiration_date: str) -> str:
    """
    Creates a new license file and returns the client ID
    """
    client_id = generate_client_id(tier)
    signature = _generate_signature(client_id, tier, domains, expiration_date)

    license_data = {
        "active": True,
        "tier": tier.lower(),
        "domains": domains,
        "expiration_date": expiration_date,
        "signature": signature,
        "created_at": datetime.utcnow().isoformat(),
        "features": tier_features(tier)
    }

    _save_license(client_id, license_data)
    return client_id


def get_license(client_id: str) -> dict:
    """
    Load and verify license. Checks expiration and signature.
    """
    license_data = _load_license(client_id)

    # Expiration enforcement
    exp = datetime.strptime(license_data["expiration_date"], "%Y-%m-%d")
    if datetime.utcnow() > exp:
        license_data["active"] = False
        _save_license(client_id, license_data)
        raise HTTPException(status_code=403, detail="License expired.")

    # Signature verification
    expected_sig = _generate_signature(
        client_id,
        license_data["tier"],
        license_data["domains"],
        license_data["expiration_date"]
    )

    if expected_sig != license_data.get("signature"):
        raise HTTPException(status_code=403, detail="Invalid license signature.")

    return license_data


def validate_domain(client_id: str, requested_domain: str):
    """
    Ensure client only monitors allowed domains
    """
    license_data = get_license(client_id)

    allowed = [normalize_domain(d) for d in license_data.get("domains", [])]
    req_norm = normalize_domain(requested_domain)

    if req_norm not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Domain '{requested_domain}' not allowed under this license."
        )
    return True


def check_feature_access(client_id: str, feature: str):
    """
    Ensure feature is allowed under license tier
    """
    license_data = get_license(client_id)

    if feature not in license_data.get("features", []):
        raise HTTPException(
            status_code=403,
            detail=f"Feature '{feature}' not permitted under {license_data['tier']} license."
        )
    return True


# -------------------------------
# FIX #2: Enforcement Guard Layer
# -------------------------------

def enforce_domain_guard(client_id: str, domains: List[str]):
    """
    Ensures monitoring batch cannot include unauthorized domains
    """
    license_data = get_license(client_id)

    allowed = set([normalize_domain(d) for d in license_data["domains"]])
    requested = set([normalize_domain(d) for d in domains])

    invalid = requested - allowed

    if invalid:
        raise HTTPException(
            status_code=403,
            detail=f"Unauthorized domains detected: {list(invalid)}"
        )


def tier_features(tier: str) -> List[str]:
    """
    Map tier names to allowed features
    """
    mapping = {
        "tier_1": ["ssl", "uptime", "seo", "latency", "traffic", "vulnerabilities"],
    }
    return mapping.get(tier.lower(), [])


# -------------------------------
# Optional: Dynamic Registration Helper
# -------------------------------

def add_client(client_id: str, tier: str, domains: List[str], expiration_date: str):
    """
    Manually add a new client to the licenses folder
    """
    if os.path.exists(os.path.join(LICENSE_FOLDER, f"{client_id}.json")):
        raise HTTPException(status_code=400, detail="Client ID already exists.")

    signature = _generate_signature(client_id, tier, domains, expiration_date)

    license_data = {
        "active": True,
        "tier": tier.lower(),
        "domains": domains,
        "expiration_date": expiration_date,
        "signature": signature,
        "created_at": datetime.utcnow().isoformat(),
        "features": tier_features(tier)
    }

    _save_license(client_id, license_data)
    return client_id