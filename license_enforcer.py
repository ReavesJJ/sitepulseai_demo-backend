# License_enforcer.py

import os
import json
import hashlib
import uuid
from datetime import datetime
from typing import List
from urllib.parse import urlparse
from fastapi import HTTPException
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64

PUBLIC_KEY_PATH = "verify_key.pem"

with open(PUBLIC_KEY_PATH, "rb") as f:
    PUBLIC_KEY = serialization.load_pem_public_key(f.read())

# -------------------------------
# Configuration
# -------------------------------
LICENSE_FOLDER = "licenses"

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


def _verify_signature(client_id: str, tier: str, domains: List[str], expiration_date: str, signature: str):
    payload = (
        f"{client_id}"
        f"{tier}"
        f"{_canonical_domains(domains)}"
        f"{expiration_date}"
    ).encode()

    try:
        PUBLIC_KEY.verify(
            base64.b64decode(signature),
            payload,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid license signature.")
    

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
    _verify_signature(
    client_id,
    license_data["tier"],
    license_data["domains"],
    license_data["expiration_date"],
    license_data.get("signature")
)


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

