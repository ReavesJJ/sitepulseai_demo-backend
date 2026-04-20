# license_enforcer.py (RSA VERSION)

import os
import json
import uuid
from datetime import datetime
from typing import List
from fastapi import HTTPException, Request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

# -------------------------------
# CONFIG
# -------------------------------
LICENSE_FOLDER = "licenses"
PUBLIC_KEY_PATH = "verify_key.pem"

FERNET_KEY = os.getenv("LICENSE_ENCRYPTION_KEY", Fernet.generate_key().decode())
fernet = Fernet(FERNET_KEY.encode())

# Load public key (used for verification ONLY)
with open(PUBLIC_KEY_PATH, "rb") as f:
    PUBLIC_KEY = serialization.load_pem_public_key(f.read())

# -------------------------------
# UTILITIES
# -------------------------------

def normalize_domain(url: str) -> str:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path
        return domain.lower().replace("www.", "")
    except:
        return url.lower()


def generate_client_id(tier: str) -> str:
    return f"SPA-{tier.upper()}-{uuid.uuid4().hex[:8].upper()}"


def _canonical_payload(data: dict) -> str:
    """
    Ensures consistent signing payload
    """
    return json.dumps({
        "client_id": data["client_id"],
        "tier": data["tier"],
        "domains": sorted([normalize_domain(d) for d in data["domains"]]),
        "max_sites": data["max_sites"],
        "expiration_date": data["expiration_date"]
    }, separators=(",", ":"), sort_keys=True)


# -------------------------------
# 🔐 ENCRYPTION LAYER
# -------------------------------

def _encrypt(data: dict) -> bytes:
    return fernet.encrypt(json.dumps(data).encode())


def _decrypt(data: bytes) -> dict:
    return json.loads(fernet.decrypt(data).decode())


# -------------------------------
# FILE SYSTEM
# -------------------------------

def _save_license(client_id, data):
    os.makedirs(LICENSE_FOLDER, exist_ok=True)
    encrypted = _encrypt(data)

    with open(f"{LICENSE_FOLDER}/{client_id}.lic", "wb") as f:
        f.write(encrypted)


def _load_license(client_id):
    path = f"{LICENSE_FOLDER}/{client_id}.lic"

    if not os.path.exists(path):
        raise HTTPException(status_code=403, detail="License not found")

    with open(path, "rb") as f:
        encrypted = f.read()

    try:
        return _decrypt(encrypted)
    except:
        raise HTTPException(status_code=403, detail="License corrupted")


# -------------------------------
# 🔐 RSA SIGNATURE VERIFICATION
# -------------------------------

def verify_signature(data: dict):
    signature = bytes.fromhex(data["signature"])
    payload = _canonical_payload(data).encode()

    try:
        PUBLIC_KEY.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        raise HTTPException(status_code=403, detail="Invalid license signature")


# -------------------------------
# 🔒 CORE VALIDATION
# -------------------------------

def enforce_site_limit(data):
    if len(data.get("domains", [])) > data.get("max_sites", 0):
        raise HTTPException(status_code=403, detail="Exceeded max_sites")


def get_license(client_id: str):
    data = _load_license(client_id)

    # Expiration
    exp = datetime.strptime(data["expiration_date"], "%Y-%m-%d")
    if datetime.utcnow() > exp:
        raise HTTPException(status_code=403, detail="License expired")

    # RSA Signature
    verify_signature(data)

    # Site limit
    enforce_site_limit(data)

    return data


# -------------------------------
# 🚨 GLOBAL ENFORCEMENT
# -------------------------------

def enforce_license(request: Request):
    client_id = request.headers.get("X-Client-ID")

    if not client_id:
        raise HTTPException(status_code=401, detail="Missing Client ID")

    license_data = get_license(client_id)

    request.state.license = license_data
    request.state.client_id = client_id

    return license_data


# -------------------------------
# 🔒 DOMAIN ENFORCEMENT
# -------------------------------

def enforce_domains(request: Request):
    license_data = request.state.license

    try:
        body = request.json()
    except:
        return

    allowed = set([normalize_domain(d) for d in license_data["domains"]])

    requested = []

    if isinstance(body, dict):
        if "domain" in body:
            requested.append(body["domain"])
        if "domains" in body:
            requested.extend(body["domains"])

    invalid = set([normalize_domain(d) for d in requested]) - allowed

    if invalid:
        raise HTTPException(
            status_code=403,
            detail=f"Unauthorized domains: {list(invalid)}"
        )


# -------------------------------
# 🔒 FEATURE ENFORCEMENT
# -------------------------------

def enforce_feature(feature: str):
    def checker(request: Request):
        if feature not in request.state.license.get("features", []):
            raise HTTPException(
                status_code=403,
                detail=f"{feature} not allowed"
            )
    return checker


# -------------------------------
# 🧾 LICENSE CREATION (YOUR SIDE ONLY)
# -------------------------------

def create_license(tier: str, domains: List[str], expiration_date: str, max_sites: int, private_key):
    client_id = generate_client_id(tier)

    data = {
        "client_id": client_id,
        "tier": tier,
        "domains": domains,
        "max_sites": max_sites,
        "expiration_date": expiration_date,
        "issued_at": datetime.utcnow().isoformat(),
        "features": tier_features(tier)
    }

    payload = _canonical_payload(data).encode()

    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    ).hex()

    data["signature"] = signature

    _save_license(client_id, data)

    return client_id


def tier_features(tier: str):
    return {
        "tier_1": ["ssl", "uptime", "seo", "latency", "traffic", "vulnerabilities"]
    }.get(tier.lower(), [])