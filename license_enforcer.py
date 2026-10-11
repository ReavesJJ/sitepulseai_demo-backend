import os
import json
import base64
import uuid

from datetime import datetime
from typing import List
from urllib.parse import urlparse

from fastapi import HTTPException
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ============================================================
# SitePulseAI License Enforcement
# Licensed Monitoring Infrastructure
# ============================================================


# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

LICENSE_FOLDER = "licenses"

PUBLIC_KEY_PEM = os.getenv("PUBLIC_KEY_PEM")

if not PUBLIC_KEY_PEM:
    raise RuntimeError(
        "Missing PUBLIC_KEY_PEM environment variable."
    )

try:
    PUBLIC_KEY = serialization.load_pem_public_key(
        PUBLIC_KEY_PEM.encode()
    )
except Exception as exc:
    raise RuntimeError(
        "PUBLIC_KEY_PEM is present but could not be loaded."
    ) from exc


# ------------------------------------------------------------
# Tier configuration
#
# This is the authoritative feature map.
# Features do NOT need to be duplicated inside license files.
# ------------------------------------------------------------

TIER_FEATURES = {
    "tier_1": [
        "ssl",
        "uptime",
        "seo",
        "latency",
        "traffic",
        "vulnerabilities",
    ],
}


def tier_features(tier: str) -> List[str]:
    """
    Return the features authorized for a license tier.
    """

    if not isinstance(tier, str):
        return []

    return list(
        TIER_FEATURES.get(tier.lower().strip(), [])
    )


# ------------------------------------------------------------
# Domain normalization
# ------------------------------------------------------------

def normalize_domain(value: str) -> str:
    """
    Normalize a URL/domain for license comparison.

    Examples:
        https://www.sitepulseai.com/path
        www.sitepulseai.com
        sitepulseai.com

    become:
        sitepulseai.com
    """

    if not isinstance(value, str) or not value.strip():
        raise HTTPException(
            status_code=400,
            detail="Invalid domain."
        )

    value = value.strip()

    try:
        # urlparse treats a bare domain as a path.
        parsed = urlparse(
            value if "://" in value else f"//{value}",
            scheme="https"
        )

        domain = parsed.hostname

        if not domain:
            raise ValueError("Unable to determine hostname.")

        domain = domain.lower().rstrip(".")

        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Invalid domain format."
        )


# ------------------------------------------------------------
# Client ID generation
# ------------------------------------------------------------

def generate_client_id(tier: str) -> str:
    """
    Generate a unique SitePulseAI client ID.

    Example:
        SPA-TIER_1-5CF062E6
    """

    if not isinstance(tier, str) or not tier.strip():
        raise ValueError("Tier is required.")

    random_part = uuid.uuid4().hex[:8].upper()

    return f"SPA-{tier.upper().strip()}-{random_part}"


# ------------------------------------------------------------
# Canonical domain representation
#
# IMPORTANT:
# This must remain compatible with generate_license.py because
# this exact representation participates in the RSA signature.
# ------------------------------------------------------------

def _canonical_domains(domains: List[str]) -> str:
    """
    Produce the deterministic domain string used for RSA
    signature verification.
    """

    if not isinstance(domains, list):
        raise HTTPException(
            status_code=403,
            detail="Invalid license domains."
        )

    canonical = []

    for domain in domains:
        if not isinstance(domain, str):
            raise HTTPException(
                status_code=403,
                detail="Invalid license domains."
            )

        canonical.append(
            domain.lower().strip()
        )

    return ",".join(sorted(canonical))


# ------------------------------------------------------------
# License path
# ------------------------------------------------------------

def _license_path(client_id: str) -> str:
    """
    Safely construct the license filename.
    """

    if not isinstance(client_id, str) or not client_id.strip():
        raise HTTPException(
            status_code=400,
            detail="Client ID is required."
        )

    client_id = client_id.strip()

    # Prevent path traversal / unexpected filenames.
    if (
        "/" in client_id
        or "\\" in client_id
        or ".." in client_id
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid client ID."
        )

    return os.path.join(
        LICENSE_FOLDER,
        f"{client_id}.json"
    )


# ------------------------------------------------------------
# License persistence
# ------------------------------------------------------------

def _save_license(client_id: str, license_data: dict) -> None:
    """
    Save license data to the local license store.
    """

    os.makedirs(
        LICENSE_FOLDER,
        exist_ok=True
    )

    path = _license_path(client_id)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            license_data,
            f,
            indent=4
        )


def _load_license(client_id: str) -> dict:
    """
    Load a client license from the local license store.
    """

    path = _license_path(client_id)

    if not os.path.isfile(path):
        raise HTTPException(
            status_code=403,
            detail="License not found."
        )

    try:
        with open(path, "r", encoding="utf-8") as f:
            license_data = json.load(f)

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=403,
            detail="License file is invalid."
        )

    except OSError:
        raise HTTPException(
            status_code=500,
            detail="Unable to read license file."
        )

    if not isinstance(license_data, dict):
        raise HTTPException(
            status_code=403,
            detail="License file is invalid."
        )

    return license_data


# ------------------------------------------------------------
# License structure validation
# ------------------------------------------------------------

def _validate_license_structure(
    requested_client_id: str,
    license_data: dict
) -> None:
    """
    Validate required fields and basic license consistency
    before cryptographic verification.
    """

    required_fields = [
        "client_id",
        "tier",
        "domains",
        "max_sites",
        "expiration_date",
        "signature",
    ]

    missing_fields = [
        field
        for field in required_fields
        if field not in license_data
    ]

    if missing_fields:
        raise HTTPException(
            status_code=403,
            detail="License file is incomplete."
        )

    if license_data["client_id"] != requested_client_id:
        raise HTTPException(
            status_code=403,
            detail="License client ID mismatch."
        )

    if not isinstance(license_data["tier"], str):
        raise HTTPException(
            status_code=403,
            detail="Invalid license tier."
        )

    if not tier_features(license_data["tier"]):
        raise HTTPException(
            status_code=403,
            detail="Unsupported license tier."
        )

    domains = license_data["domains"]

    if (
        not isinstance(domains, list)
        or not domains
        or not all(
            isinstance(domain, str) and domain.strip()
            for domain in domains
        )
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid license domains."
        )

    max_sites = license_data["max_sites"]

    if (
        isinstance(max_sites, bool)
        or not isinstance(max_sites, int)
        or max_sites < 1
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid max_sites value."
        )

    if len(set(normalize_domain(d) for d in domains)) > max_sites:
        raise HTTPException(
            status_code=403,
            detail="License domains exceed max_sites."
        )

    if (
        not isinstance(license_data["signature"], str)
        or not license_data["signature"].strip()
    ):
        raise HTTPException(
            status_code=403,
            detail="License signature missing."
        )


# ------------------------------------------------------------
# RSA signature verification
#
# MUST match generate_license.py exactly.
# ------------------------------------------------------------

def _verify_signature(
    client_id: str,
    tier: str,
    domains: List[str],
    expiration_date: str,
    signature: str
) -> None:

    payload = (
        f"{client_id}"
        f"{tier}"
        f"{_canonical_domains(domains)}"
        f"{expiration_date}"
    ).encode()

    try:
        decoded_signature = base64.b64decode(
            signature,
            validate=True
        )

    except Exception:
        raise HTTPException(
            status_code=403,
            detail="Invalid license signature."
        )

    try:
        PUBLIC_KEY.verify(
            decoded_signature,
            payload,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

    except InvalidSignature:
        raise HTTPException(
            status_code=403,
            detail="Invalid license signature."
        )

    except Exception:
        raise HTTPException(
            status_code=403,
            detail="License signature verification failed."
        )


# ------------------------------------------------------------
# Expiration enforcement
# ------------------------------------------------------------

def _verify_expiration(expiration_date: str) -> None:
    """
    Verify that the license has not expired.
    """

    try:
        expiration = datetime.strptime(
            expiration_date,
            "%Y-%m-%d"
        ).date()

    except (TypeError, ValueError):
        raise HTTPException(
            status_code=403,
            detail="Invalid license expiration date."
        )

    # Valid through the stated expiration date.
    if datetime.utcnow().date() > expiration:
        raise HTTPException(
            status_code=403,
            detail="License expired."
        )


# ------------------------------------------------------------
# Public: Get and verify license
# ------------------------------------------------------------

def get_license(client_id: str) -> dict:
    """
    Load and fully validate a SitePulseAI license.

    Validation order:
        1. File exists
        2. Structure is valid
        3. Expiration is valid
        4. RSA signature is valid
    """

    client_id = client_id.strip()

    license_data = _load_license(client_id)

    _validate_license_structure(
        client_id,
        license_data
    )

    _verify_expiration(
        license_data["expiration_date"]
    )

    _verify_signature(
        client_id=license_data["client_id"],
        tier=license_data["tier"],
        domains=license_data["domains"],
        expiration_date=license_data["expiration_date"],
        signature=license_data["signature"]
    )

    return license_data


# ------------------------------------------------------------
# Public: Domain enforcement
# ------------------------------------------------------------

def validate_domain(
    client_id: str,
    requested_domain: str
) -> bool:
    """
    Ensure the requested domain is explicitly authorized by
    the client's signed license.
    """

    license_data = get_license(client_id)

    allowed_domains = {
        normalize_domain(domain)
        for domain in license_data["domains"]
    }

    requested = normalize_domain(
        requested_domain
    )

    if requested not in allowed_domains:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Domain '{requested_domain}' is not "
                "authorized under this license."
            )
        )

    return True


# ------------------------------------------------------------
# Public: Feature enforcement
# ------------------------------------------------------------

def check_feature_access(
    client_id: str,
    feature: str
) -> bool:
    """
    Ensure a feature is authorized by the client's tier.
    """

    license_data = get_license(client_id)

    allowed_features = tier_features(
        license_data["tier"]
    )

    requested_feature = feature.lower().strip()

    if requested_feature not in allowed_features:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Feature '{feature}' is not permitted "
                f"under {license_data['tier']} license."
            )
        )

    return True


# ------------------------------------------------------------
# Public: Batch domain guard
# ------------------------------------------------------------

def enforce_domain_guard(
    client_id: str,
    domains: List[str]
) -> bool:
    """
    Enforce:
        - Valid license
        - max_sites
        - Licensed-domain whitelist
        - Domain deduplication
    """

    license_data = get_license(client_id)

    if not isinstance(domains, list) or not domains:
        raise HTTPException(
            status_code=400,
            detail="At least one domain is required."
        )

    normalized_domains = {
        normalize_domain(domain)
        for domain in domains
    }

    max_allowed = license_data["max_sites"]

    if len(normalized_domains) > max_allowed:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Exceeded max_sites limit "
                f"({max_allowed}) for this license."
            )
        )

    allowed_domains = {
        normalize_domain(domain)
        for domain in license_data["domains"]
    }

    unauthorized = (
        normalized_domains - allowed_domains
    )

    if unauthorized:
        raise HTTPException(
            status_code=403,
            detail=(
                "Unauthorized domains detected: "
                + ", ".join(sorted(unauthorized))
            )
        )

    return True