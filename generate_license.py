import os
import json
import base64
import uuid
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ============================================================
# SitePulseAI License Generator
# Licensed Monitoring Infrastructure
# ============================================================

PRIVATE_KEY_FILE = "signing_key.pem"
LICENSE_FOLDER = "licenses"


# ------------------------------------------------------------
# Load private signing key
# ------------------------------------------------------------

if not os.path.exists(PRIVATE_KEY_FILE):
    raise RuntimeError(
        f"Private signing key not found: {PRIVATE_KEY_FILE}"
    )

with open(PRIVATE_KEY_FILE, "rb") as f:
    PRIVATE_KEY = serialization.load_pem_private_key(
        f.read(),
        password=None
    )


# ------------------------------------------------------------
# Client ID generation
# ------------------------------------------------------------

def generate_client_id(tier: str) -> str:
    """
    Generate a unique SitePulseAI client/license ID.
    Example:
        SPA-TIER_1-A1B2C3D4
    """

    random_part = uuid.uuid4().hex[:8].upper()

    return f"SPA-{tier.upper()}-{random_part}"


# ------------------------------------------------------------
# Canonical domain representation
# ------------------------------------------------------------

def canonical_domains(domains: list[str]) -> str:
    """
    Produce the exact deterministic domain representation
    expected by license_enforcer.py.
    """

    return ",".join(
        sorted(
            d.lower().strip()
            for d in domains
        )
    )


# ------------------------------------------------------------
# License signature
# ------------------------------------------------------------

def sign_license(
    client_id: str,
    tier: str,
    domains: list[str],
    expiration_date: str
) -> str:
    """
    Sign the exact payload expected by
    license_enforcer._verify_signature().
    """

    payload = (
        f"{client_id}"
        f"{tier}"
        f"{canonical_domains(domains)}"
        f"{expiration_date}"
    ).encode()

    signature = PRIVATE_KEY.sign(
        payload,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode()


# ------------------------------------------------------------
# Generate license
# ------------------------------------------------------------

def generate_license():
    """
    Generate and save a signed SitePulseAI license.
    """

    tier = "tier_1"

    domains = [
        "sitepulseai.com",
        "api.sitepulseai.com"
    ]

    max_sites = 5
    expiration_date = "2027-12-31"

    # Generate a NEW unique client ID
    client_id = generate_client_id(tier)

    license_data = {
        "client_id": client_id,
        "tier": tier,
        "domains": domains,
        "max_sites": max_sites,
        "expiration_date": expiration_date,
        "issued_at": datetime.utcnow().isoformat()
    }

    # --------------------------------------------------------
    # Generate RSA signature
    # --------------------------------------------------------

    license_data["signature"] = sign_license(
        client_id=client_id,
        tier=tier,
        domains=domains,
        expiration_date=expiration_date
    )

    # --------------------------------------------------------
    # Save license using format expected by license_enforcer.py
    # --------------------------------------------------------

    os.makedirs(
        LICENSE_FOLDER,
        exist_ok=True
    )

    license_path = os.path.join(
        LICENSE_FOLDER,
        f"{client_id}.json"
    )

    with open(license_path, "w") as f:
        json.dump(
            license_data,
            f,
            indent=4
        )

    # --------------------------------------------------------
    # Confirmation
    # --------------------------------------------------------

    print("")
    print("==============================================")
    print("SitePulseAI License Generated Successfully")
    print("==============================================")
    print(f"Client ID:       {client_id}")
    print(f"Tier:            {tier}")
    print(f"Domains:         {', '.join(domains)}")
    print(f"Max Sites:       {max_sites}")
    print(f"Expiration Date: {expiration_date}")
    print(f"License File:    {license_path}")
    print("==============================================")
    print("")

    return license_data


# ------------------------------------------------------------
# Run generator
# ------------------------------------------------------------

if __name__ == "__main__":
    generate_license()