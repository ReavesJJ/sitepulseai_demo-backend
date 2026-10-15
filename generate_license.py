import os
import json
import base64
import uuid
import argparse
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ============================================================
# SitePulseAI License Generator
# Licensed Monitoring Infrastructure
#
# ISSUER-SIDE ONLY
# Private signing material must never be distributed
# inside a client deployment package.
# ============================================================

PRIVATE_KEY_FILE = "signing_key.pem"
LICENSE_FOLDER = "licenses"


# ------------------------------------------------------------
# Load private signing key
# ------------------------------------------------------------

def load_private_key():
    if not os.path.exists(PRIVATE_KEY_FILE):
        raise RuntimeError(
            f"Private signing key not found: {PRIVATE_KEY_FILE}"
        )

    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(
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
# Domain normalization
# ------------------------------------------------------------

def normalize_domain(domain: str) -> str:
    """
    Normalize an authorized domain before it is placed
    into the license.
    """

    domain = domain.strip().lower()

    if domain.startswith("https://"):
        domain = domain[8:]
    elif domain.startswith("http://"):
        domain = domain[7:]

    if domain.startswith("www."):
        domain = domain[4:]

    domain = domain.split("/")[0]

    return domain


def normalize_domains(domains: list[str]) -> list[str]:
    """
    Normalize domains and remove duplicates while
    preserving their original order.
    """

    normalized = []

    for domain in domains:
        clean = normalize_domain(domain)

        if clean and clean not in normalized:
            normalized.append(clean)

    return normalized


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
    private_key,
    client_id: str,
    tier: str,
    domains: list[str],
    expiration_date: str
) -> str:
    """
    Sign the exact payload expected by
    license_enforcer._verify_signature().

    IMPORTANT:
    Do not change this payload format independently of
    license_enforcer.py.
    """

    payload = (
        f"{client_id}"
        f"{tier}"
        f"{canonical_domains(domains)}"
        f"{expiration_date}"
    ).encode()

    signature = private_key.sign(
        payload,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode()


# ------------------------------------------------------------
# Generate license
# ------------------------------------------------------------

def generate_license(
    tier: str,
    domains: list[str],
    max_sites: int,
    expiration_date: str
):
    """
    Generate and save a signed SitePulseAI license.
    """

    domains = normalize_domains(domains)

    if not domains:
        raise ValueError(
            "At least one authorized domain is required."
        )

    if max_sites < 1:
        raise ValueError(
            "max_sites must be at least 1."
        )

    if len(domains) > max_sites:
        raise ValueError(
            f"{len(domains)} domains were supplied, "
            f"but max_sites is {max_sites}."
        )

    # Validate expiration date format
    try:
        datetime.strptime(
            expiration_date,
            "%Y-%m-%d"
        )
    except ValueError:
        raise ValueError(
            "Expiration date must use YYYY-MM-DD format."
        )

    private_key = load_private_key()

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
        private_key=private_key,
        client_id=client_id,
        tier=tier,
        domains=domains,
        expiration_date=expiration_date
    )

    # --------------------------------------------------------
    # Save license
    # --------------------------------------------------------

    os.makedirs(
        LICENSE_FOLDER,
        exist_ok=True
    )

    license_path = os.path.join(
        LICENSE_FOLDER,
        f"{client_id}.json"
    )

    with open(
        license_path,
        "w",
        encoding="utf-8"
    ) as f:
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
# Command-line interface
# ------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Generate a signed SitePulseAI client license."
        )
    )

    parser.add_argument(
        "--domains",
        required=True,
        help=(
            "Comma-separated authorized domains. "
            "Example: client.com,portal.client.com"
        )
    )

    parser.add_argument(
        "--max-sites",
        required=True,
        type=int,
        help="Maximum number of authorized sites."
    )

    parser.add_argument(
        "--expiration",
        required=True,
        help="License expiration date in YYYY-MM-DD format."
    )

    parser.add_argument(
        "--tier",
        default="tier_1",
        help="License tier. Default: tier_1"
    )

    args = parser.parse_args()

    domains = [
        domain.strip()
        for domain in args.domains.split(",")
        if domain.strip()
    ]

    generate_license(
        tier=args.tier,
        domains=domains,
        max_sites=args.max_sites,
        expiration_date=args.expiration
    )


# ------------------------------------------------------------
# Run generator
# ------------------------------------------------------------

if __name__ == "__main__":
    main()