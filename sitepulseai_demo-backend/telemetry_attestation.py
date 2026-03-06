import hashlib
import json
from datetime import datetime
import os

TELEMETRY_CERT_FOLDER = "telemetry_certificates"

def generate_telemetry_attestation(client_id: str, domain: str, results: dict) -> str:
    """
    Generate a cryptographically verifiable telemetry certificate
    Each certificate is saved to disk for auditing
    """

    os.makedirs(TELEMETRY_CERT_FOLDER, exist_ok=True)

    # Normalize payload for hashing
    payload = json.dumps({
        "client_id": client_id,
        "domain": domain,
        "results": results,
        "timestamp": datetime.utcnow().isoformat()
    }, sort_keys=True)

    # Compute SHA256 hash
    certificate = hashlib.sha256(payload.encode()).hexdigest()

    # Save certificate for audit purposes
    filename = f"{TELEMETRY_CERT_FOLDER}/{client_id}_{domain}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump({
            "client_id": client_id,
            "domain": domain,
            "results": results,
            "certificate": certificate,
            "timestamp": datetime.utcnow().isoformat()
        }, f, indent=4)

    return certificate