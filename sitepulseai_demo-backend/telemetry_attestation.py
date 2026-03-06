import json
import hashlib
from datetime import datetime


def generate_attestation(client_id, domain, telemetry_data):

    timestamp = datetime.utcnow().isoformat()

    payload = {
        "client_id": client_id,
        "domain": domain,
        "timestamp": timestamp,
        "telemetry": telemetry_data
    }

    payload_string = json.dumps(payload, sort_keys=True)

    signature = hashlib.sha256(payload_string.encode()).hexdigest()

    certificate = {
        "attestation": payload,
        "signature": signature
    }

    return certificate