import json
import os
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


LOG_DIR = "logs/telemetry"
KEY_PATH = "security/signing_key.pem"


def load_private_key():

    with open(KEY_PATH, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )


def collect_events(domain, start_date, end_date):

    events = []

    for file in os.listdir(LOG_DIR):

        if not file.endswith(".log"):
            continue

        file_date = datetime.strptime(file.replace(".log",""), "%Y-%m-%d")

        if file_date < start_date or file_date > end_date:
            continue

        with open(os.path.join(LOG_DIR, file)) as f:

            for line in f:

                entry = json.loads(line)

                if entry.get("domain") == domain:
                    events.append(entry)

    return events


def generate_attestation(client_id, domain, start_date, end_date):

    start = datetime.strptime(start_date,"%Y-%m-%d")
    end = datetime.strptime(end_date,"%Y-%m-%d")

    events = collect_events(domain, start, end)

    summary = {}

    for e in events:

        check = e.get("check_type")

        summary.setdefault(check, 0)
        summary[check] += 1

    root_hash = hashlib.sha256(
        json.dumps(events, sort_keys=True).encode()
    ).hexdigest()

    attestation = {
        "client_id": client_id,
        "domain": domain,
        "start_date": start_date,
        "end_date": end_date,
        "observations": summary,
        "telemetry_root_hash": root_hash,
        "generated_at": datetime.utcnow().isoformat()
    }

    private_key = load_private_key()

    signature = private_key.sign(
        json.dumps(attestation, sort_keys=True).encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    attestation["signature"] = signature.hex()

    return attestation