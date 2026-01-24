# remediation_store.py
import json
import os
from datetime import datetime

STORE_DIR = "remediations"

os.makedirs(STORE_DIR, exist_ok=True)


def save_remediation(remediation: dict) -> str:
    remediation_id = f"{remediation['vuln_id']}_{int(datetime.utcnow().timestamp())}"
    remediation["remediation_id"] = remediation_id

    path = os.path.join(STORE_DIR, f"{remediation_id}.json")

    with open(path, "w") as f:
        json.dump(remediation, f, indent=2)

    return remediation_id


def load_remediation(remediation_id: str) -> dict | None:
    path = os.path.join(STORE_DIR, f"{remediation_id}.json")

    if not os.path.exists(path):
        return None

    with open(path, "r") as f:
        return json.load(f)
