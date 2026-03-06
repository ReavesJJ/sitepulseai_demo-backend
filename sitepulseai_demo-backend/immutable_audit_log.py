import json
import hashlib
import os
from datetime import datetime

LOG_FOLDER = "logs"
LOG_FILE = "audit_log.json"


def write_audit_log(event_data: dict):

    os.makedirs(LOG_FOLDER, exist_ok=True)

    log_path = os.path.join(LOG_FOLDER, LOG_FILE)

    timestamp = datetime.utcnow().isoformat()

    record = {
        "timestamp": timestamp,
        "event": event_data
    }

    previous_hash = ""

    if os.path.exists(log_path):

        with open(log_path, "r") as f:
            logs = json.load(f)

        if logs:
            previous_hash = logs[-1]["hash"]

    else:
        logs = []

    record_string = json.dumps(record, sort_keys=True)

    record_hash = hashlib.sha256(
        (record_string + previous_hash).encode()
    ).hexdigest()

    entry = {
        "record": record,
        "previous_hash": previous_hash,
        "hash": record_hash
    }

    logs.append(entry)

    with open(log_path, "w") as f:
        json.dump(logs, f, indent=4)