import os
import json
import hashlib
import zipfile
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


LOG_DIR = "logs/telemetry"
ARCHIVE_DIR = "logs/archive"
KEY_PATH = "security/signing_key.pem"

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(ARCHIVE_DIR, exist_ok=True)


# -----------------------------
# Load signing key
# -----------------------------
def load_private_key():

    with open(KEY_PATH, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )


# -----------------------------
# Get previous hash
# -----------------------------
def get_last_hash(log_file):

    if not os.path.exists(log_file):
        return ""

    with open(log_file, "rb") as f:

        lines = f.readlines()

        if not lines:
            return ""

        last = json.loads(lines[-1])

        return last["hash"]


# -----------------------------
# Sign event
# -----------------------------
def sign_event(private_key, event_hash):

    signature = private_key.sign(
        event_hash.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return signature.hex()


# -----------------------------
# Compress old logs
# -----------------------------
def compress_old_logs():

    cutoff = datetime.utcnow() - timedelta(days=30)

    for file in os.listdir(LOG_DIR):

        if not file.endswith(".log"):
            continue

        path = os.path.join(LOG_DIR, file)

        file_date = datetime.strptime(file.replace(".log", ""), "%Y-%m-%d")

        if file_date < cutoff:

            archive_name = f"{file_date.strftime('%Y-%m')}-archive.zip"
            archive_path = os.path.join(ARCHIVE_DIR, archive_name)

            with zipfile.ZipFile(archive_path, "a", zipfile.ZIP_DEFLATED) as z:

                z.write(path, arcname=file)

            os.remove(path)


# -----------------------------
# Main logging function
# -----------------------------
def log_event(event):

    private_key = load_private_key()

    date = datetime.utcnow().strftime("%Y-%m-%d")
    log_file = f"{LOG_DIR}/{date}.log"

    event["timestamp"] = datetime.utcnow().isoformat()

    prev_hash = get_last_hash(log_file)

    event["prev_hash"] = prev_hash

    event_json = json.dumps(event, sort_keys=True)

    event_hash = hashlib.sha256(
        (event_json + prev_hash).encode()
    ).hexdigest()

    event["hash"] = event_hash

    signature = sign_event(private_key, event_hash)

    event["signature"] = signature

    with open(log_file, "a") as f:

        f.write(json.dumps(event) + "\n")

    # run rotation check
    compress_old_logs()