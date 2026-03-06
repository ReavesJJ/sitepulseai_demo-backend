import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


def load_public_key():

    with open("security/verify_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())


def verify_log_file(path):

    public_key = load_public_key()

    prev_hash = ""

    with open(path, "r") as f:

        for line in f:

            event = json.loads(line)

            hash_input = json.dumps(
                {k: event[k] for k in event if k not in ["hash", "signature"]},
                sort_keys=True
            )

            calculated = hashlib.sha256(
                (hash_input + prev_hash).encode()
            ).hexdigest()

            if calculated != event["hash"]:
                print("Hash mismatch detected")
                return False

            public_key.verify(
                bytes.fromhex(event["signature"]),
                event["hash"].encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            prev_hash = event["hash"]

    print("Log verified successfully")
    return True