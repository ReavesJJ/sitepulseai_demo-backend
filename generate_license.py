import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

# Load PRIVATE key (ONLY YOU HAVE THIS FILE)
with open("signing_key.pem", "rb") as f:
    PRIVATE_KEY = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

    
def sign_license(payload: dict) -> str:
    data = json.dumps(payload, sort_keys=True).encode()

    signature = PRIVATE_KEY.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode()


def generate_license():
    license_data = {
        "client_id": "SPA-TIER_1-C4AFDB5C",
        "tier": "tier_1",
        "domains": [
            "sitepulseai.com",
            "api.sitepulseai.com"
        ],
        "max_sites": 5,
        "expiration_date": "2027-12-31",
        "issued_at": datetime.utcnow().isoformat()
    }

    license_data["signature"] = sign_license(license_data)

    with open("license.json", "w") as f:
        json.dump(license_data, f, indent=2)

    print("License generated successfully")


if __name__ == "__main__":
    generate_license()