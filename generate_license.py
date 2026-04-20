import json
import hmac
import hashlib
from datetime import datetime

SECRET = b"REPLACE_WITH_YOUR_PRIVATE_KEY"

def sign_license(data):
    payload = json.dumps(data, sort_keys=True).encode()
    return hmac.new(SECRET, payload, hashlib.sha256).hexdigest()

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

    print("✅ License generated: license.json")

if __name__ == "__main__":
    generate_license()