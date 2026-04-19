import os
import json
import shutil
from datetime import datetime
import zipfile

BASE_TEMPLATE = "template_system"   # your master system folder
OUTPUT_DIR = "builds"

def generate_license(client_name):
    return {
        "client": client_name,
        "license_type": "Internal Use License",
        "issued_date": datetime.utcnow().isoformat(),
        "system": "SitePulseAI",
        "authorized_domains": "pre-configured",
        "tamper_protection": True
    }

def generate_certificate(client_name, domains):
    return {
        "certificate_id": f"SPAI-{datetime.utcnow().timestamp()}",
        "client": client_name,
        "domains": domains,
        "verification": "Telemetry Verified",
        "issued_at": datetime.utcnow().isoformat()
    }

def build_client_package(client_name, domains):
    client_slug = client_name.lower().replace(" ", "_")
    build_path = os.path.join(OUTPUT_DIR, client_slug)

    if os.path.exists(build_path):
        shutil.rmtree(build_path)

    shutil.copytree(BASE_TEMPLATE, build_path)

    # Inject domains
    sites_path = os.path.join(build_path, "data", "sites.json")
    with open(sites_path, "w") as f:
        json.dump({"domains": domains}, f, indent=4)

    # License file
    license_data = generate_license(client_name)
    with open(os.path.join(build_path, "license.json"), "w") as f:
        json.dump(license_data, f, indent=4)

    # Certificate
    cert_data = generate_certificate(client_name, domains)
    cert_path = os.path.join(build_path, "data", "certs", "telemetry_cert.json")
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    with open(cert_path, "w") as f:
        json.dump(cert_data, f, indent=4)

    # Zip it
    zip_name = f"{client_slug}_sitepulseai.zip"
    zip_path = os.path.join(OUTPUT_DIR, zip_name)

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(build_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, build_path)
                zipf.write(full_path, rel_path)

    print(f"[✔] Package ready: {zip_path}")

# Example usage
build_client_package(
    client_name="ACME Corp",
    domains=["acme.com", "portal.acme.com"]
)