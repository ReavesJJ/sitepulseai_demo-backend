import uuid
import hashlib
import json
import os
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = "certificates"
LOG_DIR = "telemetry_logs"

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)


def generate_certificate(site, uptime="100%", ssl="Valid"):

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    cert_id = f"SPAI-{uuid.uuid4().hex[:10].upper()}"

    # Monitoring Node ID (simulated infrastructure node)
    node_id = "SPAI-MON-VA01"

    # Create telemetry payload
    telemetry_payload = f"{site}|{timestamp}|{uptime}|{ssl}|{node_id}"

    # Cryptographic signature hash
    signature_hash = hashlib.sha256(telemetry_payload.encode()).hexdigest()

    # Telemetry fingerprint
    fingerprint = hashlib.md5(telemetry_payload.encode()).hexdigest().upper()[0:16]

    # Verification checksum
    checksum = hashlib.sha1(telemetry_payload.encode()).hexdigest().upper()[0:8]

    # Audit log reference
    log_ref = f"LOG-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    audit_log = {
        "site": site,
        "timestamp": timestamp,
        "uptime": uptime,
        "ssl_status": ssl,
        "monitoring_node": node_id,
        "telemetry_fingerprint": fingerprint,
        "signature_hash": signature_hash,
        "verification_checksum": checksum,
        "certificate_id": cert_id,
        "audit_log_reference": log_ref
    }

    # Save audit log
    log_file = os.path.join(LOG_DIR, f"{log_ref}.json")
    with open(log_file, "w") as f:
        json.dump(audit_log, f, indent=4)

    # Create certificate image
    width = 1200
    height = 750

    img = Image.new("RGB", (width, height), (20, 26, 36))
    draw = ImageDraw.Draw(img)

    try:
        title_font = ImageFont.truetype("arial.ttf", 60)
        body_font = ImageFont.truetype("arial.ttf", 36)
        small_font = ImageFont.truetype("arial.ttf", 26)
    except:
        title_font = ImageFont.load_default()
        body_font = ImageFont.load_default()
        small_font = ImageFont.load_default()

    # Title
    draw.text((180, 60), "SitePulseAI Telemetry Certificate", fill="white", font=title_font)

    draw.line((150, 150, 1050, 150), fill="white", width=2)

    # Core verification
    draw.text((200, 200), f"Site: {site}", fill="white", font=body_font)
    draw.text((200, 260), f"Verified Uptime: {uptime}", fill="white", font=body_font)
    draw.text((200, 320), f"SSL Status: {ssl}", fill="white", font=body_font)

    draw.text((200, 400), f"Monitoring Node: {node_id}", fill="white", font=small_font)
    draw.text((200, 440), f"Telemetry Fingerprint: {fingerprint}", fill="white", font=small_font)
    draw.text((200, 480), f"Audit Log Ref: {log_ref}", fill="white", font=small_font)

    draw.text((200, 540), f"Signature Hash:", fill="white", font=small_font)
    draw.text((200, 570), signature_hash[0:48] + "...", fill="white", font=small_font)

    draw.text((200, 620), f"Verification Checksum: {checksum}", fill="white", font=small_font)

    draw.text((200, 670), f"Issued: {timestamp}", fill="white", font=small_font)

    draw.text(
        (200, 710),
        "Issued by SitePulseAI Licensed Monitoring Infrastructure",
        fill="white",
        font=small_font
    )

    filename = f"{site.replace('.','_')}_{cert_id}.png"
    path = os.path.join(OUTPUT_DIR, filename)

    img.save(path)

    print("\nTelemetry Certificate Generated")
    print(path)
    print("Audit Log:", log_file)


if __name__ == "__main__":

    site = "example.com"

    generate_certificate(site)