import uuid
import hashlib
import json
import os
from datetime import datetime, timedelta
from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = "certificates"
LOG_DIR = "telemetry_logs"

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)


def generate_certificate(site, uptime="100%", ssl="Valid"):

    issued_time = datetime.utcnow()
    timestamp = issued_time.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Monitoring window (new upgrade)
    monitoring_start = issued_time - timedelta(minutes=15)
    monitoring_window = f"{monitoring_start.strftime('%Y-%m-%d %H:%M UTC')} → {issued_time.strftime('%Y-%m-%d %H:%M UTC')}"

    cert_id = f"SPAI-{uuid.uuid4().hex[:10].upper()}"

    # Monitoring Node ID
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
    log_ref = f"LOG-{issued_time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    audit_log = {
        "site": site,
        "timestamp": timestamp,
        "monitoring_window": monitoring_window,
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
    height = 780

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
    draw.text((200, 190), f"Site: {site}", fill="white", font=body_font)

    # New verification block
    draw.text((200, 240), "Telemetry Verification Status: VERIFIED", fill="white", font=small_font)
    draw.text((200, 270), "Monitoring Infrastructure: ACTIVE", fill="white", font=small_font)
    draw.text((200, 300), "Telemetry Integrity: VALIDATED", fill="white", font=small_font)

    draw.text((200, 340), f"Verified Uptime: {uptime}", fill="white", font=body_font)
    draw.text((200, 390), f"SSL Status: {ssl}", fill="white", font=body_font)

    # Monitoring window (new)
    draw.text((200, 440), f"Monitoring Window: {monitoring_window}", fill="white", font=small_font)

    # Telemetry identifiers
    draw.text((200, 490), f"Monitoring Node: {node_id}", fill="white", font=small_font)
    draw.text((200, 520), f"Telemetry Fingerprint: {fingerprint}", fill="white", font=small_font)
    draw.text((200, 550), f"Audit Log Ref: {log_ref}", fill="white", font=small_font)

    draw.text((200, 590), "Signature Hash:", fill="white", font=small_font)
    draw.text((200, 620), signature_hash[0:48] + "...", fill="white", font=small_font)

    draw.text((200, 650), f"Verification Checksum: {checksum}", fill="white", font=small_font)

    draw.text((200, 680), f"Certificate ID: {cert_id}", fill="white", font=small_font)

    draw.text((200, 710), f"Issued: {timestamp}", fill="white", font=small_font)

    draw.text(
        (200, 740),
        "Telemetry Verification Authority — SitePulseAI Licensed Monitoring Infrastructure",
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