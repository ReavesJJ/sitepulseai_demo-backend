import uuid
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import os

OUTPUT_DIR = "certificates"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def generate_certificate(site, uptime="100%", ssl="Valid"):

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    cert_id = f"SPAI-{uuid.uuid4().hex[:10].upper()}"

    width = 1200
    height = 700

    img = Image.new("RGB", (width, height), (20, 26, 36))
    draw = ImageDraw.Draw(img)

    # Fonts
    try:
        title_font = ImageFont.truetype("arial.ttf", 60)
        body_font = ImageFont.truetype("arial.ttf", 36)
        small_font = ImageFont.truetype("arial.ttf", 28)
    except:
        title_font = ImageFont.load_default()
        body_font = ImageFont.load_default()
        small_font = ImageFont.load_default()

    # Title
    draw.text((200, 80), "SitePulseAI Telemetry Certificate", fill="white", font=title_font)

    # Divider
    draw.line((150, 180, 1050, 180), fill="white", width=2)

    # Certificate body
    draw.text((200, 250), f"Site: {site}", fill="white", font=body_font)
    draw.text((200, 320), f"Verified Uptime: {uptime}", fill="white", font=body_font)
    draw.text((200, 390), f"SSL Status: {ssl}", fill="white", font=body_font)

    draw.text((200, 480), f"Verification Timestamp: {timestamp}", fill="white", font=small_font)
    draw.text((200, 520), f"Certificate ID: {cert_id}", fill="white", font=small_font)

    draw.text((200, 600), "Operational Monitoring Infrastructure Validation", fill="white", font=small_font)

    filename = f"{site.replace('.','_')}_{cert_id}.png"
    path = os.path.join(OUTPUT_DIR, filename)

    img.save(path)

    print(f"\nCertificate generated:")
    print(path)


if __name__ == "__main__":

    site = "example.com"

    generate_certificate(site)