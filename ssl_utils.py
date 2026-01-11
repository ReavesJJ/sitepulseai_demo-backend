import json
from datetime import datetime
from ssl_utils import update_ssl_state
from fastapi import APIRouter
import json
import os
import subprocess
# NO imports from ssl_automation
from ssl_state import load_ssl_state
# ssl_utils.py
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

def check_ssl_validity(url: str) -> str:
    try:
        hostname = urlparse(url).hostname
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            expires = datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            )
            days_left = (expires - datetime.utcnow()).days
            return f"Valid, expires in {days_left} days"
    except Exception:
        return "Not Available"


def run_certbot_renew():
    try:
        process = subprocess.run(
            ["certbot", "renew", "--quiet"],
            capture_output=True,
            text=True
        )

        if process.returncode == 0:
            return {
                "success": True,
                "output": process.stdout
            }

        return {
            "success": False,
            "error": process.stderr
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


router = APIRouter()


def renew_ssl():
    result = run_certbot_renew()  # your certbot logic

    if result.success:
        update_ssl_state("success")
        return {"status": "renewed by SitePulseAI"}

    return {"status": "failed"}


@router.get("/ssl/state")
def get_ssl_state():
    if not os.path.exists("ssl_state.json"):
        return {"status": "unknown"}

    with open("ssl_state.json") as f:
        return json.load(f)


# After certbot command returns success
update_ssl_state("success")


SSL_STATE_FILE = "ssl_state.json"

def update_ssl_state(status: str):
    data = {
        "last_renewed_by": "SitePulseAI",
        "last_renewed_at": datetime.utcnow().isoformat() + "Z",
        "status": status
    }

    with open(SSL_STATE_FILE, "w") as f:
        json.dump(data, f, indent=2)



