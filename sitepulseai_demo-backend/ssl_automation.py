from fastapi import APIRouter
import ssl
import socket
from datetime import datetime

router = APIRouter()

def get_ssl_status(domain: str):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()

        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expires - datetime.utcnow()).days

        return {
            "valid": True,
            "expires_at": expires.isoformat(),
            "expires_in_days": days_left
        }

    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
            "expires_at": None,
            "expires_in_days": None
        }

@router.get("/ssl/{domain}")
async def ssl_status(domain: str):
    return get_ssl_status(domain)


def get_ssl_status(domain: str):
    from ssl_utils import fetch_ssl_certificate
    from ssl_state import evaluate_ssl_state

    cert_data = fetch_ssl_certificate(domain)
    ssl_state = evaluate_ssl_state(domain, cert_data)

    return ssl_state

