from fastapi import APIRouter, Query
import ssl
import socket
from datetime import datetime

router = APIRouter()

@router.get("/ssl/{domain}")
def ssl_card(domain: str):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
        expires_at = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expires_at - datetime.utcnow()).days
        return {
            "domain": domain,
            "valid": days_remaining > 0,
            "expires_in_days": days_remaining,
            "managed": True
        }
    except Exception:
        return {
            "domain": domain,
            "valid": False,
            "expires_in_days": None,
            "managed": False
        }
    


  