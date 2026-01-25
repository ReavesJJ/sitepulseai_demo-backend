from fastapi import APIRouter
import ssl
import socket
from datetime import datetime

router = APIRouter()
def get_ssl_status(domain: str):
    print("📡 Fetching SSL certificate for:", domain)

    from ssl_utils import fetch_ssl_certificate
    from ssl_state import evaluate_ssl_state

    cert_data = fetch_ssl_certificate(domain)

    print("📄 Certificate data received:", cert_data)

    ssl_state = evaluate_ssl_state(domain, cert_data)

    print("🔍 SSL state evaluated:", ssl_state)

    return ssl_state
