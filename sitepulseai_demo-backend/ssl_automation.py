import ssl
import socket
from ssl_state import update_ssl_state

def start_ssl_scan(domain: str):
    """
    Perform immediate SSL scan and update state.
    """
    try:
        # Get SSL certificate
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # You can add more checks here, e.g., expiration, issuer
                update_ssl_state(domain, "VALID")
    except Exception:
        update_ssl_state(domain, "INVALID")
