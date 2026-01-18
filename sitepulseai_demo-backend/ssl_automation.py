# ssl_automation.py
import os
import shlex
import subprocess
import logging
from datetime import datetime
from typing import List
from fastapi import FastAPI, BackgroundTasks, HTTPException, Header
from pydantic import BaseModel
import requests
import ssl
import socket
from urllib.parse import urlparse
from ssl_utils import update_ssl_state


import subprocess

from fastapi import APIRouter
from ssl_state import (
    get_ssl_state,
    set_renewal_mode,
    mark_assisted_renewal
)

from certbot_utils import certbot_dry_run
from fastapi import APIRouter
from certbot_utils import run_certbot_renew


def run_certbot_renew(domain):
    # certbot logic here
    update_ssl_state(domain, renewed=True)

router = APIRouter(prefix="/ssl", tags=["SSL Automation"])

@router.post("/renew")
def renew_ssl(domain: str):
    return run_certbot_renew(domain)



@router.post("/dry-run")
def ssl_dry_run(domain: str):
    """
    Validates SSL renewal capability without changing certs.
    """
    return certbot_dry_run(domain)



router = APIRouter(prefix="/ssl", tags=["SSL Automation"])

@router.get("/state")
def ssl_state(domain: str):
    return get_ssl_state(domain)

@router.post("/enable-assisted")
def enable_assisted(domain: str):
    return set_renewal_mode(domain, "assisted")

@router.post("/assisted-renew")
def assisted_renew(domain: str):
    """
    This simulates renewal approval.
    Actual certbot execution comes later.
    """
    return mark_assisted_renewal(domain)



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





# ---------- CONFIG ----------
API_KEY = os.getenv("SITEPULSE_API_KEY", "replace-with-secure-key")
CLOUDFLARE_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")  # optional
CLOUDFLARE_ACCOUNT_ID = os.getenv("CLOUDFLARE_ACCOUNT_ID")  # required for some flows
CERTBOT_CLOUDFLARE_CRED = os.getenv("CERTBOT_CLOUDFLARE_CRED", "/etc/letsencrypt/cloudflare.ini")
CERTBOT_EMAIL = os.getenv("CERTBOT_EMAIL", "admin@example.com")
USE_STAGING = os.getenv("USE_LE_STAGING", "true").lower() in ("1", "true", "yes")

# ---------- LOGGING ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ssl_auto")

# ---------- MODELS ----------
class RenewRequest(BaseModel):
    domain: str
    method: str = "auto"  # auto | certbot-dns-cloudflare | cloudflare-origin
    notify: bool = True

# ---------- APP ----------
app = FastAPI(title="SitePulseAI SSL Automation")

# ---------- UTIL: get cert expiry ----------
def get_cert_expiry(domain: str, port: int = 443, timeout: int = 5):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(timeout)
            s.connect((domain, port))
            cert = s.getpeercert()
        notAfter = cert.get("notAfter")
        expires = datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z")
        return expires
    except Exception as e:
        logger.exception("Failed to fetch cert expiry")
        return None

# ---------- AUTH DEPENDABLE ----------
def validate_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

# ---------- CERTBOT DNS (Cloudflare) WRAPPER ----------
def run_certbot_cloudflare(domains: List[str], email: str = CERTBOT_EMAIL, cred_path: str = CERTBOT_CLOUDFLARE_CRED, staging: bool = USE_STAGING):
    """
    Runs certbot with dns-cloudflare plugin. Assumes certbot and plugin are installed
    and cred_path is accessible by the worker.
    Returns (returncode, stdout, stderr)
    """
    server = ("https://acme-staging-v02.api.letsencrypt.org/directory" if staging
              else "https://acme-v02.api.letsencrypt.org/directory")
    dom_args = " ".join(f"-d {d}" for d in domains)
    cmd = f"certbot certonly --dns-cloudflare --dns-cloudflare-credentials {cred_path} {dom_args} --noninteractive --agree-tos --email {email} --server {server}"
    logger.info("Running certbot: %s", cmd)
    p = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
    logger.info("Certbot exit %s", p.returncode)
    return p.returncode, p.stdout, p.stderr

# ---------- CLOUDFLARE ORIGIN CERT (issue cert via Cloudflare API for origin) ----------
def request_cloudflare_origin_cert(zone_id: str, hostnames: List[str], validity_days: int = 3650):
    """
    Request an origin certificate from Cloudflare for the origin server.
    Returns dict with 'certificate' and 'private_key' if successful.
    Requires CLOUDFLARE_TOKEN set and zone_id (zone identifier).
    NOTE: This creates a cert you must install on origin.
    """
    if not CLOUDFLARE_TOKEN:
        raise RuntimeError("Cloudflare token not configured")
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/ssl/origin_certificates"
    payload = {
        "hostnames": hostnames,
        "requested_validity": validity_days,
        "request_type": "origin-rsa"
    }
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_TOKEN}",
        "Content-Type": "application/json"
    }
    r = requests.post(url, json=payload, headers=headers, timeout=20)
    r.raise_for_status()
    data = r.json()
    if not data.get("success"):
        raise RuntimeError(f"Cloudflare API error: {data}")
    return data["result"]  # contains cert and private_key

# ---------- BACKGROUND TASK: DO RENEWAL ----------
def do_renewal_task(domain: str, method: str = "auto", notify: bool = True):
    """
    Background worker entry point. This is kept intentionally simple.
    In production, do this in a queue worker (Celery/RQ/SQS) with retries.
    """
    try:
        logger.info("Starting renewal for %s using %s", domain, method)
        # 1) quick check expiry
        expires = get_cert_expiry(domain)
        if expires:
            days_left = (expires - datetime.utcnow()).days
            logger.info("Days left: %s", days_left)
            # Only renew if near expiry or forced
            if days_left > 30 and method == "auto":
                logger.info("Skipping renewal; days left > 30")
                return {"skipped": True, "days_left": days_left}
        else:
            logger.info("Could not fetch current expiry; proceeding with renewal")

        if method in ("auto", "certbot-dns-cloudflare"):
            # attempt certbot flow
            try:
                rc, out, err = run_certbot_cloudflare([domain], email=CERTBOT_EMAIL, cred_path=CERTBOT_CLOUDFLARE_CRED, staging=USE_STAGING)
                if rc == 0:
                    logger.info("Certbot succeeded for %s", domain)
                    # NOTE: after certbot, you must reload your webserver (nginx/apache)
                    # Example: subprocess.run(["systemctl", "reload", "nginx"])
                    return {"status": "success", "method": "certbot", "out": out}
                else:
                    logger.error("Certbot failed: %s", err)
                    # fallback to cloudflare-origin if token present
            except Exception as e:
                logger.exception("Certbot flow failed; falling back if possible")

        if method in ("auto", "cloudflare-origin"):
            # need zone id - map domain -> zone_id in your DB/config; here we assume CLOUDFLARE_ACCOUNT_ID or preconfigured mapping
            # For demo, caller must supply zone_id via env or config mapping.
            zone_id = os.getenv("CLOUDFLARE_ZONE_ID_FOR_" + domain.replace(".", "_"), None)
            if not zone_id:
                # for demo, try using CLOUDFLARE_ACCOUNT_ID as fallback (not correct in prod)
                zone_id = os.getenv("CLOUDFLARE_ZONE_ID")
            if zone_id:
                logger.info("Requesting cloudflare origin cert for zone %s", zone_id)
                res = request_cloudflare_origin_cert(zone_id, [domain])
                # res contains 'certificate' and 'private_key'
                # install them on origin server (requires SSH or API) - not done here
                logger.info("Cloudflare origin cert retrieved, length: %s", len(res.get("certificate","")) )
                return {"status": "success", "method": "cloudflare-origin", "cert_info": {"expires_in_days": res.get("expires_on")}}
            else:
                logger.error("No zone id available; cannot request cloudflare cert")
                return {"status": "failed", "reason": "no_zone_id"}

        return {"status": "failed", "reason": "no_method_succeeded"}
    except Exception as e:
        logger.exception("Renewal failed")
        return {"status": "error", "detail": str(e)}

# ---------- ENDPOINTS ----------
@app.post("/alexa/renew-ssl")
def alexa_trigger_renew(req: RenewRequest, background_tasks: BackgroundTasks, x_api_key: str = Header(...)):
    validate_api_key(x_api_key)
    # quick domain validation
    parsed = urlparse("https://" + req.domain if "://" not in req.domain else req.domain)
    domain = parsed.hostname or req.domain
    # queue job
    background_tasks.add_task(do_renewal_task, domain, req.method, req.notify)
    return {"status": "queued", "domain": domain, "method": req.method}

@app.post("/renew-ssl")
def api_trigger_renew(req: RenewRequest, background_tasks: BackgroundTasks, x_api_key: str = Header(...)):
    """
    General API for triggering renewals. Use authentication.
    """
    validate_api_key(x_api_key)
    parsed = urlparse("https://" + req.domain if "://" not in req.domain else req.domain)
    domain = parsed.hostname or req.domain
    background_tasks.add_task(do_renewal_task, domain, req.method, req.notify)
    return {"status": "queued", "domain": domain, "method": req.method}



@app.get("/debug/cert-expiry")
def debug_cert_expiry(domain: str, x_api_key: str = Header(...)):
    validate_api_key(x_api_key)
    expires = get_cert_expiry(domain)
    if not expires:
        raise HTTPException(status_code=500, detail="Could not determine cert expiry")
    return {"domain": domain, "expires": expires.isoformat(), "days_left": (expires - datetime.utcnow()).days}

