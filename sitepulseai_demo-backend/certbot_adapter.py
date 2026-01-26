# certbot_adapter.py
import subprocess
import subprocess
from datetime import datetime

def attempt_ssl_repair(domain: str, dry_run: bool = False) -> dict:
    """
    Attempt to repair or renew SSL certificate using Certbot.
    This is a controlled adapter used by the SSL automation layer.
    """

    command = [
        "certbot",
        "certonly",
        "--standalone",
        "-d", domain,
        "--non-interactive",
        "--agree-tos",
        "--email", "admin@" + domain
    ]

    if dry_run:
        command.append("--dry-run")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300
        )

        success = result.returncode == 0

        return {
            "domain": domain,
            "attempted_at": datetime.utcnow().isoformat(),
            "dry_run": dry_run,
            "success": success,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
        }

    except Exception as e:
        return {
            "domain": domain,
            "attempted_at": datetime.utcnow().isoformat(),
            "dry_run": dry_run,
            "success": False,
            "error": str(e),
        }



def certbot_dry_run(domain: str):
    """
    Phase 3 Step 4 — Safe validation of Certbot renewal capability
    """
    try:
        result = subprocess.run(
            ["certbot", "renew", "--dry-run", "-d", domain],
            capture_output=True,
            text=True,
            timeout=120
        )

        return {
            "mode": "dry_run",
            "domain": domain,
            "return_code": result.returncode,
            "stdout": result.stdout[-2000:],
            "stderr": result.stderr[-2000:],
            "status": "success" if result.returncode == 0 else "failed",
            "executed_at": datetime.utcnow().isoformat()
        }

    except FileNotFoundError:
        return {
            "mode": "dry_run",
            "domain": domain,
            "status": "failed",
            "error": "Certbot binary not found on host",
            "executed_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        return {
            "mode": "dry_run",
            "domain": domain,
            "status": "failed",
            "error": str(e),
            "executed_at": datetime.utcnow().isoformat()
        }


def certbot_live_renew(domain: str):
    """
    Phase 3 Step 4 — Live SSL renewal (DISABLED BY DEFAULT)
    """
    try:
        result = subprocess.run(
            ["certbot", "renew", "-d", domain],
            capture_output=True,
            text=True,
            timeout=180
        )

        return {
            "mode": "live",
            "domain": domain,
            "return_code": result.returncode,
            "stdout": result.stdout[-2000:],
            "stderr": result.stderr[-2000:],
            "status": "success" if result.returncode == 0 else "failed",
            "executed_at": datetime.utcnow().isoformat()
        }

    except FileNotFoundError:
        return {
            "mode": "live",
            "domain": domain,
            "status": "failed",
            "error": "Certbot binary not found on host",
            "executed_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        return {
            "mode": "live",
            "domain": domain,
            "status": "failed",
            "error": str(e),
            "executed_at": datetime.utcnow().isoformat()
        }
