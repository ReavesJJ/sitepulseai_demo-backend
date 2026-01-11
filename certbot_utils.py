import subprocess

def certbot_dry_run(domain: str):
    """
    Runs certbot dry-run to validate renewal capability.
    Requires certbot installed on the server.
    """
    try:
        result = subprocess.run(
            [
                "certbot",
                "renew",
                "--dry-run",
                "--cert-name",
                domain
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode == 0:
            return {
                "status": "success",
                "message": "Certbot dry-run successful. Renewal is possible."
            }

        return {
            "status": "failed",
            "message": result.stderr or "Dry-run failed."
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


def run_certbot_renew(domain: str):
    # placeholder for now
    return {
        "status": "simulated",
        "message": f"Certbot renewal simulated for {domain}"
    }
