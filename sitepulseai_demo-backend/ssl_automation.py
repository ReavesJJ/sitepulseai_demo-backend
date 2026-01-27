from fastapi import APIRouter
from ssl_utils import get_ssl_certificate
from ssl_state import update_ssl_state, can_attempt_repair, record_policy_decision
from ssl_policy import evaluate_ssl_policy
from certbot_adapter import attempt_ssl_repair

router = APIRouter(prefix="/ssl", tags=["ssl"])


def check_ssl(domain: str) -> dict:
    """
    Core SSL inspection logic used by scanners and baseline engine.
    """
    ssl_data = get_ssl_certificate(domain)

    policy_decision = evaluate_ssl_policy(domain, ssl_data)
    record_policy_decision(domain, policy_decision)

    repair_attempted = False
    repair_result = None

    if not policy_decision.get("policy_compliant"):
        if can_attempt_repair(domain):
            repair_attempted = True
            repair_result = attempt_ssl_repair(domain, dry_run=True)

            update_ssl_state(domain, {
                "repair_attempted": True,
                "repair_result": repair_result
            })

    update_ssl_state(domain, {
        "ssl_data": ssl_data,
        "policy": policy_decision
    })

    return {
        "domain": domain,
        "ssl_data": ssl_data,
        "policy": policy_decision,
        "repair_attempted": repair_attempted,
        "repair_result": repair_result
    }


@router.get("/{domain}")
def get_ssl_status(domain: str):
    """
    HTTP endpoint for dashboard and API consumers.
    """
    return check_ssl(domain)


from fastapi import FastAPI, Query
from monitoring_checks import (
    check_ssl_state,
    check_uptime,
    check_response_time,
    scan_headers,
    scan_seo
)

app = FastAPI()

@app.get("/api/ssl")
def ssl_card(domain: str = Query(...)):
    return check_ssl_state(domain)

@app.get("/api/uptime")
def uptime_card(url: str = Query(...)):
    return check_uptime(url)

@app.get("/api/latency")
def latency_card(url: str = Query(...)):
    return check_response_time(url)

@app.get("/api/vuln")
def vuln_card(url: str = Query(...)):
    return scan_headers(url)

@app.get("/api/seo")
def seo_card(url: str = Query(...)):
    return scan_seo(url)

