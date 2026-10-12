# ============================================================
# SitePulseAI Monitoring Engine
# Autonomous Monitoring Layer
# ============================================================

import time
import threading
from monitor import run_full_check
from telemetry_event_store import create_telemetry_event
from license_enforcer import get_license, validate_domain


# ============================================================
# Configuration
# ============================================================

MONITOR_INTERVAL = 300  # seconds (5 minutes)

# Current SitePulseAI deployment.
#
# Later, when multiple client licenses are loaded simultaneously,
# client/domain ownership should be resolved dynamically.
DEFAULT_CLIENT_ID = "SPA-TIER_1-5CF062E6"

# Track active threads to prevent duplicate monitoring loops.
active_threads = {}


# ============================================================
# Core Monitoring Function
# ============================================================

def run_monitor(domain, client_id=DEFAULT_CLIENT_ID):
    """
    Run one autonomous monitoring cycle for a licensed domain
    and create a certificate-capable telemetry event.

    Certificate generation itself remains separate and on-demand.
    """

    try:
        print(f"[Monitoring Started] {domain}")

        # ----------------------------------------------------
        # 1. LICENSE + DOMAIN ENFORCEMENT
        # ----------------------------------------------------

        get_license(client_id)
        validate_domain(client_id, domain)

        # ----------------------------------------------------
        # 2. RUN EXISTING MONITORING ENGINE
        # ----------------------------------------------------

        monitoring_results = run_full_check(domain)

        if not monitoring_results:
            print(
                f"[Monitoring Warning] "
                f"{domain} returned no results"
            )
            return None

        print(f"[Monitoring Success] {domain}")

        # ----------------------------------------------------
        # 3. BUILD TELEMETRY SNAPSHOT
        # ----------------------------------------------------

        results = {
            "domain": domain,
            "monitoring": monitoring_results
        }

        # ----------------------------------------------------
        # 4. CREATE CERTIFICATE-CAPABLE TELEMETRY EVENT
        #
        # Uses the same shared telemetry evidence layer as
        # POST /monitor.
        # ----------------------------------------------------

        event_record = create_telemetry_event(
            client_id=client_id,
            domain=domain,
            results=results
        )

        print(
            f"[Telemetry Created] "
            f"{domain} -> {event_record['event_id']}"
        )

        return {
            "monitoring": monitoring_results,
            "telemetry_event": {
                "event_type": event_record["event_type"],
                "event_id": event_record["event_id"],
                "timestamp": event_record["timestamp"],
                "client_id": event_record["client_id"],
                "domain": event_record["domain"],
                "monitoring_agent":
                    event_record["monitoring_agent"],
                "previous_event_hash":
                    event_record["previous_event_hash"],
                "event_hash": event_record["event_hash"]
            }
        }

    except Exception as e:
        print(f"[Monitoring Error] {domain}: {e}")
        return None


# ============================================================
# Per-Domain Monitoring Loop
# ============================================================

def monitor_domain_loop(
    domain,
    client_id=DEFAULT_CLIENT_ID
):
    """
    Continuously monitor one licensed domain.
    """

    while True:

        run_monitor(
            domain=domain,
            client_id=client_id
        )

        time.sleep(MONITOR_INTERVAL)


# ============================================================
# Start Monitoring for All Sites
# ============================================================

def start_monitoring(
    client_id=DEFAULT_CLIENT_ID
):
    """
    Start autonomous monitoring for all domains authorized
    by the supplied client license.
    """

    print("🚀 Monitoring Engine: ACTIVE")

    # Load and fully validate the client license.
    license_data = get_license(client_id)

    # The signed license is the authoritative source
    # for domains this monitoring engine may monitor.
    sites = license_data.get("domains", [])

    if not sites:
        print(
            "[Monitoring Engine] "
            "No licensed domains found."
        )
        return

    for site in sites:

        try:
            validate_domain(
                client_id,
                site
            )

        except Exception as e:
            print(
                f"[Monitoring Skipped] "
                f"{site}: {e}"
            )
            continue

        start_domain_thread(
            domain=site,
            client_id=client_id
        )
# ============================================================
# Start Individual Domain Thread
# ============================================================

def start_domain_thread(
    domain,
    client_id=DEFAULT_CLIENT_ID
):
    """
    Start one autonomous monitoring thread for a domain.

    Duplicate threads for the same client/domain pair are
    prevented.
    """

    thread_key = f"{client_id}:{domain}"

    existing_thread = active_threads.get(thread_key)

    if (
        existing_thread is not None
        and existing_thread.is_alive()
    ):
        print(
            f"[Thread Exists] "
            f"{domain} already being monitored"
        )
        return

    print(f"[Thread Starting] {domain}")

    thread = threading.Thread(
        target=monitor_domain_loop,
        args=(domain, client_id),
        daemon=True
    )

    active_threads[thread_key] = thread

    thread.start()


# ============================================================
# Dynamic Hook
# Used when a licensed domain is added during runtime
# ============================================================

def add_domain_to_monitoring(
    domain,
    client_id=DEFAULT_CLIENT_ID
):
    """
    Add a licensed domain to autonomous monitoring.

    The domain is license-validated before monitoring begins.

    start_domain_thread() immediately starts monitor_domain_loop(),
    so a separate run_monitor() call is intentionally NOT made
    here. This prevents duplicate first-run telemetry events.
    """

    get_license(client_id)
    validate_domain(client_id, domain)

    start_domain_thread(
        domain=domain,
        client_id=client_id
    )

    return {
        "status": "monitoring_started",
        "client_id": client_id,
        "domain": domain
    }