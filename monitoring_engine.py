# ============================================================
# SitePulseAI Monitoring Engine
# Autonomous Monitoring Layer
# ============================================================

import time
import threading
from monitor import run_full_check
from site_manager import get_all_sites



# ---------------------------
# Configuration
# ---------------------------
MONITOR_INTERVAL = 300  # seconds (5 minutes)

# Track active threads (prevents duplicates)
active_threads = {}

# ============================================================
# Core Monitoring Function
# ============================================================
def run_monitor(domain):
    try:
        print(f"[Monitoring Started] {domain}")

        results = run_full_check(domain)

        if results:
            print(f"[Monitoring Success] {domain}")
        else:
            print(f"[Monitoring Warning] {domain} returned no results")

        return results

    except Exception as e:
        print(f"[Monitoring Error] {domain}: {e}")
        return None


# ============================================================
# Per-Domain Monitoring Loop (Autonomous)
# ============================================================
def monitor_domain_loop(domain):
    while True:
        run_monitor(domain)
        time.sleep(MONITOR_INTERVAL)


# ============================================================
# Start Monitoring for All Sites (Initial Boot)
# ============================================================
def start_monitoring():
    print("🚀 Monitoring Engine: ACTIVE")

    sites = get_all_sites()

    for site in sites:
        start_domain_thread(site)


# ============================================================
# Start Individual Domain Thread
# ============================================================
def start_domain_thread(domain):
    if domain in active_threads:
        print(f"[Thread Exists] {domain} already being monitored")
        return

    print(f"[Thread Starting] {domain}")

    thread = threading.Thread(
        target=monitor_domain_loop,
        args=(domain,),
        daemon=True
    )

    active_threads[domain] = thread
    thread.start()


# ============================================================
# Dynamic Hook (Used by /add_url)
# ============================================================
def add_domain_to_monitoring(domain):
    """
    Called when a new domain is added via API
    """
    start_domain_thread(domain)

    # 🔥 Immediate execution (no waiting)
    return run_monitor(domain)